"""Окно приложения (ZePyGUI): подключение к vCenter, настройки сканирования, прогресс, лог, таблица, выгрузка.

Вся долгая работа (подключение, задание, выбор папки, запись отчётов) идёт через ui.task в фоне,
окно получает изменения через State и не зависает.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import time
from pathlib import Path

from zepygui import App, Log, State, ui

import exporter
from inventory import JobConfig, run_job
from network_scanner import DEFAULT_PORTS
from vsphere_client import VSphereError, make_client

log = logging.getLogger("inventory.gui")

TYPE_COLORS = (("vsphere", "blue"), ("esxi", "blue"), ("виртуальная", "blue"), ("windows", "accent"),
               ("linux", "green"), ("сетевое", "yellow"), ("принтер", "gray"), ("камера", "gray"), ("nas", "gray"))
SAVED_KEYS = ("vcenter", "user", "verify_ssl", "subnets", "scan_vsphere", "scan_subnets", "detect_types",
              "use_ping", "scan_timeout", "workers", "ports", "export_dir")


def type_color(kind: str) -> str:
    k = (kind or "").lower()
    return next((c for word, c in TYPE_COLORS if word in k), "gray")


def folder_dialog_available() -> bool:
    if platform.system() in ("Windows", "Darwin"):
        return True
    has_display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    return bool(has_display and (shutil.which("zenity") or shutil.which("kdialog")))

CSS = """
.inv-filter { flex: 1 1 320px; }
.inv-dir { flex: 1 1 260px; }
.inv-status { max-width: 100%; white-space: normal; }
"""


class GuiLogHandler(logging.Handler):
    """Строки журнала → окно (zepygui.Log потокобезопасен и шлёт в окно только новые строки)."""

    def __init__(self, target: Log):
        super().__init__(logging.INFO)
        self.target = target
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.target.append(self.format(record))
        except Exception:  # noqa: BLE001
            self.handleError(record)


class InventoryApp:
    def __init__(self, settings_path: Path, log_path: Path, reports_dir: Path, demo: bool = False):
        self.settings_path = settings_path
        self.log_path = log_path
        s = self._load_settings()
        if demo:
            s.update(vcenter="mock", user="administrator@vsphere.local", subnets="127.0.0.0/29")
        self.vcenter = State(s.get("vcenter", ""))
        self.user = State(s.get("user", ""))
        self.password = State("demo" if demo else "")
        self.verify_ssl = State(bool(s.get("verify_ssl", False)))
        self.subnets = State(s.get("subnets", ""))
        self.scan_vsphere = State(bool(s.get("scan_vsphere", True)))
        self.scan_subnets = State(bool(s.get("scan_subnets", True)))
        self.detect_types = State(bool(s.get("detect_types", True)))
        self.use_ping = State(bool(s.get("use_ping", True)))
        self.scan_timeout = State(s.get("scan_timeout", 600))
        self.workers = State(s.get("workers", 64))
        self.ports = State(s.get("ports", ", ".join(map(str, DEFAULT_PORTS))))
        self.export_dir = State(s.get("export_dir") or str(reports_dir))
        self.show_advanced = State(False)
        self.fmt = {f: State(True) for f in exporter.FORMATS}

        self.conn = State(("off", "Не подключено"))
        self.conn_busy = State(False)
        self.client = None
        self.job = State(None)
        self.devices = State([])
        self.result = State(None)
        self.filter = State("")
        self.last_export = State(None)

        self.log = Log(max_lines=50_000)
        self._handler = GuiLogHandler(self.log)
        logging.getLogger("inventory").addHandler(self._handler)

        self.app = App("Инвентаризация инфраструктуры", theme="dark", accent="#3b82f6", width=1320, height=940,
                       css=CSS)
        self.app.page("/", title="Инвентаризация")(self.page)
        self.app.on_shutdown(self.shutdown)
        log.info("Программа запущена. Журнал: %s", log_path)

    # ------------------------------------------------------------------ настройки (без пароля)
    def _load_settings(self) -> dict:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_settings(self):
        data = {k: getattr(self, k).value for k in SAVED_KEYS}
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:
            log.warning("Не удалось сохранить настройки: %s", e)

    # ------------------------------------------------------------------ подключение
    @property
    def running(self) -> bool:
        job = self.job.value
        return job is not None and job.running

    def connect(self):
        if self.conn_busy.value or self.running:
            return
        if not self.vcenter.value.strip() or not self.user.value.strip():
            ui.toast("Укажите адрес vCenter и логин", "warning")
            return
        self.conn_busy.set(True)
        self.conn.set(("busy", "Подключение…"))
        old, self.client = self.client, None
        ui.task(self._connect_worker, old, self.vcenter.value.strip(), self.user.value.strip(), self.password.value,
                self.verify_ssl.value, on_done=self._connected, on_error=self._connect_failed)

    @staticmethod
    def _connect_worker(old, address, user, password, verify_ssl):
        if old is not None:
            old.disconnect()
        client = make_client(address, user, password, verify_ssl=verify_ssl)
        client.connect()
        return client

    def _connected(self, client):
        self.client = client
        self.conn_busy.set(False)
        self.conn.set(("ok", f"Подключено: {client.about.get('name', client.host)}"))
        ui.toast("Подключение к vCenter установлено", "success")

    def _connect_failed(self, exc):
        self.conn_busy.set(False)
        msg = str(exc) if isinstance(exc, VSphereError) else f"{type(exc).__name__}: {exc}"
        if not isinstance(exc, VSphereError):
            log.exception("Неожиданная ошибка подключения", exc_info=exc)
        else:
            log.error("vCenter: %s", msg)
        self.conn.set(("error", msg))
        ui.toast(msg, "error", title="Нет подключения к vCenter", duration=6)

    def disconnect(self):
        if self.client is not None and not self.running:
            client, self.client = self.client, None
            ui.task(client.disconnect)
        self.conn.set(("off", "Не подключено"))

    # ------------------------------------------------------------------ задание
    def _config(self) -> JobConfig | str:
        try:
            ports = tuple(int(p) for p in str(self.ports.value).replace(";", ",").split(",") if p.strip())
            if not ports or any(not 0 < p < 65536 for p in ports):
                raise ValueError
        except ValueError:
            return "Порты: укажите числа 1–65535 через запятую"
        try:
            timeout = float(self.scan_timeout.value or 0)
            workers = int(self.workers.value or 64)
        except (TypeError, ValueError):
            return "Таймаут и число потоков должны быть числами"
        return JobConfig(vcenter=self.vcenter.value.strip(), user=self.user.value.strip(), password=self.password.value,
                         verify_ssl=self.verify_ssl.value, subnets=self.subnets.value,
                         scan_vsphere=self.scan_vsphere.value, scan_subnets=self.scan_subnets.value,
                         detect_types=self.detect_types.value, use_ping=self.use_ping.value, ports=ports,
                         scan_timeout=max(0.0, timeout), workers=max(1, min(workers, 512)))

    def start_job(self):
        if self.running or self.conn_busy.value:
            return
        cfg = self._config()
        problems = [cfg] if isinstance(cfg, str) else cfg.validate()
        if problems:
            for p in problems:
                log.warning("Задание не запущено: %s", p)
            ui.toast("\n".join(problems), "warning", title="Проверьте настройки", duration=6)
            return
        self._save_settings()
        client = None
        if cfg.scan_vsphere and self.client is not None and self.client.connected \
                and self.client.user == cfg.user and self.conn.value[0] == "ok":
            client = self.client                      # используем уже открытую сессию
        self.devices.set([])
        self.result.set(None)
        self.last_export.set(None)
        self.job.set(ui.task(self._job_worker, cfg, client, on_done=self._job_done, on_error=self._job_failed,
                             name="inventory"))

    def _job_worker(self, cfg, client, task):
        found = []

        self.devices.set(found)
        last = [0.0]

        def on_device(dev):            # из потока задания; таблицу обновляем не чаще ~3 раз в секунду
            found.append(dev)
            now = time.monotonic()
            if now - last[0] > 0.3:
                last[0] = now
                self.devices.notify()

        shown = [0.0]

        def progress(frac, msg):       # каждое обновление — перерисовка окна; 5 раз в секунду достаточно
            now = time.monotonic()
            if now - shown[0] >= 0.2 or frac >= 1.0:
                shown[0] = now
                task.report(frac, msg)

        return run_job(cfg, client=client, progress=progress, is_cancelled=lambda: task.cancelled,
                       on_device=on_device)

    def _job_done(self, result):
        self.result.set(result)
        self.devices.set(result["devices"])
        n = len(result["devices"])
        if result["errors"]:
            ui.toast(f"Готово с ошибками: устройств {n}, ошибок {len(result['errors'])}", "warning", duration=6)
        elif result["cancelled"]:
            ui.toast(f"Остановлено. Найдено устройств: {n}", "warning")
        else:
            ui.toast(f"Готово: найдено устройств {n}", "success")

    def _job_failed(self, exc):
        log.error("Задание прервано ошибкой: %s: %s", type(exc).__name__, exc, exc_info=exc)
        ui.toast(f"{type(exc).__name__}: {exc}", "error", title="Задание прервано", duration=8)

    def stop_job(self):
        job = self.job.value
        if job is not None and job.running:
            log.info("Остановка задания…")
            job.cancel()

    # ------------------------------------------------------------------ выгрузка
    def export_click(self):
        log.info("Выгрузка отчёта: выбор папки")
        if not self.result.value:
            ui.toast("Сначала выполните задание", "warning")
            return
        if not any(s.value for s in self.fmt.values()):
            ui.toast("Отметьте хотя бы один формат", "warning")
            return
        if folder_dialog_available():
            ui.task(ui.choose_folder, "Папка для отчётов", on_done=self._export_to)
        else:                      # нет графического диалога (Linux без zenity/kdialog) — папка из поля
            self._export_to(self.export_dir.value)

    def _export_to(self, folder):
        if not folder:
            return                 # пользователь закрыл диалог
        self.export_dir.set(str(folder))
        log.info("Выгрузка отчёта в %s", folder)
        formats = [f for f, s in self.fmt.items() if s.value]
        ui.task(exporter.export, self.result.value, folder, formats, on_done=self._exported,
                on_error=self._export_failed)

    def _exported(self, paths):
        self.last_export.set([str(p) for p in paths])
        self._save_settings()
        for p in paths:
            log.info("Отчёт сохранён: %s", p)
        ui.toast(f"Сохранено файлов: {len(paths)} в {paths[0].parent}", "success", duration=5)

    def _export_failed(self, exc):
        log.error("Не удалось сохранить отчёт: %s", exc)
        ui.toast(str(exc), "error", title="Ошибка выгрузки", duration=8)

    def open_reports(self):
        paths = self.last_export.value
        if paths:
            ui.open_path(str(Path(paths[0]).parent))

    # ------------------------------------------------------------------ окно
    def shutdown(self):
        job = self.job.value
        if job is not None and job.running:
            job.cancel()
        if self.client is not None:
            self.client.disconnect()
        logging.getLogger("inventory").removeHandler(self._handler)
        log.info("Программа закрыта")

    def _status_badge(self):
        state, text = self.conn.value
        color = {"ok": "green", "busy": "yellow", "error": "red"}.get(state, "gray")
        return ui.badge(text, color, dot=True, cls="inv-status", title=text)

    def connection_card(self):
        busy, running = self.conn_busy.value, self.running
        connected = self.conn.value[0] == "ok"
        return ui.card(
            ui.input(self.vcenter, label="Адрес vCenter", placeholder="vcenter.company.local или 10.0.0.10",
                     icon="globe", disabled=busy or running, name="vcenter"),
            ui.grid(
                ui.input(self.user, label="Логин", placeholder="administrator@vsphere.local", icon="user",
                         disabled=busy or running, name="user"),
                ui.input(self.password, label="Пароль", type="password", icon="lock", disabled=busy or running,
                         on_enter=lambda _: self.connect(), name="password", autocomplete="off"),
                cols=2, gap=3),
            ui.checkbox("Проверять сертификат vCenter", self.verify_ssl, disabled=busy or running,
                        description="Выключите для самоподписанного сертификата"),
            ui.row(
                ui.button("Подключиться", self.connect, icon="zap", loading=busy, disabled=running, id="btn-connect"),
                ui.button("Отключиться", self.disconnect, variant="ghost", disabled=busy or running)
                if connected else None,
                ui.spacer(), self._status_badge(), wrap=True),
            title="Подключение к vCenter", subtitle="Права администратора не нужны — хватает роли Read-only")

    def settings_card(self):
        running = self.running
        advanced = None
        if self.show_advanced.value:
            advanced = ui.column(
                ui.input(self.ports, label="TCP-порты для проверки", disabled=running, name="ports"),
                ui.grid(ui.input(self.scan_timeout, label="Таймаут задания, с (0 — без лимита)", type="number",
                                 disabled=running, name="scan_timeout"),
                        ui.input(self.workers, label="Потоков", type="number", disabled=running, name="workers"),
                        cols=2, gap=3),
                ui.checkbox("Использовать ping", self.use_ping, disabled=running),
                gap=3)
        return ui.card(
            ui.textarea(self.subnets, label="Подсети", rows=4, disabled=running, name="subnets",
                        placeholder="192.168.1.0/24\n10.0.0.1-10.0.0.50\n10.10.5.7",
                        hint="По одной в строке или через запятую: CIDR, диапазон или адрес"),
            ui.column(
                ui.checkbox("Сканировать vSphere", self.scan_vsphere, disabled=running),
                ui.checkbox("Сканировать подсети", self.scan_subnets, disabled=running),
                ui.checkbox("Определять типы устройств", self.detect_types, disabled=running,
                            description="Баннеры SSH/HTTP, открытые порты, производитель по MAC"),
                gap=2),
            ui.switch("Дополнительные настройки", self.show_advanced),
            advanced,
            ui.row(
                ui.button("Запустить задание", self.start_job, icon="play", loading=running,
                          disabled=self.conn_busy.value, id="btn-run"),
                ui.button("Остановить", self.stop_job, variant="danger", icon="x") if running else None,
                wrap=True),
            title="Настройки сканирования")

    def progress_card(self):
        job = self.job.value
        if job is None:
            pct, message, status = 0, "Задание ещё не запускалось", None
        else:
            p = job.progress.value
            pct = (p or 0) * 100
            message = job.message.value or "Запуск…"
            status = job.status.value
        res = self.result.value
        status_badge = None
        if status in ("pending", "running"):
            status_badge = ui.badge("Выполняется", "yellow", dot=True)
        elif status == "done" and res is not None:
            if res.get("cancelled"):
                status_badge = ui.badge("Остановлено", "yellow")
            elif res.get("errors"):
                status_badge = ui.badge("Готово с ошибками", "red")
            else:
                status_badge = ui.badge("Готово", "green")
        elif status == "error":
            status_badge = ui.badge("Ошибка", "red")
        alerts = []
        if res:
            if res.get("errors"):
                alerts.append(ui.alert(ui.column(*[ui.text(e, size="sm") for e in res["errors"][:8]], gap=1),
                                       kind="error", title=f"Ошибки ({len(res['errors'])})"))
            if res.get("warnings"):
                alerts.append(ui.alert(ui.column(*[ui.text(w, size="sm") for w in res["warnings"]], gap=1),
                                       kind="warning", title="Предупреждения"))
        return ui.card(
            ui.progress(pct, label=message, show_value=True),
            *alerts,
            ui.log_view(self.log, height=230),
            title="Прогресс и журнал", actions=status_badge,
            subtitle=f"Журнал также пишется в файл {self.log_path}")

    def devices_card(self):
        devices = self.devices.value
        q = (self.filter.value or "").strip().lower()
        rows = devices
        if q:
            rows = [d for d in devices if q in " ".join(str(d.get(k) or "") for k in
                                                        ("ip", "mac", "vendor", "hostname", "type", "os")).lower()]
        res = self.result.value
        vs = (res or {}).get("vsphere") or {}
        scan = (res or {}).get("scan") or {}
        stats = ui.grid(
            ui.stat("Устройств", len(devices), icon="grid"),
            ui.stat("Виртуальных машин", sum(1 for v in vs.get("vms", []) if not v.get("template")) if vs else "—",
                    icon="box"),
            ui.stat("ESXi-хостов", len(vs.get("hosts", [])) if vs else "—", icon="activity"),
            ui.stat("Ответили в сети", scan.get("alive", "—") if scan else "—", icon="search"),
            cols=4, gap=3)
        columns = [
            {"key": "ip", "label": "IP", "format": lambda v: ui.code(v) if v else "—"},
            {"key": "mac", "label": "MAC", "format": lambda v: v or "—"},
            {"key": "vendor", "label": "Производитель", "format": lambda v: v or "—"},
            {"key": "hostname", "label": "Hostname", "format": lambda v: v or "—"},
            {"key": "type", "label": "Тип", "format": lambda v: ui.badge(v, type_color(v)) if v else "—"},
            {"key": "source", "label": "Источник", "format": lambda v: exporter.SOURCE_NAMES.get(v, v or "—")},
        ]
        exported = self.last_export.value
        fmt_boxes = [ui.checkbox(label, self.fmt[f]) for f, label in
                     (("json", "JSON"), ("csv", "CSV"), ("md", "Markdown"))]
        return ui.card(
            stats,
            ui.row(ui.input(self.filter, placeholder="Фильтр: IP, имя, тип, производитель…", icon="filter",
                            clearable=True, debounce=150, cls="inv-filter"),
                   ui.text(f"Показано {len(rows)} из {len(devices)}", muted=True, size="sm"), wrap=True),
            ui.table(rows, columns, empty="Пока нет данных — запустите задание", max_height=520, compact=True,
                     virtual=len(rows) > 200, row_height=36),
            ui.divider(),
            ui.row(*fmt_boxes,
                   ui.input(self.export_dir, placeholder="Папка для отчётов", icon="folder", cls="inv-dir", name="export_dir",
                            hint=None if folder_dialog_available() else "Диалог выбора папки недоступен — "
                                                                        "отчёт сохранится в эту папку"),
                   ui.button("Выгрузить отчёт", self.export_click, icon="download",
                             disabled=self.result.value is None or self.running, id="btn-export"),
                   ui.button("Открыть папку", self.open_reports, variant="ghost", icon="external") if exported else None,
                   wrap=True, align="end"),
            ui.text("Сохранено: " + ", ".join(Path(p).name for p in exported), size="sm", muted=True,
                    id="export-done") if exported else None,
            title="Найденные устройства")

    def page(self):
        return ui.container(
            ui.column(
                ui.row(ui.column(ui.h2("Инвентаризация инфраструктуры"),
                                 ui.text("vCenter + сканирование подсетей → отчёты JSON, CSV, Markdown", muted=True),
                                 gap=1),
                       ui.spacer(), ui.theme_toggle(), wrap=True),
                ui.grid(self.connection_card(), self.settings_card(), cols=2, gap=4),
                self.progress_card(),
                self.devices_card(),
                gap=4),
            max_width=1400, padding=5)

    def run(self, mode: str = "auto"):
        self.app.run(mode)
