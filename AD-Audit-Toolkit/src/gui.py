"""Окно приложения (tkinter): подключение, сбор, прогресс, журнал, сохранение JSON.

Вся работа с AD идёт в фоновых потоках; окно получает события через очередь (tkinter не потокобезопасен).
"""
from __future__ import annotations

import json
import logging
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import collector as col
from ad_client import SECURITY_MODES, ADError
from mock_ad import make_client

log = logging.getLogger("ad_collector.gui")
STATUS_COLORS = {"off": "#9ca3af", "busy": "#f59e0b", "ok": "#16a34a", "error": "#dc2626"}


class QueueLogHandler(logging.Handler):
    def __init__(self, q: queue.Queue):
        super().__init__(logging.INFO)
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.q.put(("log", record.levelno, self.format(record)))
        except Exception:
            self.handleError(record)


class CollectorApp:
    def __init__(self, root: tk.Tk, settings_path: Path, log_path: Path | None = None, demo: bool = False):
        self.root, self.settings_path, self.log_path = root, Path(settings_path), log_path
        self.q: queue.Queue = queue.Queue()
        self.client = None
        self.result: dict | None = None
        self.worker: threading.Thread | None = None
        self.cancel = threading.Event()
        self.busy = None                  # None | "connect" | "collect" | "save"
        self.closing = False
        self.handler = QueueLogHandler(self.q)
        logging.getLogger("ad_collector").addHandler(self.handler)

        s = self._load_settings()
        if demo:
            s.update(dc="mock", user="DEMO\\reader")
        self.v_dc = tk.StringVar(value=s.get("dc", ""))
        self.v_user = tk.StringVar(value=s.get("user", ""))
        self.v_pass = tk.StringVar(value="demo" if demo else "")
        self.v_sec = tk.StringVar(value=SECURITY_MODES.get(s.get("security", "auto"), SECURITY_MODES["auto"]))
        self.v_verify = tk.BooleanVar(value=bool(s.get("verify_cert", False)))
        self.v_timeout = tk.IntVar(value=int(s.get("timeout", 10)))
        self.v_offices = tk.StringVar(value=s.get("offices_ou", ""))
        self.last_dir = s.get("last_dir") or str(Path.home())
        self.v_status = tk.StringVar(value="Не подключено")
        self.v_progress = tk.DoubleVar(value=0)
        self.v_phase = tk.StringVar(value="")
        self.stats = {k: tk.StringVar(value="—") for k in ("ous", "users", "groups", "computers", "offices", "positions")}

        root.title("Сбор данных Active Directory")
        root.minsize(760, 600)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build()
        self._set_status("off", "Не подключено")
        self._update_buttons()
        if self.log_path:
            log.info("Журнал пишется в файл: %s", self.log_path)
        if demo:
            log.info("Демо-режим: тестовый домен demo.local в памяти (адрес «mock»)")
        root.after(100, self._poll)

    # ---------- интерфейс
    def _build(self):
        pad = {"padx": 8, "pady": 4}
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="both", expand=True)
        top.columnconfigure(0, weight=1)
        top.rowconfigure(3, weight=1)

        conn = ttk.LabelFrame(top, text="Подключение к контроллеру домена", padding=8)
        conn.grid(row=0, column=0, sticky="ew")
        conn.columnconfigure(1, weight=1)
        conn.columnconfigure(3, weight=1)
        ttk.Label(conn, text="Контроллер домена:").grid(row=0, column=0, sticky="w", **pad)
        self.e_dc = ttk.Entry(conn, textvariable=self.v_dc)
        self.e_dc.grid(row=0, column=1, sticky="ew", **pad)
        ttk.Label(conn, text="Защита:").grid(row=0, column=2, sticky="w", **pad)
        self.c_sec = ttk.Combobox(conn, textvariable=self.v_sec, values=list(SECURITY_MODES.values()), state="readonly")
        self.c_sec.grid(row=0, column=3, sticky="ew", **pad)
        ttk.Label(conn, text="Логин:").grid(row=1, column=0, sticky="w", **pad)
        self.e_user = ttk.Entry(conn, textvariable=self.v_user)
        self.e_user.grid(row=1, column=1, sticky="ew", **pad)
        ttk.Label(conn, text="Пароль:").grid(row=1, column=2, sticky="w", **pad)
        self.e_pass = ttk.Entry(conn, textvariable=self.v_pass, show="•")
        self.e_pass.grid(row=1, column=3, sticky="ew", **pad)
        self.e_pass.bind("<Return>", lambda e: self.connect())
        ttk.Label(conn, text="ДОМЕН\\user или user@домен", foreground="#6b7280").grid(
            row=2, column=1, sticky="w", padx=8)
        opts = ttk.Frame(conn)
        opts.grid(row=2, column=3, sticky="w", padx=4)
        ttk.Checkbutton(opts, text="Проверять сертификат", variable=self.v_verify).pack(side="left")
        ttk.Label(opts, text="   Таймаут, с:").pack(side="left")
        ttk.Spinbox(opts, from_=3, to=300, width=5, textvariable=self.v_timeout).pack(side="left", padx=4)

        row = ttk.Frame(conn)
        row.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        self.b_connect = ttk.Button(row, text="Подключиться", command=self.connect)
        self.b_connect.pack(side="left", padx=8)
        self.dot = tk.Canvas(row, width=14, height=14, highlightthickness=0, bg=self._bg())
        self.dot.pack(side="left")
        self.dot_id = self.dot.create_oval(2, 2, 12, 12, fill=STATUS_COLORS["off"], outline="")
        self.l_status = ttk.Label(row, textvariable=self.v_status, wraplength=560)
        self.l_status.pack(side="left", padx=6, fill="x", expand=True)

        job = ttk.LabelFrame(top, text="Сбор данных", padding=8)
        job.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        job.columnconfigure(1, weight=1)
        ttk.Label(job, text="OU площадок (необязательно):").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(job, textvariable=self.v_offices).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Label(job, text="имя или DN; пусто — найти «Площадки», «Филиалы», «Sites»…",
                  foreground="#6b7280").grid(row=1, column=1, sticky="w", padx=8)
        btns = ttk.Frame(job)
        btns.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.b_collect = ttk.Button(btns, text="Собрать данные", command=self.collect)
        self.b_collect.pack(side="left", padx=8)
        self.b_stop = ttk.Button(btns, text="Остановить", command=self.stop)
        self.b_stop.pack(side="left")
        self.b_save = ttk.Button(btns, text="Сохранить JSON", command=self.save)
        self.b_save.pack(side="right", padx=8)
        self.pb = ttk.Progressbar(job, variable=self.v_progress, maximum=100)
        self.pb.grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 2))
        ttk.Label(job, textvariable=self.v_phase).grid(row=4, column=0, columnspan=2, sticky="w", padx=8)

        stats = ttk.Frame(top, padding=(0, 8, 0, 0))
        stats.grid(row=2, column=0, sticky="ew")
        for i, (key, title) in enumerate((("ous", "OU"), ("users", "Пользователи"), ("groups", "Группы"),
                                          ("computers", "Компьютеры"), ("offices", "Площадки"),
                                          ("positions", "Должности"))):
            stats.columnconfigure(i, weight=1)
            box = ttk.Frame(stats, padding=4, relief="groove")
            box.grid(row=0, column=i, sticky="ew", padx=3)
            ttk.Label(box, text=title, foreground="#6b7280").pack()
            ttk.Label(box, textvariable=self.stats[key], font=("TkDefaultFont", 13, "bold")).pack()

        nb = ttk.Notebook(top)
        nb.grid(row=3, column=0, sticky="nsew", pady=(8, 0))
        self.nb = nb
        self.t_log = ScrolledText(nb, height=12, state="disabled", wrap="word",
                                  font=("Consolas" if sys.platform == "win32" else "TkFixedFont", 9))
        self.t_log.tag_configure("warn", foreground="#b45309")
        self.t_log.tag_configure("error", foreground="#dc2626")
        nb.add(self.t_log, text="Журнал")
        tree_frame = ttk.Frame(nb)
        self.tree = ttk.Treeview(tree_frame, columns=("users", "computers", "groups", "desc"), show="tree headings")
        for cid, title, w in (("#0", "OU", 280), ("users", "Польз.", 70), ("computers", "Комп.", 70),
                              ("groups", "Групп", 70), ("desc", "Описание", 260)):
            self.tree.heading(cid, text=title)
            self.tree.column(cid, width=w, stretch=cid in ("#0", "desc"), anchor="w" if cid in ("#0", "desc") else "e")
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        nb.add(tree_frame, text="Дерево OU")
        self.t_lists = ScrolledText(nb, height=12, state="disabled", wrap="word")
        nb.add(self.t_lists, text="Площадки и должности")

        foot = ttk.Label(top, text=f"Журнал: {self.log_path}" if self.log_path else "", foreground="#6b7280")
        foot.grid(row=4, column=0, sticky="w", pady=(6, 0))

    def _bg(self):
        try:
            return ttk.Style().lookup("TFrame", "background") or self.root.cget("bg")
        except tk.TclError:
            return self.root.cget("bg")

    def _set_status(self, kind: str, text: str):
        self.dot.itemconfigure(self.dot_id, fill=STATUS_COLORS[kind])
        self.v_status.set(text)

    def _update_buttons(self):
        idle = self.busy is None
        connected = bool(self.client and self.client.connected)
        self.b_connect.configure(state="normal" if idle else "disabled",
                                 text="Переподключиться" if connected else "Подключиться")
        self.b_collect.configure(state="normal" if idle and connected else "disabled")
        self.b_stop.configure(state="normal" if self.busy == "collect" else "disabled")
        self.b_save.configure(state="normal" if idle and self.result else "disabled")

    def _append_log(self, level, text):
        t = self.t_log
        t.configure(state="normal")
        tag = "error" if level >= logging.ERROR else "warn" if level >= logging.WARNING else ""
        t.insert("end", text + "\n", tag)
        if int(t.index("end-1c").split(".")[0]) > 5000:      # журнал в окне не растёт бесконечно (в файле — всё)
            t.delete("1.0", "1000.0")
        t.see("end")
        t.configure(state="disabled")

    # ---------- очередь событий из потоков
    def _poll(self):
        if self.closing:
            return
        deadline = time.monotonic() + 0.05
        try:
            while time.monotonic() < deadline:
                ev = self.q.get_nowait()
                getattr(self, "_on_" + ev[0])(*ev[1:])
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _run(self, kind: str, target, *args):
        self.busy = kind
        self._update_buttons()

        def wrapper():
            try:
                target(*args)
            except Exception as e:                            # неожиданная ошибка — в журнал и в окно, не молча
                log.exception("Внутренняя ошибка")
                self.q.put(("failed", kind, f"Внутренняя ошибка: {e}"))
        self.worker = threading.Thread(target=wrapper, name=f"ad-{kind}", daemon=True)
        self.worker.start()

    def _on_log(self, level, text):
        self._append_log(level, text)

    def _on_progress(self, frac, msg):
        self.v_progress.set(round(frac * 100, 1))
        self.v_phase.set(msg)

    def _on_failed(self, kind, text):
        self.busy = None
        if kind == "connect":
            self._set_status("error", text)
        else:
            self.v_phase.set(text)
            messagebox.showerror("Ошибка", text, parent=self.root)
        self._update_buttons()

    # ---------- подключение
    def _security_key(self):
        return next((k for k, v in SECURITY_MODES.items() if v == self.v_sec.get()), "auto")

    def connect(self):
        if self.busy:
            return
        dc, user, password = self.v_dc.get().strip(), self.v_user.get().strip(), self.v_pass.get()
        if self.client:
            self.client.close()
            self.client = None
        self._save_settings()
        self._set_status("busy", f"Подключение к {dc}…")
        try:
            timeout = max(3, int(self.v_timeout.get()))
        except (tk.TclError, ValueError):
            timeout = 10
        client = make_client(dc, user, password, security=self._security_key(), verify_cert=self.v_verify.get(),
                             connect_timeout=timeout, receive_timeout=max(30, timeout * 3))
        self._run("connect", self._connect_worker, client)

    def _connect_worker(self, client):
        try:
            client.connect()
        except ADError as e:
            log.error("Подключение не выполнено: %s", e)
            self.q.put(("failed", "connect", str(e)))
            return
        self.q.put(("connected", client))

    def _on_connected(self, client):
        self.busy = None
        if self.closing:
            client.close()
            return
        self.client = client
        warn = "" if client.encrypted else "  ⚠ без шифрования"
        self._set_status("ok", f"Подключено: {client.dc_name} · домен {client.domain} · {client.mode_used.upper()}{warn}")
        self._update_buttons()

    # ---------- сбор
    def collect(self):
        if self.busy or not (self.client and self.client.connected):
            return
        self._save_settings()
        self.cancel.clear()
        self.v_progress.set(0)
        for v in self.stats.values():
            v.set("…")
        self.nb.select(0)
        self._run("collect", self._collect_worker, self.client, self.v_offices.get())

    def _collect_worker(self, client, offices_ou):
        last = [0.0]

        def progress(frac, msg):
            now = time.monotonic()
            if now - last[0] >= 0.1 or frac >= 1:          # не чаще 10 раз в секунду
                last[0] = now
                self.q.put(("progress", frac, msg))
        log.info("Сбор данных из %s (база %s)", client.dc_name, client.base_dn)
        result = col.Collector(client, progress, self.cancel.is_set, offices_ou=offices_ou).collect()
        si = result["scan_info"]
        log.info("Итого: пользователей %d, групп %d, OU %d, компьютеров %d, площадок %d, должностей %d — за %s с",
                 si["total_users"], si["total_groups"], si["total_ous"], si["total_computers"],
                 len(result["offices"]), len(result["positions"]), si["duration_s"])
        self.q.put(("collected", result))

    def _on_collected(self, result):
        self.busy = None
        self.result = result
        si = result["scan_info"]
        self.stats["ous"].set(si["total_ous"])
        self.stats["users"].set(f"{si['total_users']} ({si['disabled_users']} откл.)" if si["disabled_users"] else si["total_users"])
        self.stats["groups"].set(si["total_groups"])
        self.stats["computers"].set(si["total_computers"])
        self.stats["offices"].set(len(result["offices"]))
        self.stats["positions"].set(len(result["positions"]))
        self._fill_tree(result["ou_tree"])
        self._fill_lists(result)
        if si["status"] == "complete":
            self.v_phase.set(f"Готово за {si['duration_s']} с" + (f" · предупреждений: {len(si['warnings'])}" if si["warnings"] else ""))
        elif si["status"] == "cancelled":
            self.v_phase.set("Остановлено — данные неполные, их можно сохранить")
        else:
            self.v_phase.set("Сбор прерван: " + "; ".join(si["errors"])[:300])
            if self.client and not self._alive():
                self._set_status("error", "Связь с контроллером домена потеряна — переподключитесь")
                self.client = None
        self._update_buttons()

    def _alive(self):
        try:
            return bool(self.client.conn and not self.client.conn.closed)
        except Exception:
            return False

    def stop(self):
        if self.busy == "collect":
            self.cancel.set()
            self.v_phase.set("Останавливается…")
            log.info("Остановка по запросу пользователя")

    def _fill_tree(self, roots):
        self.tree.delete(*self.tree.get_children())

        def add(parent, node):
            c = node.get("counts", {})
            iid = self.tree.insert(parent, "end", text=node["name"], open=parent == "",
                                   values=(c.get("users", ""), c.get("computers", ""), c.get("groups", ""),
                                           node.get("description") or ""))
            for ch in node["children"]:
                add(iid, ch)
        for n in roots:
            add("", n)

    def _fill_lists(self, r):
        d = r["offices_detail"]
        src = {"ou": "из OU: " + "; ".join(d["ou_containers"]), "physicalDeliveryOfficeName":
               "из атрибута «Офис» (physicalDeliveryOfficeName) пользователей", "none": "не найдены"}[d["source"]]
        lines = [f"ПЛОЩАДКИ ({len(r['offices'])}) — {src}"]
        if d["from_ou"]:
            lines += [f"  • {o['name']}: пользователей {o['users']}, отделы: {', '.join(o['departments']) or '—'}"
                      for o in d["from_ou"]]
        else:
            lines += [f"  • {o['name']}: {o['users']}" for o in d["from_attribute"]]
        if d["from_ou"] and d["from_attribute"]:
            lines += ["", "Значения атрибута «Офис» у пользователей:"]
            lines += [f"  • {o['name']}: {o['users']}" for o in d["from_attribute"]]
        lines += ["", f"ДОЛЖНОСТИ ({len(r['positions'])})"]
        lines += [f"  • {p['name']}: {p['users']}" for p in r["positions_detail"]]
        lines += ["", f"ОТДЕЛЫ ({len(r['departments'])})"]
        lines += [f"  • {p['name']}: {p['users']}" for p in r["departments_detail"]]
        if r.get("ad_sites"):
            lines += ["", f"САЙТЫ AD ({len(r['ad_sites'])})"]
            lines += [f"  • {s['name'] or '(без сайта)'}: подсети {', '.join(n['subnet'] for n in s['subnets']) or '—'}"
                      for s in r["ad_sites"]]
        t = self.t_lists
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("1.0", "\n".join(lines))
        t.configure(state="disabled")

    # ---------- сохранение
    def save(self):
        if self.busy or not self.result:
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Сохранить JSON", defaultextension=".json",
                                            initialdir=self.last_dir, initialfile=col.default_filename(self.result),
                                            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")])
        if not path:
            return
        self.save_to(path)

    def save_to(self, path):
        self.last_dir = str(Path(path).parent)
        self._save_settings()
        self._run("save", self._save_worker, self.result, path)

    def _save_worker(self, result, path):
        try:
            p = col.save_json(result, path)
        except OSError as e:
            log.error("Не удалось сохранить %s: %s", path, e)
            self.q.put(("failed", "save", f"Не удалось сохранить файл: {e}"))
            return
        log.info("Сохранено: %s (%.1f МБ)", p, p.stat().st_size / 1048576)
        self.q.put(("saved", str(p)))

    def _on_saved(self, path):
        self.busy = None
        self.v_phase.set(f"Сохранено: {path}")
        self._update_buttons()

    # ---------- настройки и закрытие
    def _load_settings(self) -> dict:
        try:
            return json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_settings(self):
        data = {"dc": self.v_dc.get().strip(), "user": self.v_user.get().strip(), "security": self._security_key(),
                "verify_cert": self.v_verify.get(), "offices_ou": self.v_offices.get().strip(),
                "last_dir": self.last_dir}
        try:
            data["timeout"] = int(self.v_timeout.get())
        except (tk.TclError, ValueError):
            pass
        if data["dc"].lower().startswith("mock"):            # демо-адрес не запоминаем
            return
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:
            log.warning("Настройки не сохранены: %s", e)

    def on_close(self):
        if self.busy == "collect" and not messagebox.askyesno(
                "Выход", "Сбор данных ещё идёт. Остановить и выйти?", parent=self.root):
            return
        self.closing = True
        self.cancel.set()
        if self.busy != "collect":                          # во время сбора соединение закроет сам поток
            if self.client:
                self.client.close()
        logging.getLogger("ad_collector").removeHandler(self.handler)
        log.info("Окно закрыто")
        self.root.destroy()


def run(settings_path: Path, log_path: Path | None, demo: bool = False) -> int:
    if sys.platform == "win32":
        try:                                        # чёткий шрифт на мониторах с масштабированием
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    style = ttk.Style(root)
    if sys.platform.startswith("linux") and "clam" in style.theme_names():
        style.theme_use("clam")
    CollectorApp(root, settings_path, log_path, demo=demo)
    root.mainloop()
    return 0
