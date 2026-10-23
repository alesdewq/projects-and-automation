"""Выгрузка результатов: JSON (полные данные), CSV (таблица устройств), Markdown (отчёт для людей)."""
from __future__ import annotations

import csv
import json
import os
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

FORMATS = ("json", "csv", "md")
CSV_COLUMNS = [("ip", "IP"), ("mac", "MAC"), ("vendor", "Производитель"), ("hostname", "Hostname"), ("type", "Тип"),
               ("os", "ОС"), ("ports", "Открытые порты"), ("source", "Источник"), ("vsphere_name", "Имя в vSphere"),
               ("power_state", "Питание ВМ")]
SOURCE_NAMES = {"scan": "сеть", "vsphere": "vSphere", "vsphere+scan": "vSphere + сеть"}


def _atomic_write(path: Path, write) -> None:
    """Пишем во временный файл рядом и переименовываем: недописанный отчёт не появится."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig" if path.suffix == ".csv" else "utf-8", newline="") as f:
            write(f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(map(str, value))
    return str(value)


def _csv_safe(text: str) -> str:
    """Защита от формул в Excel: имена узлов и баннеры приходят из сети и могут начинаться с = + - @."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_json(result: dict, path: Path) -> Path:
    _atomic_write(path, lambda f: json.dump(result, f, ensure_ascii=False, indent=2, default=str))
    return path


def write_csv(result: dict, path: Path, delimiter: str = ";") -> Path:
    """CSV в UTF-8 с BOM и разделителем «;» — так его без мастера импорта открывает Excel с русской локалью."""
    def write(f):
        w = csv.writer(f, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL)
        w.writerow([label for _, label in CSV_COLUMNS])
        for d in result.get("devices", []):
            row = []
            for key, _ in CSV_COLUMNS:
                v = d.get(key)
                if key == "source":
                    v = SOURCE_NAMES.get(v, v)
                row.append(_csv_safe(_cell(v)))
            w.writerow(row)
    _atomic_write(path, write)
    return path


def _md(value) -> str:
    """Ячейка Markdown-таблицы: экранируем | и переводы строк, пустое — «—»."""
    s = _cell(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()
    for ch in "*`<>[]":
        s = s.replace(ch, "\\" + ch)
    return s or "—"


def _table(headers: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(_md(c) for c in r) + " |" for r in rows]
    return out


def markdown_report(result: dict) -> str:
    devices = result.get("devices", [])
    vs = result.get("vsphere")
    scan = result.get("scan")
    lines = ["# Отчёт об инвентаризации инфраструктуры", "",
             f"- Начало: {result.get('started')}", f"- Окончание: {result.get('finished')} "
             f"(длительность {result.get('duration_s')} с)", f"- Компьютер, с которого выполнялось: {_md(result.get('host'))}",
             f"- Версия программы: {result.get('version')}", ""]
    if result.get("cancelled"):
        lines += ["> **Задание остановлено пользователем — данные неполные.**", ""]

    lines += ["## Итоги", ""]
    types = Counter(d.get("type") or "Не определён" for d in devices)
    summary = [["Всего устройств", len(devices)]]
    if vs:
        summary += [["ESXi-хостов", len(vs.get("hosts", []))],
                    ["Виртуальных машин", sum(1 for v in vs.get("vms", []) if not v.get("template"))],
                    ["Шаблонов ВМ", sum(1 for v in vs.get("vms", []) if v.get("template"))]]
    if scan:
        summary += [["Проверено адресов", f"{scan.get('checked')} из {scan.get('total')}"],
                    ["Отвечающих узлов в сети", scan.get("alive")]]
    lines += _table(["Показатель", "Значение"], summary) + [""]
    if types:
        lines += ["### Типы устройств", ""] + _table(["Тип", "Количество"], types.most_common()) + [""]

    if result.get("errors") or result.get("warnings"):
        lines += ["## Ошибки и предупреждения", ""]
        lines += [f"- ⚠️ {_md(w)}" for w in result.get("warnings", [])]
        lines += [f"- ❌ {_md(e)}" for e in result.get("errors", [])]
        lines += [""]

    if vs:
        about = vs.get("about") or {}
        lines += ["## vSphere", "", f"- Сервер: {_md(about.get('name'))}",
                  f"- Датацентры: {_md(vs.get('datacenters'))}",
                  f"- Кластеры: {_md([c.get('name') for c in vs.get('clusters', [])])}", ""]
        if vs.get("hosts"):
            lines += ["### ESXi-хосты", ""]
            lines += _table(["Хост", "Кластер", "Модель", "CPU ядер", "RAM, ГБ", "Версия", "Состояние", "IP управления"],
                            [[h.get("name"), h.get("cluster"), f"{h.get('vendor') or ''} {h.get('model') or ''}".strip(),
                              h.get("cpu_cores"), h.get("memory_gb"), h.get("version"), h.get("connection_state"),
                              [n.get("ip") for n in h.get("vmkernel", []) if n.get("ip")]] for h in vs["hosts"]]) + [""]
        if vs.get("vms"):
            lines += ["### Виртуальные машины", ""]
            lines += _table(["ВМ", "Питание", "ОС", "Hostname", "IP", "vCPU", "RAM, МБ", "Диск, ГБ", "Хост"],
                            [[v.get("name") + (" (шаблон)" if v.get("template") else ""), v.get("power_state"),
                              v.get("guest_os"), v.get("hostname"),
                              sorted({ip for n in v.get("nics", []) for ip in n.get("ips", [])} | ({v["ip"]} if v.get("ip") else set())),
                              v.get("cpu"), v.get("memory_mb"), v.get("disk_gb"), v.get("host")] for v in vs["vms"]]) + [""]
        if vs.get("datastores"):
            lines += ["### Хранилища", ""]
            lines += _table(["Хранилище", "Тип", "Ёмкость, ГБ", "Свободно, ГБ"],
                            [[d.get("name"), d.get("type"), d.get("capacity_gb"), d.get("free_gb")]
                             for d in vs["datastores"]]) + [""]

    if scan:
        lines += ["## Сканирование сети", "", f"- Подсети: {_md(scan.get('subnets'))}",
                  f"- Порты: {_md(scan.get('ports'))}", f"- Справочник производителей: {_md(scan.get('oui_source'))}",
                  f"- Длительность: {scan.get('elapsed_s')} с", ""]

    lines += ["## Устройства", ""]
    if devices:
        lines += _table(["IP", "MAC", "Производитель", "Hostname", "Тип", "ОС", "Порты", "Источник"],
                        [[d.get("ip"), d.get("mac"), d.get("vendor"), d.get("hostname"), d.get("type"), d.get("os"),
                          d.get("ports"), SOURCE_NAMES.get(d.get("source"), d.get("source"))] for d in devices])
    else:
        lines += ["Устройства не найдены."]
    lines += ["", f"_Сформировано {datetime.now().strftime('%d.%m.%Y %H:%M')} программой infra-inventory._", ""]
    return "\n".join(lines)


def write_markdown(result: dict, path: Path) -> Path:
    text = markdown_report(result)
    _atomic_write(path, lambda f: f.write(text))
    return path


def export(result: dict, folder: str | os.PathLike, formats=FORMATS, stamp: str | None = None) -> list[Path]:
    """Сохранить отчёты в папку (создаётся при необходимости). Возвращает пути созданных файлов."""
    folder = Path(folder).expanduser()
    folder.mkdir(parents=True, exist_ok=True)
    stamp = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    writers = {"json": write_json, "csv": write_csv, "md": write_markdown}
    out = []
    for fmt in formats:
        if fmt not in writers:
            raise ValueError(f"Неизвестный формат: {fmt}")
        out.append(writers[fmt](result, folder / f"inventory_{stamp}.{fmt}"))
    return out
