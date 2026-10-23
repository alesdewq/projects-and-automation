"""Задание инвентаризации: vSphere + сканирование подсетей + объединение результатов.

Не зависит от GUI: тот же run_job вызывают окно (в фоновом потоке) и консольный режим main.py --cli.
"""
from __future__ import annotations

import ipaddress
import logging
import platform
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Callable

from network_scanner import DEFAULT_PORTS, NetworkScanner, ScanError, parse_targets
from vsphere_client import VSphereClient, VSphereError, devices_from_inventory, make_client

__version__ = "1.0.0"
log = logging.getLogger("inventory")


@dataclass
class JobConfig:
    vcenter: str = ""
    user: str = ""
    password: str = field(default="", repr=False)
    verify_ssl: bool = False
    vcenter_timeout: float = 15
    subnets: str = ""
    scan_vsphere: bool = True
    scan_subnets: bool = True
    detect_types: bool = True
    ports: tuple = DEFAULT_PORTS
    workers: int = 64
    connect_timeout: float = 0.7
    scan_timeout: float = 600
    use_ping: bool = True

    def validate(self) -> list[str]:
        errors = []
        if not (self.scan_vsphere or self.scan_subnets):
            errors.append("Выберите хотя бы одно: сканировать vSphere или подсети")
        if self.scan_vsphere and not self.vcenter.strip():
            errors.append("Укажите адрес vCenter (или снимите «Сканировать vSphere»)")
        if self.scan_vsphere and not self.user.strip():
            errors.append("Укажите логин vCenter")
        if self.scan_subnets:
            try:
                parse_targets(self.subnets)
            except ScanError as e:
                errors.append(str(e))
        return errors

    def public(self) -> dict:
        """Настройки для отчёта — без пароля."""
        d = asdict(self)
        d.pop("password")
        d["ports"] = list(self.ports)
        return d


def _ip_key(dev: dict):
    try:
        ip = ipaddress.ip_address(dev.get("ip") or "")
        return (0, ip.version, int(ip), dev.get("hostname") or "")
    except ValueError:
        return (1, 0, 0, dev.get("hostname") or "")


def merge_devices(vs_devices: list[dict], scan_devices: list[dict]) -> list[dict]:
    """Объединение по IP: данные vSphere (имя ВМ, ОС) + сети (реальный MAC, порты, баннеры)."""
    by_ip: dict[str, dict] = {}
    out = []
    for d in scan_devices:
        row = dict(d)
        out.append(row)
        by_ip[row["ip"]] = row
    for v in vs_devices:
        row = by_ip.get(v["ip"]) if v.get("ip") else None
        if row is None:
            out.append(dict(v))
            if v.get("ip"):
                by_ip[v["ip"]] = out[-1]
            continue
        row["source"] = "vsphere+scan"
        row["vsphere_name"] = v.get("vsphere_name")
        row["os"] = v.get("os") or row.get("os", "")
        row["power_state"] = v.get("power_state", "")
        row["scan_type"] = row.get("type", "")
        row["type"] = v["type"]
        row["hostname"] = v.get("hostname") or row.get("hostname", "")
        if not row.get("mac") and v.get("mac"):
            row["mac"] = v["mac"]
        if not row.get("vendor") and v.get("vendor"):
            row["vendor"] = v["vendor"]
    for d in out:
        for k in ("mac", "vendor", "hostname", "type", "os", "source"):
            d.setdefault(k, "")
        d.setdefault("ports", [])
    out.sort(key=_ip_key)
    return out


def run_job(cfg: JobConfig, *, client: VSphereClient | None = None, progress: Callable | None = None,
            is_cancelled: Callable[[], bool] | None = None, on_device: Callable | None = None) -> dict:
    """Выполнить задание. Ошибка одной части (например, vCenter недоступен) не отменяет другую:
    она попадает в result["errors"]. ``progress(доля 0..1, сообщение)``."""
    progress = progress or (lambda *a: None)
    is_cancelled = is_cancelled or (lambda: False)
    started = datetime.now().astimezone()
    t0 = time.monotonic()
    result = {"tool": "infra-inventory", "version": __version__, "started": started.isoformat(timespec="seconds"),
              "finished": None, "duration_s": None, "host": platform.node(), "settings": cfg.public(),
              "vsphere": None, "scan": None, "devices": [], "errors": [], "warnings": [], "cancelled": False}
    log.info("Задание запущено: vSphere=%s, подсети=%s, типы=%s", cfg.scan_vsphere, cfg.scan_subnets, cfg.detect_types)
    share_vs = 0.3 if (cfg.scan_vsphere and cfg.scan_subnets) else 1.0
    vs_devices, scan_devices = [], []

    if cfg.scan_vsphere:
        own = client is None or not client.connected
        try:
            if own:
                client = make_client(cfg.vcenter, cfg.user, cfg.password, verify_ssl=cfg.verify_ssl,
                                     timeout=cfg.vcenter_timeout)
                progress(0.0, "Подключение к vCenter…")
                client.connect()
            inv = client.collect(progress=lambda f, m: progress(f * share_vs, m), is_cancelled=is_cancelled)
            result["vsphere"] = inv
            vs_devices = devices_from_inventory(inv)
            log.info("vSphere: хостов %d, ВМ %d, хранилищ %d", len(inv["hosts"]), len(inv["vms"]), len(inv["datastores"]))
            if on_device:
                for d in vs_devices:
                    on_device(d)
        except VSphereError as e:
            if not is_cancelled():
                log.error("vSphere: %s", e)
                result["errors"].append(f"vSphere: {e}")
        finally:
            if own and client is not None:
                client.disconnect()

    if cfg.scan_subnets and not is_cancelled():
        try:
            addrs, labels = parse_targets(cfg.subnets)
            base = share_vs if cfg.scan_vsphere else 0.0
            span = 1.0 - base
            progress(base, f"Сканирование {len(addrs)} адресов…")
            scanner = NetworkScanner(cfg.ports, connect_timeout=cfg.connect_timeout, workers=cfg.workers,
                                     use_ping=cfg.use_ping, detect_types=cfg.detect_types, scan_timeout=cfg.scan_timeout)
            scan = scanner.scan(addrs, progress=lambda done, total, msg: progress(base + span * done / max(1, total), msg),
                                on_device=on_device, is_cancelled=is_cancelled)
            scan["subnets"] = labels
            scan_devices = scan.pop("devices")
            result["scan"] = scan
            if scan["timed_out"]:
                result["warnings"].append(f"Таймаут сканирования {cfg.scan_timeout:.0f} с: проверено {scan['checked']} "
                                          f"из {scan['total']} адресов, результаты неполные")
            result["errors"] += [f"Сканирование: {e}" for e in scan["errors"][:50]]
        except ScanError as e:
            log.error("Сканирование: %s", e)
            result["errors"].append(f"Сканирование: {e}")

    result["devices"] = merge_devices(vs_devices, scan_devices)
    result["cancelled"] = is_cancelled()
    if result["cancelled"]:
        result["warnings"].append("Задание остановлено пользователем, результаты неполные")
    result["finished"] = datetime.now().astimezone().isoformat(timespec="seconds")
    result["duration_s"] = round(time.monotonic() - t0, 1)
    progress(1.0, "Готово")
    log.info("Задание завершено за %.1f с: устройств %d, ошибок %d", result["duration_s"], len(result["devices"]),
             len(result["errors"]))
    return result
