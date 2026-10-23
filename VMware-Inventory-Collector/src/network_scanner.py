"""Сканирование подсетей без прав администратора.

Только стандартная библиотека и обычные (непривилегированные) операции:
  * TCP connect к набору портов (без raw-сокетов/SYN-сканирования);
    ответ RST («порт закрыт») тоже значит, что узел жив;
  * системная команда ping (у неё свои права, нам они не нужны);
  * обратный DNS и NetBIOS-запрос NBSTAT (UDP 137) — имя и MAC Windows-машин даже через маршрутизатор;
  * MAC из ARP-кэша ОС (только для своих L2-сегментов) и производитель по OUI;
  * баннеры SSH/HTTP и набор открытых портов для определения типа устройства.
"""
from __future__ import annotations

import concurrent.futures as cf
import errno
import ipaddress
import logging
import os
import platform
import re
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

log = logging.getLogger("inventory.scan")

DEFAULT_PORTS = (21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 554, 631, 902, 3389, 5000, 5001,
                 5900, 5985, 8006, 8080, 8443, 9100)
MAX_HOSTS = 65536            # не больше /16 за одно задание
_SYSTEM = platform.system()
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0   # CREATE_NO_WINDOW: без мелькания консоли


class ScanError(Exception):
    """Ошибка параметров сканирования (понятное пользователю сообщение)."""


# --------------------------------------------------------------------------- цели
def parse_targets(text: str, max_hosts: int = MAX_HOSTS) -> tuple[list[str], list[str]]:
    """Подсети из текста: CIDR, отдельные IP и диапазоны (10.0.0.5-10.0.0.20 или 10.0.0.5-20),
    через перевод строки, запятую, точку с запятой или пробел. Строки с # — комментарии.
    Возвращает (уникальные адреса по порядку, нормализованные подсети). Ошибки — ScanError."""
    tokens = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        tokens += [t for t in re.split(r"[\s,;]+", line) if t]
    if not tokens:
        raise ScanError("Не указано ни одной подсети")
    seen, addrs, labels, bad = set(), [], [], []

    def add(ip):
        s = str(ip)
        if s not in seen:
            seen.add(s)
            addrs.append(s)
            if len(addrs) > max_hosts:
                raise ScanError(f"Слишком много адресов (больше {max_hosts}). Разбейте задание на подсети поменьше")

    for tok in tokens:
        try:
            if "-" in tok:
                a, b = tok.split("-", 1)
                start = ipaddress.ip_address(a)
                if "." not in b and ":" not in b:          # 10.0.0.5-20
                    b = a.rsplit(".", 1)[0] + "." + b
                end = ipaddress.ip_address(b)
                if start.version != end.version or int(end) < int(start):
                    raise ValueError
                if int(end) - int(start) >= max_hosts:
                    raise ScanError(f"Диапазон {tok} слишком большой")
                for n in range(int(start), int(end) + 1):
                    add(ipaddress.ip_address(n))
                labels.append(f"{start}-{end}")
            elif "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.num_addresses > max_hosts * 2:
                    raise ScanError(f"Подсеть {net} слишком большая (больше /16)")
                hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
                for ip in hosts:
                    add(ip)
                labels.append(str(net))
            else:
                add(ipaddress.ip_address(tok))
                labels.append(tok)
        except ScanError:
            raise
        except ValueError:
            bad.append(tok)
    if bad:
        raise ScanError("Не удалось разобрать: " + ", ".join(bad[:10]) + (" …" if len(bad) > 10 else ""))
    return addrs, labels


# --------------------------------------------------------------------------- проверка портов
_IN_PROGRESS = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035, 10036}  # 10035/36 — Windows
_REFUSED = {errno.ECONNREFUSED, 10061}


def probe_ports(ip: str, ports: Iterable[int], timeout: float) -> tuple[list[int], bool]:
    """Параллельный TCP connect ко всем портам узла с общим таймаутом.
    Возвращает (открытые порты, был ли хоть один RST — признак живого узла)."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sel = selectors.DefaultSelector()
    socks, open_ports, refused = [], [], False
    try:
        for port in ports:
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
            except OSError as e:          # кончились дескрипторы — проверим сколько успели
                log.debug("socket(): %s", e)
                break
            socks.append(s)
            s.setblocking(False)
            rc = s.connect_ex((ip, port))
            if rc == 0:
                open_ports.append(port)
            elif rc in _REFUSED:
                refused = True
            elif rc in _IN_PROGRESS:
                sel.register(s, selectors.EVENT_WRITE, port)
        deadline = time.monotonic() + timeout
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            for key, _ in sel.select(left):
                sel.unregister(key.fileobj)
                err = key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    open_ports.append(key.data)
                elif err in _REFUSED:
                    refused = True
    finally:
        sel.close()
        for s in socks:
            s.close()
    return sorted(open_ports), refused


def ping(ip: str, timeout: float = 1.0) -> bool:
    """Системный ping (одна попытка). Нет команды ping — False, без ошибки."""
    exe = shutil.which("ping")
    if not exe:
        return False
    ms = max(1, int(timeout * 1000))
    if _SYSTEM == "Windows":
        cmd = [exe, "-n", "1", "-w", str(ms), ip]
    elif _SYSTEM == "Darwin":
        cmd = [exe, "-c", "1", "-W", str(ms), ip]
    else:
        cmd = [exe, "-c", "1", "-W", str(max(1, round(timeout))), ip]
    if ":" in ip and _SYSTEM != "Windows":
        cmd.insert(1, "-6")
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                           timeout=timeout + 2, creationflags=_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return False
    # Windows отвечает кодом 0 и на «Заданный узел недоступен» — смотрим на TTL= в ответе
    return r.returncode == 0 and (_SYSTEM != "Windows" or b"TTL=" in r.stdout.upper())


# --------------------------------------------------------------------------- имена
def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


_NBSTAT_QUERY = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01")


def parse_nbstat(data: bytes) -> tuple[str, str, str]:
    """Ответ NetBIOS NBSTAT → (имя компьютера, рабочая группа/домен, MAC). Пустые строки, если не разобрать."""
    try:
        if len(data) < 57:
            return "", "", ""
        pos = 12
        if data[pos] & 0xC0 == 0xC0:          # имя сжато указателем
            pos += 2
        else:
            while pos < len(data) and data[pos]:
                pos += data[pos] + 1
            pos += 1
        pos += 2 + 2 + 4                       # type, class, ttl
        rdlen = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        end = min(len(data), pos + rdlen)
        count = data[pos]
        pos += 1
        name = group = ""
        complete = True
        for _ in range(count):
            if pos + 18 > end:
                complete = False                 # ответ обрезан — MAC за списком имён не читаем
                break
            raw, suffix = data[pos:pos + 15], data[pos + 15]
            flags = struct.unpack(">H", data[pos + 16:pos + 18])[0]
            label = raw.decode("ascii", "replace").strip("\x00 ").strip()
            is_group = bool(flags & 0x8000)
            if suffix == 0x00 and not is_group and not name:
                name = label
            elif suffix == 0x00 and is_group and not group:
                group = label
            pos += 18
        mac = ""
        if complete and pos + 6 <= end:
            m = data[pos:pos + 6]
            if any(m):
                mac = ":".join(f"{b:02X}" for b in m)
        return name, group, mac
    except (IndexError, struct.error):
        return "", "", ""


def netbios_query(ip: str, timeout: float = 0.8) -> tuple[str, str, str]:
    if ":" in ip:
        return "", "", ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_NBSTAT_QUERY, (ip, 137))
            data, _ = s.recvfrom(2048)
        return parse_nbstat(data)
    except OSError:
        return "", "", ""


# --------------------------------------------------------------------------- баннеры
def _clean(text: str, limit: int = 200) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()[:limit]


def ssh_banner(ip: str, port: int = 22, timeout: float = 1.5) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            return _clean(s.recv(256).split(b"\n", 1)[0].decode("utf-8", "replace"))
    except OSError:
        return ""


def http_server(ip: str, port: int = 80, timeout: float = 1.5) -> str:
    """Заголовок Server: ответа на HEAD / (только HTTP, без TLS)."""
    host = f"[{ip}]" if ":" in ip else ip
    req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: infra-inventory\r\n\r\n".encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(req)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return ""
    for line in data.decode("latin-1").split("\r\n")[1:]:
        if line.lower().startswith("server:"):
            return _clean(line.split(":", 1)[1])
    return ""


# --------------------------------------------------------------------------- MAC и производители
def norm_mac(mac: str) -> str:
    parts = re.split(r"[:\-.]", mac.strip())
    if len(parts) == 3 and all(len(p) == 4 for p in parts):          # cisco: aabb.ccdd.eeff
        parts = [p[i:i + 2] for p in parts for i in (0, 2)]
    if len(parts) != 6:
        return ""
    try:
        b = [int(p, 16) for p in parts]
    except ValueError:
        return ""
    if not any(b) or all(x == 0xFF for x in b):
        return ""
    return ":".join(f"{x:02X}" for x in b)


def _run_text(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                           timeout=10, creationflags=_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    enc = "oem" if sys.platform == "win32" else "utf-8"
    return r.stdout.decode(enc, "replace")


def arp_table() -> dict[str, str]:
    """IP → MAC из кэша соседей ОС (без прав администратора)."""
    table = {}
    proc = Path("/proc/net/arp")
    if proc.exists():
        try:
            for line in proc.read_text().splitlines()[1:]:
                f = line.split()
                if len(f) >= 4 and f[2] != "0x0":
                    mac = norm_mac(f[3])
                    if mac:
                        table[f[0]] = mac
        except OSError:
            pass
    if _SYSTEM == "Linux" and shutil.which("ip"):
        for line in _run_text(["ip", "neigh", "show"]).splitlines():   # заодно IPv6
            m = re.match(r"(\S+) .*lladdr ([0-9a-fA-F:]{11,17})", line)
            if m and "FAILED" not in line and "INCOMPLETE" not in line:
                mac = norm_mac(m.group(2))
                if mac:
                    table.setdefault(m.group(1), mac)
    elif _SYSTEM == "Windows":
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", _run_text(["arp", "-a"])):
            mac = norm_mac(m.group(2))
            if mac:
                table[m.group(1)] = mac
    elif _SYSTEM != "Linux" and shutil.which("arp"):                     # macOS / BSD
        for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", _run_text(["arp", "-an"])):
            mac = norm_mac(m.group(2))
            if mac:
                table[m.group(1)] = mac
    return table


# небольшой встроенный справочник; полный — файл Wireshark «manuf» или IEEE «oui.txt» (см. README)
BUILTIN_OUI = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "00:15:5D": "Microsoft (Hyper-V)", "08:00:27": "Oracle VirtualBox", "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen", "00:1C:42": "Parallels", "00:00:0C": "Cisco Systems",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading", "E4:5F:01": "Raspberry Pi Trading",
    "00:11:32": "Synology",
}


class OuiDB:
    """Производитель по MAC. Источники по приоритету: файл (INVENTORY_OUI_FILE, manuf или oui.txt рядом
    с программой), пакет manuf (если установлен), встроенный справочник."""

    def __init__(self, path: str | os.PathLike | None = None):
        self.table: dict[str, str] = {}
        self.long: list[tuple[str, int, str]] = []    # блоки MA-M/MA-S: (префикс-биты, длина, имя)
        self.source = "встроенный справочник"
        here = Path(__file__).resolve().parent
        candidates = [path, os.environ.get("INVENTORY_OUI_FILE"), here / "manuf", here / "oui.txt"]
        for c in candidates:
            if c and Path(c).is_file():
                try:
                    self._load(Path(c))
                    self.source = str(c)
                    break
                except OSError as e:
                    log.warning("Не удалось прочитать справочник OUI %s: %s", c, e)
        self._manuf = None
        if not self.table:
            try:
                from manuf import manuf  # type: ignore
                self._manuf = manuf.MacParser(update=False)
                self.source = "пакет manuf"
            except Exception:  # noqa: BLE001 — пакет необязательный
                self._manuf = None

    def _load(self, path: Path):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)   # IEEE oui.txt
            if m:
                self.table[m.group(1).replace("-", ":").upper()] = m.group(2).strip()
                continue
            f = line.split("\t")                                                         # Wireshark manuf
            if len(f) >= 2:
                prefix = f[0].strip()
                name = (f[2] if len(f) > 2 and f[2].strip() else f[1]).strip()
                if "/" in prefix:
                    p, bits = prefix.split("/")
                    hexs = re.sub(r"[^0-9A-Fa-f]", "", p)
                    self.long.append((hexs.upper(), int(bits), name))
                elif re.fullmatch(r"[0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}", prefix):
                    self.table[prefix.replace("-", ":").upper()] = name

    def lookup(self, mac: str) -> str:
        mac = norm_mac(mac) if mac else ""
        if not mac:
            return ""
        hexs = mac.replace(":", "")
        for prefix, bits, name in self.long:
            if bits % 4 == 0 and hexs.startswith(prefix[: bits // 4]):
                return name
        name = self.table.get(mac[:8])
        if name:
            return name
        if self._manuf is not None:
            try:
                name = self._manuf.get_manuf_long(mac) or self._manuf.get_manuf(mac)
                if name:
                    return name
            except Exception:  # noqa: BLE001
                pass
        name = BUILTIN_OUI.get(mac[:8], "")
        if not name and int(mac[:2], 16) & 0x02:
            return "локальный/случайный MAC"
        return name


# --------------------------------------------------------------------------- тип устройства
def classify(dev: dict) -> tuple[str, list[str]]:
    """Тип устройства по открытым портам, баннерам и производителю. Возвращает (тип, причины)."""
    ports = set(dev.get("ports") or [])
    vendor = (dev.get("vendor") or "").lower()
    ssh = (dev.get("ssh_banner") or "").lower()
    http = (dev.get("http_server") or "").lower()
    why = []

    def r(kind, reason):
        why.append(reason)
        return kind, why

    if 902 in ports and (443 in ports or 80 in ports):
        return r("Гипервизор VMware ESXi", "порты 902 и 443")
    if 8006 in ports:
        return r("Гипервизор Proxmox VE", "порт 8006")
    if ports & {9100, 515, 631} and not ports & {3389, 445, 22}:
        return r("Принтер/МФУ", "порты печати " + ",".join(map(str, sorted(ports & {9100, 515, 631}))))
    if "cisco" in ssh or "cisco" in vendor:
        return r("Сетевое оборудование (Cisco)", "баннер/производитель Cisco")
    if "rosssh" in ssh or "mikrotik" in vendor or "mikrotik" in http:
        return r("Сетевое оборудование (MikroTik)", "баннер/производитель MikroTik")
    if 554 in ports:
        return r("IP-камера/видеорегистратор", "порт 554 (RTSP)")
    if "synology" in vendor or "qnap" in vendor:
        return r("Сетевое хранилище (NAS)", f"производитель {dev.get('vendor')}")
    if 3389 in ports or 5985 in ports or (135 in ports and 445 in ports):
        return r("Windows", "порты " + ",".join(map(str, sorted(ports & {135, 445, 3389, 5985}))))
    if "vmware" in vendor:
        return r("Виртуальная машина VMware", "MAC VMware")
    if "hyper-v" in vendor:
        return r("Виртуальная машина Hyper-V", "MAC Hyper-V")
    if vendor.startswith(("qemu", "xen", "oracle virtualbox", "parallels")):
        return r("Виртуальная машина", f"MAC {dev.get('vendor')}")
    if "dropbear" in ssh:
        return r("Встраиваемое устройство/роутер", "SSH dropbear")
    if 22 in ports and "openssh" in ssh:
        distro = next((d for d in ("Ubuntu", "Debian", "FreeBSD", "Raspbian") if d.lower() in ssh), "")
        return r(f"Linux/Unix{' (' + distro + ')' if distro else ''}", "OpenSSH")
    if 445 in ports or 139 in ports:
        return r("Windows/Samba", "порты SMB")
    if 53 in ports:
        return r("DNS-сервер/роутер", "порт 53")
    if ports & {80, 443, 8080, 8443}:
        return r("Устройство с веб-интерфейсом", "только веб-порты")
    if "raspberry" in vendor:
        return r("Raspberry Pi", "производитель")
    if 22 in ports:
        return r("Linux/Unix", "порт 22")
    return "Неизвестно", why


# --------------------------------------------------------------------------- сканер
class NetworkScanner:
    """Сканирование списка адресов в пуле потоков.

    ``progress(done, total, message)``, ``on_device(dev)`` и ``is_cancelled()`` вызываются из рабочих
    потоков. ``scan_timeout`` — общий лимит времени на задание (секунды, 0 = без лимита): по его истечении
    новые адреса не проверяются, результат помечается timed_out."""

    def __init__(self, ports: Iterable[int] = DEFAULT_PORTS, *, connect_timeout: float = 0.7, workers: int = 64,
                 use_ping: bool = True, resolve_names: bool = True, detect_types: bool = True,
                 scan_timeout: float = 0, oui: OuiDB | None = None):
        self.ports = tuple(sorted({int(p) for p in ports if 0 < int(p) < 65536}))
        self.connect_timeout = connect_timeout
        self.use_ping = use_ping
        self.resolve_names = resolve_names
        self.detect_types = detect_types
        self.scan_timeout = scan_timeout
        self.oui = oui or OuiDB()
        self.workers = max(1, min(workers, self._fd_budget()))

    def _fd_budget(self) -> int:
        """Каждый поток держит до len(ports) сокетов — не упираемся в лимит открытых файлов."""
        try:
            import resource
            soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except (ImportError, ValueError, OSError):
            return 256
        if soft == resource.RLIM_INFINITY:
            return 256
        return max(4, (soft - 128) // max(1, len(self.ports) + 2))

    def scan_host(self, ip: str) -> dict | None:
        alive_ping = self.use_ping and ping(ip, timeout=1.0)
        open_ports, refused = probe_ports(ip, self.ports, self.connect_timeout) if self.ports else ([], False)
        if not (alive_ping or open_ports or refused):
            return None
        dev = {"ip": ip, "mac": "", "vendor": "", "hostname": "", "type": "", "ports": open_ports,
               "alive_by": [x for x, ok in (("ping", alive_ping), ("tcp", bool(open_ports)), ("rst", refused)) if ok],
               "netbios": "", "workgroup": "", "ssh_banner": "", "http_server": "", "type_reasons": [],
               "source": "scan"}
        if self.resolve_names:
            dev["hostname"] = reverse_dns(ip)
            nb_name, nb_group, nb_mac = netbios_query(ip)
            dev["netbios"], dev["workgroup"] = nb_name, nb_group
            if nb_mac:
                dev["mac"] = nb_mac
            if not dev["hostname"] and nb_name:
                dev["hostname"] = nb_name
        if self.detect_types:
            if 22 in open_ports:
                dev["ssh_banner"] = ssh_banner(ip)
            for p in (80, 8080):
                if p in open_ports:
                    dev["http_server"] = http_server(ip, p)
                    if dev["http_server"]:
                        break
        return dev

    def _finish(self, dev: dict, arp: dict):
        if not dev["mac"]:
            dev["mac"] = arp.get(dev["ip"], "")
        dev["vendor"] = self.oui.lookup(dev["mac"]) if dev["mac"] else ""
        if self.detect_types:
            dev["type"], dev["type_reasons"] = classify(dev)

    def scan(self, addresses: list[str], progress: Callable | None = None, on_device: Callable | None = None,
             is_cancelled: Callable[[], bool] | None = None) -> dict:
        total = len(addresses)
        started = time.monotonic()
        deadline = started + self.scan_timeout if self.scan_timeout else None
        found, errors, done = [], [], 0
        timed_out = cancelled = False
        lock = threading.Lock()
        is_cancelled = is_cancelled or (lambda: False)
        log.info("Сканирование: %d адресов, %d портов, потоков %d, ping %s", total, len(self.ports), self.workers,
                 "да" if self.use_ping and shutil.which("ping") else "нет")
        if self.use_ping and not shutil.which("ping"):
            log.warning("Команда ping не найдена — живые узлы определяются только по TCP")
        it = iter(addresses)
        with cf.ThreadPoolExecutor(self.workers, thread_name_prefix="scan") as pool:
            pending = {}

            def fill():
                while len(pending) < self.workers * 2:
                    ip = next(it, None)
                    if ip is None:
                        return
                    pending[pool.submit(self.scan_host, ip)] = ip

            fill()
            while pending:
                if is_cancelled():
                    cancelled = True
                    break
                if deadline and time.monotonic() > deadline:
                    timed_out = True
                    break
                wait = 0.5 if deadline is None else max(0.05, min(0.5, deadline - time.monotonic()))
                ready, _ = cf.wait(pending, timeout=wait, return_when=cf.FIRST_COMPLETED)
                for fut in ready:
                    ip = pending.pop(fut)
                    try:
                        dev = fut.result()
                    except Exception as e:  # noqa: BLE001 — один узел не должен ронять задание
                        errors.append(f"{ip}: {e}")
                        log.warning("Ошибка при проверке %s: %s", ip, e)
                        dev = None
                    with lock:
                        done += 1
                    if dev:
                        self._finish(dev, {})
                        found.append(dev)
                        if on_device:
                            on_device(dev)
                        log.info("Найден %s%s, порты: %s", ip, f" ({dev['hostname']})" if dev["hostname"] else "",
                                 ",".join(map(str, dev["ports"])) or "—")
                    if progress:
                        progress(done, total, f"Проверено {done} из {total}, найдено {len(found)}")
                fill()
            if cancelled or timed_out:
                for fut in pending:
                    fut.cancel()
                # уже запущенные проверки короткие — дожидаемся, чтобы не терять найденное
                for fut, ip in list(pending.items()):
                    if fut.cancelled():
                        continue
                    try:
                        dev = fut.result(timeout=15)
                    except Exception:  # noqa: BLE001
                        dev = None
                    done += 1
                    if dev:
                        found.append(dev)
        # MAC из ARP-кэша появляется после наших же обращений к узлам
        arp = arp_table()
        for dev in found:
            self._finish(dev, arp)
        found.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
        elapsed = time.monotonic() - started
        if timed_out:
            log.warning("Превышен таймаут сканирования (%.0f с): проверено %d из %d адресов", self.scan_timeout,
                        done, total)
        elif cancelled:
            log.warning("Сканирование остановлено: проверено %d из %d адресов", done, total)
        log.info("Сканирование завершено за %.1f с: живых узлов %d", elapsed, len(found))
        return {"total": total, "checked": done, "alive": len(found), "devices": found, "errors": errors,
                "timed_out": timed_out, "cancelled": cancelled, "elapsed_s": round(elapsed, 1),
                "ports": list(self.ports), "oui_source": self.oui.source}
