"""Подключение к vCenter/ESXi через pyvmomi и сбор инвентаризации.

Для сбора хватает учётной записи с ролью Read-only. Пароль нигде не логируется и не сохраняется.
Адрес «mock» (или mock://…) включает встроенный тестовый vCenter — для демонстрации и тестов без VMware.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import threading
import time
from typing import Callable

log = logging.getLogger("inventory.vsphere")


class VSphereError(Exception):
    """Ошибка vSphere с понятным пользователю текстом."""


class AuthError(VSphereError):
    pass


class UnreachableError(VSphereError):
    pass


class VSphereTimeout(VSphereError):
    pass


def _split_host(address: str, default_port: int = 443) -> tuple[str, int]:
    """'vc.local', 'vc.local:8443', 'https://vc.local/sdk', '[fe80::1]:443' → (host, port)."""
    a = address.strip()
    for prefix in ("https://", "http://"):
        if a.lower().startswith(prefix):
            a = a[len(prefix):]
    a = a.split("/", 1)[0]
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif a.count(":") == 1:
        host, port = a.split(":")
    else:
        host, port = a, ""
    if not host:
        raise VSphereError("Не указан адрес vCenter")
    try:
        return host, int(port) if port else default_port
    except ValueError:
        raise VSphereError(f"Неверный порт в адресе: {address}") from None


def _gb(n) -> float | None:
    return round(n / 1024 ** 3, 1) if isinstance(n, (int, float)) else None


def _is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


class VSphereClient:
    def __init__(self, address: str, user: str, password: str, *, verify_ssl: bool = False, timeout: float = 15):
        self.host, self.port = _split_host(address)
        self.user = user
        self._password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.si = None
        self.about: dict = {}

    def __repr__(self):
        return f"<VSphereClient {self.user}@{self.host}:{self.port}>"     # без пароля

    @property
    def connected(self) -> bool:
        return self.si is not None

    # ------------------------------------------------------------------ подключение
    def connect(self) -> dict:
        try:
            from pyVim.connect import SmartConnect
            from pyVmomi import vim
        except ImportError:
            raise VSphereError("Не установлен pyvmomi: pip install pyvmomi") from None
        if not self.user:
            raise AuthError("Не указан логин")
        log.info("Подключение к vCenter %s:%d как %s", self.host, self.port, self.user)
        # быстрая проверка доступности — понятная ошибка вместо длинного SSL/HTTP-трейса
        try:
            socket.create_connection((self.host, self.port), timeout=min(self.timeout, 10)).close()
        except socket.gaierror:
            raise UnreachableError(f"Имя {self.host} не найдено в DNS") from None
        except (socket.timeout, TimeoutError):
            raise VSphereTimeout(f"vCenter {self.host}:{self.port} не отвечает (таймаут)") from None
        except OSError as e:
            raise UnreachableError(f"vCenter {self.host}:{self.port} недоступен: {e.strerror or e}") from None
        kwargs = dict(host=self.host, port=self.port, user=self.user, pwd=self._password,
                      httpConnectionTimeout=self.timeout, connectionPoolTimeout=-1)
        if self.verify_ssl:
            kwargs["sslContext"] = ssl.create_default_context()
        else:
            kwargs["disableSslCertValidation"] = True
        try:
            self.si = self._smart_connect(SmartConnect, kwargs)
        except vim.fault.InvalidLogin:
            raise AuthError("Неверный логин или пароль") from None
        except vim.fault.NoPermission:
            raise AuthError("У учётной записи нет прав на вход в vCenter") from None
        except ssl.SSLCertVerificationError as e:
            raise VSphereError(f"Сертификат vCenter не прошёл проверку: {e.verify_message}. "
                               "Отключите «Проверять сертификат» или добавьте CA в систему") from None
        except (socket.timeout, TimeoutError):
            raise VSphereTimeout(f"vCenter {self.host} не ответил за {self.timeout:.0f} с") from None
        except vim.fault.VimFault as e:
            raise VSphereError(f"vCenter отклонил вход: {getattr(e, 'msg', '') or type(e).__name__}") from None
        except (OSError, ssl.SSLError) as e:
            raise UnreachableError(f"Ошибка соединения с {self.host}: {e}") from None
        except Exception as e:  # noqa: BLE001 — pyvmomi бросает и свои, и http.client-исключения
            raise VSphereError(f"Не удалось подключиться к {self.host}: {type(e).__name__}: {e}") from None
        a = self.si.content.about
        self.about = {"name": a.fullName, "version": a.version, "build": a.build, "api_type": a.apiType,
                      "instance_uuid": getattr(a, "instanceUuid", None)}
        log.info("Подключено: %s", a.fullName)
        return self.about

    def _smart_connect(self, smart_connect, kwargs):
        """SmartConnect с жёстким сроком. pyvmomi при определении версии API открывает HTTPS без таймаута,
        и «зависший» vCenter (TCP принят, ответа нет) держал бы задание вечно. Поэтому — отдельный поток."""
        box, lock = {}, threading.Lock()

        def work():
            try:
                si = smart_connect(**kwargs)
            except BaseException as e:  # noqa: B902 — передаём в вызывающий поток
                box["exc"] = e
                return
            with lock:
                if box.get("abandoned"):             # ответ пришёл после таймаута — закрываем сессию
                    try:
                        from pyVim.connect import Disconnect
                        Disconnect(si)
                    except Exception:  # noqa: BLE001
                        pass
                else:
                    box["si"] = si

        t = threading.Thread(target=work, name="vcenter-connect", daemon=True)
        t.start()
        t.join(self.timeout * 2 + 5)
        with lock:
            if t.is_alive():
                box["abandoned"] = True
                raise TimeoutError
        if "exc" in box:
            raise box["exc"]
        return box["si"]

    def disconnect(self):
        if self.si is not None:
            try:
                from pyVim.connect import Disconnect
                Disconnect(self.si)
            except Exception:  # noqa: BLE001 — сессия могла истечь
                pass
            self.si = None
            log.info("Отключено от %s", self.host)

    # ------------------------------------------------------------------ сбор
    def _retrieve(self, obj_type, props: list[str]) -> list[dict]:
        """Все объекты типа с нужными свойствами одним PropertyCollector-запросом (с постраничной догрузкой)."""
        from pyVmomi import vim, vmodl
        content = self.si.content
        view = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)
        pc = vmodl.query.PropertyCollector
        try:
            spec = pc.FilterSpec(
                objectSet=[pc.ObjectSpec(obj=view, skip=True, selectSet=[
                    pc.TraversalSpec(name="view", path="view", skip=False, type=vim.view.ContainerView)])],
                propSet=[pc.PropertySpec(type=obj_type, pathSet=props, all=False)])
            collector = content.propertyCollector
            res = collector.RetrievePropertiesEx([spec], pc.RetrieveOptions(maxObjects=500))
            out = []
            while res:
                for o in res.objects:
                    d = {p.name: p.val for p in (o.propSet or [])}
                    d["_moid"] = o.obj._moId
                    out.append(d)
                if not res.token:
                    break
                res = collector.ContinueRetrievePropertiesEx(res.token)
            return out
        finally:
            view.Destroy()

    def collect(self, progress: Callable | None = None, is_cancelled: Callable[[], bool] | None = None) -> dict:
        if not self.connected:
            self.connect()
        from pyVmomi import vim
        is_cancelled = is_cancelled or (lambda: False)
        progress = progress or (lambda *a: None)
        started = time.monotonic()
        try:
            steps = [("датацентры", vim.Datacenter, ["name"]),
                     ("кластеры", vim.ClusterComputeResource, ["name", "summary.numHosts", "summary.numEffectiveHosts"]),
                     ("ESXi-хосты", vim.HostSystem, [
                         "name", "parent", "runtime.connectionState", "runtime.powerState", "runtime.inMaintenanceMode",
                         "summary.hardware.vendor", "summary.hardware.model", "summary.hardware.cpuModel",
                         "summary.hardware.numCpuCores", "summary.hardware.memorySize", "summary.config.product.fullName",
                         "config.network.vnic"]),
                     ("виртуальные машины", vim.VirtualMachine, [
                         "name", "runtime.powerState", "runtime.host", "config.template", "config.guestFullName",
                         "config.hardware.numCPU", "config.hardware.memoryMB", "config.hardware.device",
                         "config.instanceUuid", "guest.guestFullName", "guest.hostName", "guest.ipAddress", "guest.net",
                         "guest.toolsRunningStatus", "summary.storage.committed"]),
                     ("хранилища", vim.Datastore, ["name", "summary.type", "summary.capacity", "summary.freeSpace"]),
                     ("сети", vim.Network, ["name"])]
            raw = {}
            for i, (title, vimtype, props) in enumerate(steps):
                if is_cancelled():
                    raise VSphereError("Остановлено пользователем")
                progress(i / len(steps), f"vSphere: {title}")
                raw[title] = self._retrieve(vimtype, props)
                log.info("vSphere: %s — %d", title, len(raw[title]))
        except VSphereError:
            raise
        except (socket.timeout, TimeoutError):
            raise VSphereTimeout("vCenter перестал отвечать во время сбора данных") from None
        except vim.fault.NotAuthenticated:
            self.si = None
            raise AuthError("Сессия vCenter истекла — подключитесь заново") from None
        except Exception as e:  # noqa: BLE001
            raise VSphereError(f"Ошибка сбора данных vSphere: {type(e).__name__}: {e}") from None
        progress(1.0, "vSphere: готово")
        inv = self._shape(raw)
        inv["about"] = self.about
        inv["elapsed_s"] = round(time.monotonic() - started, 1)
        return inv

    @staticmethod
    def _shape(raw: dict) -> dict:
        from pyVmomi import vim
        clusters = {c["_moid"]: c.get("name") for c in raw["кластеры"]}
        hosts, host_names = [], {}
        for h in raw["ESXi-хосты"]:
            host_names[h["_moid"]] = h.get("name")
            parent = h.get("parent")
            vnics = []
            for v in h.get("config.network.vnic") or []:
                spec = v.spec
                ip = getattr(spec.ip, "ipAddress", "") or ""
                vnics.append({"device": v.device, "ip": "" if ip in ("0.0.0.0", "::") else ip,
                              "mac": (spec.mac or "").upper(), "portgroup": v.portgroup or ""})
            hosts.append({
                "name": h.get("name"), "cluster": clusters.get(parent._moId) if parent is not None else None,
                "connection_state": h.get("runtime.connectionState"), "power_state": h.get("runtime.powerState"),
                "maintenance": h.get("runtime.inMaintenanceMode"), "vendor": h.get("summary.hardware.vendor"),
                "model": h.get("summary.hardware.model"), "cpu_model": h.get("summary.hardware.cpuModel"),
                "cpu_cores": h.get("summary.hardware.numCpuCores"), "memory_gb": _gb(h.get("summary.hardware.memorySize")),
                "version": h.get("summary.config.product.fullName"), "vmkernel": vnics})
        vms = []
        for v in raw["виртуальные машины"]:
            nics = []
            for n in v.get("guest.net") or []:
                nics.append({"mac": (n.macAddress or "").upper(), "network": n.network or "", "connected": n.connected,
                             "ips": [ip for ip in (n.ipAddress or []) if ip]})
            known = {n["mac"] for n in nics}
            for d in v.get("config.hardware.device") or []:            # MAC без VMware Tools
                if isinstance(d, vim.vm.device.VirtualEthernetCard) and d.macAddress and d.macAddress.upper() not in known:
                    nics.append({"mac": d.macAddress.upper(), "network": getattr(d.deviceInfo, "summary", "") or "",
                                 "connected": bool(d.connectable and d.connectable.connected), "ips": []})
            host = v.get("runtime.host")
            vms.append({
                "name": v.get("name"), "power_state": v.get("runtime.powerState"),
                "template": bool(v.get("config.template")),
                "guest_os": v.get("guest.guestFullName") or v.get("config.guestFullName"),
                "hostname": v.get("guest.hostName") or "", "ip": v.get("guest.ipAddress") or "",
                "nics": nics, "cpu": v.get("config.hardware.numCPU"), "memory_mb": v.get("config.hardware.memoryMB"),
                "disk_gb": _gb(v.get("summary.storage.committed")),
                "host": host_names.get(host._moId) if host is not None else None,
                "tools": v.get("guest.toolsRunningStatus"), "uuid": v.get("config.instanceUuid")})
        datastores = [{"name": d.get("name"), "type": d.get("summary.type"), "capacity_gb": _gb(d.get("summary.capacity")),
                       "free_gb": _gb(d.get("summary.freeSpace"))} for d in raw["хранилища"]]
        return {"datacenters": sorted(d.get("name") for d in raw["датацентры"]),
                "clusters": [{"name": c.get("name"), "hosts": c.get("summary.numHosts")} for c in raw["кластеры"]],
                "hosts": sorted(hosts, key=lambda h: h["name"] or ""), "vms": sorted(vms, key=lambda v: v["name"] or ""),
                "datastores": datastores, "networks": sorted({n.get("name") for n in raw["сети"] if n.get("name")})}


# --------------------------------------------------------------------------- устройства из инвентаризации
def devices_from_inventory(inv: dict) -> list[dict]:
    """Строки таблицы устройств из данных vSphere: по одной на каждый IPv4 (или одна без IP)."""
    out = []
    for h in inv.get("hosts", []):
        nics = [n for n in h.get("vmkernel", []) if n.get("ip")]
        for n in nics or [{"ip": "", "mac": ""}]:
            out.append({"ip": n["ip"], "mac": n.get("mac", ""), "vendor": h.get("vendor") or "",
                        "hostname": h.get("name") or "", "type": "Гипервизор VMware ESXi (vSphere)",
                        "os": h.get("version") or "", "source": "vsphere", "vsphere_name": h.get("name"),
                        "power_state": h.get("power_state") or "", "ports": []})
    for v in inv.get("vms", []):
        if v.get("template"):
            continue
        rows = []
        for n in v.get("nics", []):
            ips = [ip for ip in n.get("ips", []) if _is_ipv4(ip)]
            for ip in ips:
                rows.append((ip, n.get("mac", "")))
            if not ips:
                rows.append(("", n.get("mac", "")))
        if v.get("ip") and v["ip"] not in {r[0] for r in rows} and _is_ipv4(v["ip"]):
            rows = [r for r in rows if r[0]] + [(v["ip"], "")]
        if any(r[0] for r in rows):
            rows = [r for r in rows if r[0]]          # MAC без адреса не дублируем, если адреса есть
        for ip, mac in rows or [("", "")]:
            out.append({"ip": ip, "mac": mac, "vendor": "VMware" if mac else "",
                        "hostname": v.get("hostname") or v.get("name") or "", "type": "Виртуальная машина (vSphere)",
                        "os": v.get("guest_os") or "", "source": "vsphere", "vsphere_name": v.get("name"),
                        "power_state": v.get("power_state") or "", "ports": []})
    return out


# --------------------------------------------------------------------------- тестовый vCenter
class MockVSphereClient(VSphereClient):
    """Имитация vCenter для демонстрации и тестов. Особые случаи:
    пароль «wrong» — неверный пароль; адрес «mock-timeout» — таймаут; «mock-down» — недоступен."""

    def __init__(self, address: str, user: str, password: str, *, delay: float = 0.3, **_):
        self.host, self.port = address.replace("mock://", "") or "mock", 443
        self.user, self._password, self.delay = user, password, delay
        self.timeout, self.verify_ssl, self.si, self.about = 1, False, None, {}

    def connect(self) -> dict:
        log.info("Подключение к тестовому vCenter %s как %s", self.host, self.user)
        time.sleep(self.delay)
        if self.host == "mock-timeout":
            raise VSphereTimeout(f"vCenter {self.host}:443 не отвечает (таймаут)")
        if self.host == "mock-down":
            raise UnreachableError(f"vCenter {self.host}:443 недоступен: Connection refused")
        if not self.user:
            raise AuthError("Не указан логин")
        if self._password == "wrong":
            raise AuthError("Неверный логин или пароль")
        self.si = object()
        self.about = {"name": "VMware vCenter Server 8.0.3 build-24022515 (тестовый)", "version": "8.0.3",
                      "build": "24022515", "api_type": "VirtualCenter", "instance_uuid": "mock-0000"}
        log.info("Подключено: %s", self.about["name"])
        return self.about

    def disconnect(self):
        self.si = None

    def collect(self, progress=None, is_cancelled=None) -> dict:
        if not self.connected:
            self.connect()
        progress = progress or (lambda *a: None)
        for i in range(5):
            if is_cancelled and is_cancelled():
                raise VSphereError("Остановлено пользователем")
            progress(i / 5, "vSphere (тест): сбор")
            time.sleep(self.delay / 5)
        progress(1.0, "vSphere: готово")
        hosts = [{"name": f"esxi-0{i}.lab.local", "cluster": "Cluster-A", "connection_state": "connected",
                  "power_state": "poweredOn", "maintenance": False, "vendor": "Dell Inc.", "model": "PowerEdge R650",
                  "cpu_model": "Intel(R) Xeon(R) Gold 6338", "cpu_cores": 32, "memory_gb": 511.6,
                  "version": "VMware ESXi 8.0.3 build-24022510",
                  "vmkernel": [{"device": "vmk0", "ip": f"127.0.0.{i}", "mac": f"00:50:56:6A:00:0{i}",
                                "portgroup": "Management Network"}]} for i in (1, 2)]
        vms = [
            {"name": "dc01", "power_state": "poweredOn", "template": False,
             "guest_os": "Microsoft Windows Server 2022 (64-bit)", "hostname": "dc01.lab.local", "ip": "127.0.0.3",
             "nics": [{"mac": "00:50:56:AA:00:03", "network": "VM Network", "connected": True, "ips": ["127.0.0.3"]}],
             "cpu": 4, "memory_mb": 8192, "disk_gb": 80.0, "host": "esxi-01.lab.local", "tools": "guestToolsRunning",
             "uuid": "5003a1b2-0000-0000-0000-000000000003"},
            {"name": "web01", "power_state": "poweredOn", "template": False, "guest_os": "Ubuntu Linux (64-bit)",
             "hostname": "web01", "ip": "10.99.0.20",
             "nics": [{"mac": "00:50:56:AA:00:20", "network": "DMZ", "connected": True, "ips": ["10.99.0.20", "fe80::1"]}],
             "cpu": 2, "memory_mb": 4096, "disk_gb": 40.0, "host": "esxi-02.lab.local", "tools": "guestToolsRunning",
             "uuid": "5003a1b2-0000-0000-0000-000000000020"},
            {"name": "old-app", "power_state": "poweredOff", "template": False, "guest_os": "CentOS 7 (64-bit)",
             "hostname": "", "ip": "", "nics": [{"mac": "00:50:56:AA:00:99", "network": "VM Network",
                                                  "connected": False, "ips": []}],
             "cpu": 2, "memory_mb": 2048, "disk_gb": 20.0, "host": "esxi-02.lab.local", "tools": "guestToolsNotRunning",
             "uuid": "5003a1b2-0000-0000-0000-000000000099"},
            {"name": "tpl-ubuntu", "power_state": "poweredOff", "template": True, "guest_os": "Ubuntu Linux (64-bit)",
             "hostname": "", "ip": "", "nics": [], "cpu": 2, "memory_mb": 2048, "disk_gb": 10.0,
             "host": "esxi-01.lab.local", "tools": "guestToolsNotRunning", "uuid": "tpl"},
        ]
        return {"about": self.about, "datacenters": ["DC-Lab"], "clusters": [{"name": "Cluster-A", "hosts": 2}],
                "hosts": hosts, "vms": vms,
                "datastores": [{"name": "datastore1", "type": "VMFS", "capacity_gb": 1862.5, "free_gb": 904.2}],
                "networks": ["DMZ", "Management Network", "VM Network"], "elapsed_s": self.delay}


def make_client(address: str, user: str, password: str, **kw) -> VSphereClient:
    if address.strip().lower().startswith("mock"):
        return MockVSphereClient(address.strip().lower(), user, password, **kw)
    return VSphereClient(address, user, password, **kw)
