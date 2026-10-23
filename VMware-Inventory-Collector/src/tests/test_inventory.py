"""Тесты без реальной инфраструктуры: python -m unittest discover -s tests -v

* тестовый vCenter (mock) и ошибки подключения pyvmomi на локальных «плохих» серверах;
* тестовая подсеть на 127.0.0.x с имитацией устройств (SSH, принтер, Windows, ESXi, NetBIOS).
  Имитации на стандартных портах (22, 445, 9100…) нужен свободный порт: на Linux под root
  запускайте tests/run_tests.sh — он выполняет тесты в отдельном сетевом пространстве имён;
* экспорт JSON/CSV/Markdown;
* (необязательно) настоящий pyvmomi против vcsim: VCSIM_URL=127.0.0.1:8989 VCSIM_USER=user VCSIM_PASSWORD=pass.
"""
import csv
import json
import os
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import exporter  # noqa: E402
import network_scanner as ns  # noqa: E402
from inventory import JobConfig, merge_devices, run_job  # noqa: E402
from vsphere_client import (AuthError, UnreachableError, VSphereClient, VSphereTimeout,  # noqa: E402
                            devices_from_inventory, make_client)


# --------------------------------------------------------------------------- имитация устройств
class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def tcp_service(ip, port, greeting=b"", http_server=None):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                if greeting:
                    self.request.sendall(greeting)
                if http_server:
                    self.request.settimeout(2)
                    self.request.recv(1024)
                    self.request.sendall(f"HTTP/1.0 200 OK\r\nServer: {http_server}\r\n\r\n".encode())
                else:
                    time.sleep(0.2)
            except OSError:
                pass
    srv = _TCP((ip, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def nbstat_reply(name, group, mac: bytes) -> bytes:
    names = [(name, 0x00, 0x0400), (group, 0x00, 0x8400), (name, 0x20, 0x0400)]
    body = bytes([len(names)])
    for n, suffix, flags in names:
        body += n.encode().ljust(15, b" ") + bytes([suffix]) + struct.pack(">H", flags)
    body += mac + b"\x00" * 40
    return (b"\x13\x37\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
            + b"\x00\x21\x00\x01" + b"\x00\x00\x00\x00" + struct.pack(">H", len(body)) + body)


def udp_nbstat(ip, reply):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            if data[2:4] == b"\x00\x00":
                sock.sendto(reply, self.client_address)
    srv = socketserver.ThreadingUDPServer((ip, 137), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def can_bind(ip, port):
    try:
        with socket.socket() as s:
            s.bind((ip, port))
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------- разбор целей
class TestTargets(unittest.TestCase):
    def test_formats(self):
        addrs, labels = ns.parse_targets("192.168.1.0/30\n10.0.0.5-7, 10.0.0.9;10.0.0.5  # комментарий\n")
        self.assertEqual(addrs, ["192.168.1.1", "192.168.1.2", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.9"])
        self.assertEqual(labels[0], "192.168.1.0/30")

    def test_full_range_and_single(self):
        addrs, _ = ns.parse_targets("10.1.1.250-10.1.2.1 172.16.0.1/32")
        self.assertEqual(addrs, ["10.1.1.250", "10.1.1.251", "10.1.1.252", "10.1.1.253", "10.1.1.254", "10.1.1.255",
                                 "10.1.2.0", "10.1.2.1", "172.16.0.1"])

    def test_errors(self):
        for bad in ("", "   ", "10.0.0.300", "abc", "10.0.0.9-3", "10.0.0.0/8"):
            with self.subTest(bad=bad), self.assertRaises(ns.ScanError):
                ns.parse_targets(bad)


# --------------------------------------------------------------------------- MAC, OUI, NetBIOS, типы
class TestIdentify(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(ns.norm_mac("00-50-56-ab-cd-ef"), "00:50:56:AB:CD:EF")
        self.assertEqual(ns.norm_mac("0:50:56:a:b:c"), "00:50:56:0A:0B:0C")
        self.assertEqual(ns.norm_mac("0050.56ab.cdef"), "00:50:56:AB:CD:EF")
        self.assertEqual(ns.norm_mac("00:00:00:00:00:00"), "")
        self.assertEqual(ns.norm_mac("ff:ff:ff:ff:ff:ff"), "")
        self.assertEqual(ns.norm_mac("garbage"), "")

    def test_oui_builtin_and_files(self):
        db = ns.OuiDB(path=os.devnull)
        self.assertEqual(db.lookup("00:50:56:01:02:03"), "VMware")
        self.assertEqual(db.lookup("02:11:22:33:44:55"), "локальный/случайный MAC")
        with tempfile.TemporaryDirectory() as d:
            manuf = Path(d, "manuf")
            manuf.write_text("# Wireshark\n00:00:0C\tCisco\tCisco Systems, Inc\n"
                             "70:B3:D5:00:00/36\tExample\tExample MA-S Vendor\n", encoding="utf-8")
            db = ns.OuiDB(manuf)
            self.assertEqual(db.lookup("00:00:0c:11:22:33"), "Cisco Systems, Inc")
            self.assertEqual(db.lookup("70:B3:D5:00:00:42"), "Example MA-S Vendor")
            oui = Path(d, "oui.txt")
            oui.write_text("00-1B-21   (hex)\t\tIntel Corporate\n001B21     (base 16)\t\tIntel Corporate\n")
            self.assertEqual(ns.OuiDB(oui).lookup("00:1b:21:aa:bb:cc"), "Intel Corporate")

    def test_nbstat_parse(self):
        name, group, mac = ns.parse_nbstat(nbstat_reply("FILESRV01", "CORP", bytes.fromhex("00155D010203")))
        self.assertEqual((name, group, mac), ("FILESRV01", "CORP", "00:15:5D:01:02:03"))
        self.assertEqual(ns.parse_nbstat(b"\x00" * 20), ("", "", ""))
        self.assertEqual(ns.parse_nbstat(nbstat_reply("X", "Y", bytes.fromhex("00505601AB02"))[:80]), ("X", "", ""))

    def test_classify(self):
        cases = [
            ({"ports": [443, 902]}, "Гипервизор VMware ESXi"),
            ({"ports": [9100, 80]}, "Принтер/МФУ"),
            ({"ports": [135, 445, 3389]}, "Windows"),
            ({"ports": [22], "ssh_banner": "SSH-2.0-Cisco-1.25"}, "Сетевое оборудование (Cisco)"),
            ({"ports": [22], "ssh_banner": "SSH-2.0-ROSSSH"}, "Сетевое оборудование (MikroTik)"),
            ({"ports": [22], "ssh_banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}, "Linux/Unix (Ubuntu)"),
            ({"ports": [], "vendor": "VMware"}, "Виртуальная машина VMware"),
            ({"ports": [554, 80]}, "IP-камера/видеорегистратор"),
            ({"ports": [80, 443]}, "Устройство с веб-интерфейсом"),
            ({"ports": []}, "Неизвестно"),
        ]
        for dev, expected in cases:
            with self.subTest(dev=dev):
                self.assertEqual(ns.classify(dev)[0], expected)


# --------------------------------------------------------------------------- порты и тестовая подсеть
class TestScanner(unittest.TestCase):
    def test_probe_open_and_refused(self):
        srv = tcp_service("127.0.0.1", 0)
        port = srv.server_address[1]
        with socket.socket() as s:            # гарантированно закрытый порт
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        try:
            open_ports, refused = ns.probe_ports("127.0.0.1", [port, closed], 1.0)
            self.assertEqual(open_ports, [port])
            self.assertTrue(refused)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_banners(self):
        ssh = tcp_service("127.0.0.1", 0, greeting=b"SSH-2.0-OpenSSH_9.6p1 Debian\r\n")
        web = tcp_service("127.0.0.1", 0, http_server="Microsoft-IIS/10.0")
        try:
            self.assertEqual(ns.ssh_banner("127.0.0.1", ssh.server_address[1]), "SSH-2.0-OpenSSH_9.6p1 Debian")
            self.assertEqual(ns.http_server("127.0.0.1", web.server_address[1]), "Microsoft-IIS/10.0")
        finally:
            for s in (ssh, web):
                s.shutdown()
                s.server_close()

    def test_scan_timeout_and_cancel(self):
        addrs, _ = ns.parse_targets("127.0.1.0/24")
        sc = ns.NetworkScanner([1], use_ping=False, resolve_names=False, workers=2, scan_timeout=0.3)
        sc.scan_host = lambda ip: (time.sleep(0.1), None)[1]
        res = sc.scan(addrs)
        self.assertTrue(res["timed_out"])
        self.assertLess(res["checked"], res["total"])
        stop = threading.Event()
        threading.Timer(0.2, stop.set).start()
        sc = ns.NetworkScanner([1], use_ping=False, resolve_names=False, workers=2)
        sc.scan_host = lambda ip: (time.sleep(0.1), None)[1]
        res = sc.scan(addrs, is_cancelled=stop.is_set)
        self.assertTrue(res["cancelled"])
        self.assertLess(res["checked"], res["total"])


@unittest.skipUnless(all(can_bind(f"127.0.0.{i}", p) for i, p in ((11, 22), (12, 445), (13, 9100), (14, 902)))
                     and sys.platform.startswith("linux"),
                     "нужны свободные стандартные порты на 127.0.0.x — запустите tests/run_tests.sh")
class TestTestSubnet(unittest.TestCase):
    """Тестовая подсеть 127.0.0.8/29: Linux-сервер, Windows с NetBIOS, принтер, ESXi."""

    @classmethod
    def setUpClass(cls):
        cls.servers = [
            tcp_service("127.0.0.11", 22, greeting=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"),
            tcp_service("127.0.0.12", 445), tcp_service("127.0.0.12", 135), tcp_service("127.0.0.12", 3389),
            udp_nbstat("127.0.0.12", nbstat_reply("WIN-SRV01", "CORP", bytes.fromhex("00505601AB02"))),
            tcp_service("127.0.0.13", 9100), tcp_service("127.0.0.13", 80, http_server="HP HTTP Server"),
            tcp_service("127.0.0.14", 902), tcp_service("127.0.0.14", 443),
        ]

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def test_subnet(self):
        cfg = JobConfig(subnets="127.0.0.11-14", scan_vsphere=False, use_ping=False, connect_timeout=0.5)
        res = run_job(cfg)
        by_ip = {d["ip"]: d for d in res["devices"]}
        self.assertEqual(sorted(by_ip), ["127.0.0.11", "127.0.0.12", "127.0.0.13", "127.0.0.14"])
        self.assertEqual(by_ip["127.0.0.11"]["type"], "Linux/Unix (Ubuntu)")
        win = by_ip["127.0.0.12"]
        self.assertEqual(win["type"], "Windows")
        self.assertEqual(win["netbios"], "WIN-SRV01")
        self.assertEqual(win["workgroup"], "CORP")
        self.assertEqual(win["mac"], "00:50:56:01:AB:02")
        self.assertEqual(win["vendor"], "VMware")
        self.assertEqual(by_ip["127.0.0.13"]["type"], "Принтер/МФУ")
        self.assertEqual(by_ip["127.0.0.13"]["http_server"], "HP HTTP Server")
        self.assertEqual(by_ip["127.0.0.14"]["type"], "Гипервизор VMware ESXi")
        self.assertEqual(res["errors"], [])

    def test_no_type_detection(self):
        res = run_job(JobConfig(subnets="127.0.0.11-14", scan_vsphere=False, use_ping=False, detect_types=False))
        self.assertTrue(res["devices"])
        self.assertTrue(all(d["type"] == "" and d["ssh_banner"] == "" for d in res["devices"]))


# --------------------------------------------------------------------------- vCenter
class TestVSphere(unittest.TestCase):
    def test_mock(self):
        c = make_client("mock", "admin", "secret", delay=0)
        self.assertIn("vCenter", c.connect()["name"])
        inv = c.collect()
        self.assertEqual(len(inv["hosts"]), 2)
        devs = devices_from_inventory(inv)
        self.assertNotIn("tpl-ubuntu", [d["vsphere_name"] for d in devs])        # шаблоны не устройства
        self.assertIn("fe80::1", json.dumps(inv))
        self.assertNotIn("fe80::1", [d["ip"] for d in devs])                       # в таблице только IPv4

    def test_mock_errors(self):
        with self.assertRaises(AuthError):
            make_client("mock", "admin", "wrong", delay=0).connect()
        with self.assertRaises(VSphereTimeout):
            make_client("mock-timeout", "admin", "x", delay=0).connect()
        with self.assertRaises(UnreachableError):
            make_client("mock-down", "admin", "x", delay=0).connect()

    def test_repr_hides_password(self):
        c = VSphereClient("vc.local:8443", "admin", "S3cret!")
        self.assertEqual((c.host, c.port), ("vc.local", 8443))
        self.assertNotIn("S3cret", repr(c))
        self.assertNotIn("S3cret", repr(JobConfig(password="S3cret!")))
        self.assertNotIn("password", JobConfig(password="S3cret!").public())

    def test_real_client_unreachable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        with self.assertRaises(UnreachableError):
            VSphereClient(f"127.0.0.1:{port}", "u", "p", timeout=2).connect()
        with self.assertRaises(UnreachableError):
            VSphereClient("no-such-host.invalid", "u", "p", timeout=2).connect()

    def test_real_client_timeout(self):
        """Сервер принимает TCP, но молчит (завис vCenter) — должен быть таймаут, а не вечное ожидание."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        try:
            t0 = time.monotonic()
            with self.assertRaises(VSphereTimeout):
                VSphereClient(f"127.0.0.1:{srv.getsockname()[1]}", "u", "p", timeout=2).connect()
            self.assertLess(time.monotonic() - t0, 15)
        finally:
            srv.close()


@unittest.skipUnless(os.environ.get("VCSIM_URL"), "VCSIM_URL не задан (vcsim не запущен)")
class TestVcsim(unittest.TestCase):
    """Настоящий pyvmomi против симулятора vCenter (govmomi vcsim)."""

    def setUp(self):
        self.url = os.environ["VCSIM_URL"]
        self.user = os.environ.get("VCSIM_USER", "user")
        self.password = os.environ.get("VCSIM_PASSWORD", "pass")

    def test_collect(self):
        c = VSphereClient(self.url, self.user, self.password, timeout=10)
        about = c.connect()
        self.assertEqual(about["api_type"], "VirtualCenter")
        inv = c.collect()
        c.disconnect()
        self.assertGreater(len(inv["hosts"]), 0)
        self.assertGreater(len(inv["vms"]), 0)
        self.assertTrue(all(v["name"] and v["host"] for v in inv["vms"]))
        self.assertTrue(inv["datastores"] and inv["datacenters"])
        self.assertTrue(devices_from_inventory(inv))

    def test_wrong_password(self):
        with self.assertRaises(AuthError):
            VSphereClient(self.url, self.user, "definitely-wrong", timeout=10).connect()

    def test_job_with_vcsim(self):
        res = run_job(JobConfig(vcenter=self.url, user=self.user, password=self.password, scan_subnets=False))
        self.assertEqual(res["errors"], [])
        self.assertTrue(res["devices"])


# --------------------------------------------------------------------------- задание и экспорт
class TestJobAndExport(unittest.TestCase):
    def test_validate(self):
        self.assertTrue(JobConfig(scan_vsphere=False, scan_subnets=False).validate())
        self.assertTrue(JobConfig(scan_vsphere=True, vcenter="", scan_subnets=False).validate())
        self.assertTrue(JobConfig(scan_vsphere=False, subnets="bad").validate())
        self.assertEqual(JobConfig(scan_vsphere=False, subnets="10.0.0.0/30").validate(), [])

    def test_vsphere_error_does_not_stop_scan(self):
        res = run_job(JobConfig(vcenter="mock", user="a", password="wrong", subnets="127.0.0.1",
                                use_ping=False, ports=(1,)))
        self.assertTrue(any("Неверный логин" in e for e in res["errors"]))
        self.assertEqual([d["ip"] for d in res["devices"]], ["127.0.0.1"])     # RST от закрытого порта = узел жив

    def test_merge(self):
        vs = [{"ip": "10.0.0.5", "mac": "00:50:56:00:00:05", "vendor": "VMware", "hostname": "app01",
               "type": "Виртуальная машина (vSphere)", "os": "Ubuntu", "source": "vsphere", "vsphere_name": "app01"},
              {"ip": "", "mac": "00:50:56:00:00:09", "hostname": "off", "type": "Виртуальная машина (vSphere)",
               "source": "vsphere"}]
        sc = [{"ip": "10.0.0.5", "mac": "", "vendor": "", "hostname": "", "type": "Linux/Unix", "ports": [22],
               "source": "scan"},
              {"ip": "10.0.0.1", "mac": "AA:00:00:00:00:01", "hostname": "gw", "type": "DNS-сервер/роутер",
               "ports": [53], "source": "scan"}]
        m = merge_devices(vs, sc)
        self.assertEqual([d["ip"] for d in m], ["10.0.0.1", "10.0.0.5", ""])
        app = m[1]
        self.assertEqual((app["source"], app["hostname"], app["mac"], app["ports"], app["scan_type"]),
                         ("vsphere+scan", "app01", "00:50:56:00:00:05", [22], "Linux/Unix"))

    def test_export_all_formats(self):
        result = run_job(JobConfig(vcenter="mock", user="admin", password="x", scan_subnets=False))
        result["devices"].append({"ip": "10.0.0.66", "mac": "", "vendor": "", "hostname": "=cmd|' /C calc'!A0",
                                  "type": "x|y", "os": "", "ports": [80, 443], "source": "scan"})
        with tempfile.TemporaryDirectory() as d:
            paths = exporter.export(result, Path(d) / "new" / "dir", stamp="t")
            self.assertEqual([p.name for p in paths], ["inventory_t.json", "inventory_t.csv", "inventory_t.md"])
            data = json.loads(paths[0].read_text(encoding="utf-8"))
            self.assertEqual(len(data["devices"]), len(result["devices"]))
            self.assertEqual(data["vsphere"]["about"]["version"], "8.0.3")
            self.assertNotIn('"password"', paths[0].read_text(encoding="utf-8"))
            raw = paths[1].read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))                          # BOM для Excel
            rows = list(csv.reader(raw.decode("utf-8-sig").splitlines(), delimiter=";"))
            self.assertEqual(rows[0][:5], ["IP", "MAC", "Производитель", "Hostname", "Тип"])
            self.assertEqual(len(rows), len(result["devices"]) + 1)
            evil = next(r for r in rows if r[0] == "10.0.0.66")
            self.assertTrue(evil[3].startswith("'="))                                 # формула обезврежена
            self.assertEqual(evil[6], "80, 443")
            md = paths[2].read_text(encoding="utf-8")
            self.assertIn("# Отчёт об инвентаризации", md)
            self.assertIn("x\\|y", md)                                                # | не ломает таблицу
            for line in md.splitlines():
                if line.startswith("| 10.0.0.66"):
                    self.assertEqual(line.count(" | "), 7)
            self.assertFalse(list(Path(d, "new", "dir").glob(".*.tmp")))              # временных файлов нет


if __name__ == "__main__":
    unittest.main(verbosity=2)
