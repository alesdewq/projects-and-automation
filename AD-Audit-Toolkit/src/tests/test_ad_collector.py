"""Тесты: python -m unittest discover -s tests -v (из папки проекта).

Без сети и без AD: преобразования, тестовый домен в памяти (mock), AD-подобный LDAP-сервер (лимит 1000
записей на страницу и выдача больших групп кусками по 1500), ошибки подключения.
С настоящим контроллером (Samba AD / Windows AD) — класс TestRealDC, если заданы переменные
AD_TEST_DC, AD_TEST_USER, AD_TEST_PASSWORD (см. README).
"""
import json
import logging
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import ad_client as ac          # noqa: E402
import collector as col        # noqa: E402
import mock_ad                 # noqa: E402
from fake_ad_server import FakeAD   # noqa: E402

logging.getLogger("ad_collector").addHandler(logging.NullHandler())   # предупреждения не сыплются в вывод тестов

SPEC_SCAN_INFO = {"domain", "dc_address", "scan_date", "total_users", "total_groups", "total_ous", "total_computers"}
SPEC_USER = {"sAMAccountName", "displayName", "givenName", "sn", "mail", "telephoneNumber", "title", "department",
             "office", "company", "manager", "memberOf", "dn", "userAccountControl", "whenCreated", "lastLogonTimestamp"}
SPEC_GROUP = {"cn", "sAMAccountName", "description", "members", "memberOf", "groupType", "dn"}
SPEC_COMPUTER = {"cn", "dnsHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp", "dn"}


def walk(nodes):
    for n in nodes:
        yield n
        yield from walk(n["children"])


def check_format(tc, r):
    """Проверка формата JSON из задания."""
    tc.assertTrue(SPEC_SCAN_INFO <= set(r["scan_info"]))
    for key in ("ou_tree", "users", "groups", "computers", "offices", "positions"):
        tc.assertIsInstance(r[key], list, key)
    for n in walk(r["ou_tree"]):
        tc.assertTrue({"dn", "name", "description", "children"} <= set(n))
    for u in r["users"]:
        tc.assertTrue(SPEC_USER <= set(u))
        tc.assertIsInstance(u["memberOf"], list)
    for g in r["groups"]:
        tc.assertTrue(SPEC_GROUP <= set(g))
        tc.assertIsInstance(g["groupType"], str)
    for c in r["computers"]:
        tc.assertTrue(SPEC_COMPUTER <= set(c))
    si = r["scan_info"]
    tc.assertEqual(si["total_users"], len(r["users"]))
    tc.assertEqual(si["total_groups"], len(r["groups"]))
    tc.assertEqual(si["total_computers"], len(r["computers"]))
    tc.assertEqual(si["total_ous"], sum(1 for _ in walk(r["ou_tree"])))
    tc.assertTrue(all(isinstance(x, str) for x in r["offices"] + r["positions"]))
    tc.assertEqual(r["positions"], sorted(set(r["positions"]), key=str.casefold))
    json.loads(json.dumps(r, ensure_ascii=False))          # сериализуется без default=


class TestConverters(unittest.TestCase):
    def test_md4_vectors(self):
        self.assertEqual(ac.md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(ac.md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")
        self.assertEqual(ac.md4(b"1234567890" * 8).hex(), "e33b4ddc9c38f2199c3e7b164fcc0536")
        self.assertEqual(ac.md4("password".encode("utf-16-le")).hex(), "8846f7eaee8fb117ad06bdd830b7586c")  # NT-хеш

    def test_ntlm_uses_md4_shim(self):
        ac._enable_ntlm()
        from ldap3.utils import ntlm
        self.assertEqual(ntlm.hashlib.new("MD4", b"abc").hexdigest(), "a448017aaf21d8525fc10ae87aa6729d")
        self.assertEqual(ntlm.hashlib.new("md5", b"").hexdigest(), "d41d8cd98f00b204e9800998ecf8427e")

    def test_times(self):
        self.assertEqual(col.filetime("133000000000000000"), "2022-06-18T04:26:40+00:00")
        for never in (None, "", "0", "9223372036854775807", "-1"):
            self.assertIsNone(col.filetime(never))
        self.assertEqual(col.generalized_time("20240115100000.0Z"), "2024-01-15T10:00:00+00:00")
        self.assertEqual(col.interval_minutes("-18000000000"), 30.0)
        self.assertIsNone(col.interval_minutes(str(-0x8000000000000000)))

    def test_sid_guid(self):
        raw = bytes([1, 5]) + (5).to_bytes(6, "big") + b"".join(x.to_bytes(4, "little") for x in (21, 1, 2, 3, 1105))
        self.assertEqual(col.sid_to_str(raw), "S-1-5-21-1-2-3-1105")
        self.assertIsNone(col.sid_to_str(b"\x01\x05\x00"))
        g = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
        import uuid
        self.assertEqual(col.guid_to_str(uuid.UUID(g).bytes_le), g)

    def test_flags(self):
        self.assertEqual(col.uac_flags(514), ["ACCOUNTDISABLE", "NORMAL_ACCOUNT"])
        self.assertEqual(col.group_kind(-2147483646), ("security", "global"))
        self.assertEqual(col.group_kind(-2147483644), ("security", "domain_local"))
        self.assertEqual(col.group_kind(-2147483640), ("security", "universal"))
        self.assertEqual(col.group_kind(2), ("distribution", "global"))

    def test_dn(self):
        dn = r"OU=Отдел продаж\, маркетинг,OU=Площадка-В,DC=c,DC=local"
        self.assertEqual(col.split_dn(dn), (r"OU=Отдел продаж\, маркетинг", "OU=Площадка-В,DC=c,DC=local"))
        self.assertEqual(col.rdn_value(dn), "Отдел продаж, маркетинг")
        self.assertEqual(col.rdn_value(r"CN=\D0\98\D0\B2\D0\B0\D0\BD,DC=x"), "Иван")
        self.assertEqual(col.parent_dn("DC=local"), "")
        self.assertEqual(ac.dn_to_domain("DC=company,DC=local"), "company.local")

    def test_address_and_login(self):
        self.assertEqual(ac.split_address("dc01"), ("dc01", None))
        self.assertEqual(ac.split_address("ldaps://dc01.c.local:3269/"), ("dc01.c.local", 3269))
        self.assertEqual(ac.split_address("[fe80::1]:636"), ("fe80::1", 636))
        self.assertEqual(ac.split_address("fe80::1"), ("fe80::1", None))
        self.assertEqual(ac.login_kind("CORP\\ivanov"), "ntlm")
        self.assertEqual(ac.login_kind("ivanov@corp.local"), "simple")
        self.assertEqual(ac.login_kind("ivanov"), "bare")

    def test_bind_errors(self):
        msg = "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {}, v4563"
        cases = {"52e": "Неверный логин или пароль", "775": "заблокирована", "532": "пароля истёк", "533": "отключена"}
        for code, text in cases.items():
            cls, t = ac.bind_error_text({"result": 49, "message": msg.format(code)})
            self.assertIs(cls, ac.AuthError)
            self.assertIn(text, t)
        cls, _ = ac.bind_error_text({"result": 8, "message": "BindSimple: Transport encryption required."})
        self.assertIs(cls, ac.StrongAuthRequired)

    def test_offices_heuristic(self):
        ous = [{"dn": "OU=Sites,DC=x", "name": "Sites"}, {"dn": "OU=Площадки,OU=Old,DC=x", "name": "Площадки"},
               {"dn": "OU=Тверь,OU=Sites,DC=x", "name": "Тверь"}]
        self.assertEqual([o["dn"] for o in col.find_office_ous(ous, None)], ["OU=Sites,DC=x"])
        self.assertEqual([o["dn"] for o in col.find_office_ous(ous, "OU=Площадки,OU=Old,DC=x")], ["OU=Площадки,OU=Old,DC=x"])
        self.assertEqual(col.find_office_ous([{"dn": "OU=IT,DC=x", "name": "IT"}], None), [])


class TestMockDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = mock_ad.make_client("mock", "DEMO\\reader", "demo").connect()
        calls = []
        orig = cls.client.conn.search
        cls.client.conn.search = lambda *a, **kw: (calls.append(kw.get("paged_size")), orig(*a, **kw))[1]
        progress = []
        cls.result = col.Collector(cls.client, progress=lambda f, m: progress.append(f)).collect()
        cls.calls, cls.progress = calls, progress

    def test_format(self):
        check_format(self, self.result)
        self.assertEqual(self.result["scan_info"]["status"], "complete")

    def test_counts_and_paging(self):
        si = self.result["scan_info"]
        self.assertEqual(si["total_users"], 1101)              # 1100 сотрудников + учётка для чтения
        self.assertEqual(si["total_computers"], 40)
        self.assertEqual(si["total_ous"], 10)
        self.assertEqual(si["disabled_users"], 37)
        self.assertTrue(all(size == col.PAGE_SIZE for size in self.calls))
        self.assertGreaterEqual(len(self.calls), 3 + 7)       # пользователи — минимум 3 страницы по 500

    def test_progress_monotonic(self):
        self.assertEqual(self.progress, sorted(self.progress))
        self.assertEqual(self.progress[-1], 1.0)

    def test_tree_offices_positions(self):
        r = self.result
        top = {n["name"]: n for n in r["ou_tree"]}
        self.assertEqual(set(top), {"Площадки", "Группы"})
        self.assertEqual([c["name"] for c in top["Площадки"]["children"]], ["Площадка-А", "Площадка-Б", "Площадка-В"])
        self.assertEqual(top["Площадки"]["gpo_links"], ["Default Domain Policy"])
        self.assertEqual(r["offices"], ["Площадка-А", "Площадка-Б", "Площадка-В"])
        self.assertEqual(r["offices_detail"]["source"], "ou")
        vl = next(o for o in r["offices_detail"]["from_ou"] if o["name"] == "Площадка-А")
        self.assertEqual((vl["users"], vl["departments"]), (440, ["Офис", "Производство"]))
        self.assertEqual(r["positions"], ["Бухгалтер", "Инженер", "Кладовщик", "Менеджер", "Наладчик", "Оператор"])
        self.assertEqual(r["domain"]["upn_suffixes"], ["corp.demo.example", "demo.example"])
        self.assertEqual(r["domain"]["netbios_name"], "DEMO")
        self.assertEqual(r["domain"]["password_policy"]["min_length"], 8)
        self.assertEqual([s["name"] for s in r["ad_sites"]], ["Site-A", "Site-B"])

    def test_user_fields(self):
        u = next(x for x in self.result["users"] if x["sAMAccountName"] == "user0010")
        self.assertEqual(u["office"], "Площадка-А")
        self.assertEqual(u["ou_path"], "Площадки/Площадка-А/Производство")
        self.assertTrue(u["objectSid"].startswith("S-1-5-21-1111111111-"))
        self.assertEqual(u["primaryGroup"], "CN=Domain Users,CN=Users,DC=demo,DC=local")
        self.assertEqual(u["manager_sAMAccountName"], "user0000")
        self.assertIsNone(u["accountExpires"])
        self.assertTrue(u["lastLogonTimestamp"].startswith("2026-10-"))
        self.assertEqual(len(u["memberOf"]), 2)
        self.assertFalse(next(x for x in self.result["users"] if x["sAMAccountName"] == "user0000")["enabled"])

    def test_save_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = col.save_json(self.result, Path(d) / "sub" / col.default_filename(self.result))
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data["scan_info"]["total_users"], 1101)
            self.assertIn("Иванов", p.read_text(encoding="utf-8"))   # кириллица без \\u-экранирования
            self.assertEqual(os.listdir(p.parent), [p.name])        # временных файлов не осталось
            self.assertTrue(p.name.startswith("ad_structure_demo.local_"))


class TestMockBehaviour(unittest.TestCase):
    def test_errors(self):
        for pw, exc in (("wrong", ac.AuthError), ("mock-timeout", ac.ADTimeout), ("mock-down", ac.UnreachableError)):
            with self.assertRaises(exc):
                mock_ad.make_client("mock", "u", pw, connect_timeout=1).connect()
        with self.assertRaises(ac.ADError):
            mock_ad.make_client("mock", "u", "").connect()           # пустой пароль = анонимный вход — запрещён

    def test_cancel_gives_partial(self):
        c = mock_ad.make_client("mock", "u", "mock-slow").connect()
        flag = threading.Event()
        threading.Timer(1.5, flag.set).start()
        t = time.monotonic()
        r = col.Collector(c, is_cancelled=flag.is_set).collect()
        self.assertLess(time.monotonic() - t, 4)
        self.assertEqual(r["scan_info"]["status"], "cancelled")
        self.assertFalse(r["scan_info"]["complete"])
        self.assertTrue(any("остановлен" in w for w in r["scan_info"]["warnings"]))

    def test_offices_from_attribute_and_override(self):
        c = mock_ad.make_client("mock", "u", "demo").connect()
        r = col.Collector(c, offices_ou="Нет такой").collect()
        self.assertEqual(r["offices_detail"]["source"], "physicalDeliveryOfficeName")
        self.assertEqual(r["offices"], ["Площадка-А", "Площадка-Б", "Площадка-В"])
        self.assertTrue(any("не найдена" in w for w in r["scan_info"]["warnings"]))
        r = col.Collector(c, offices_ou="OU=Площадка-В,OU=Площадки,DC=demo,DC=local").collect()
        self.assertEqual(r["offices"], ["Бухгалтерия", "Продажи"])


class TestADLikeServer(unittest.TestCase):
    """Сервер с ограничениями настоящего AD: MaxPageSize 1000, MaxValRange 1500."""

    @classmethod
    def setUpClass(cls):
        cls.srv = FakeAD()
        cls.client = ac.ADClient(f"127.0.0.1:{cls.srv.port}", "u@fake.local", "pass", security="plain",
                                 connect_timeout=3, receive_timeout=10).connect()

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.srv.close()

    def test_without_paging_only_1000(self):
        self.client.conn.search("DC=fake,DC=local", col.USER_FILTER, attributes=["cn"])
        self.assertEqual(len(self.client.conn.response), 1000)
        self.assertEqual(self.client.conn.result["description"], "sizeLimitExceeded")

    def test_collect_all(self):
        r = col.Collector(self.client).collect()
        check_format(self, r)
        self.assertEqual(r["scan_info"]["total_users"], 2500)
        big = next(g for g in r["groups"] if g["cn"] == "Big Group")
        self.assertEqual(big["member_count"], 3200)
        self.assertEqual(len(set(big["members"])), 3200)
        self.assertIn(["member;range=3000-*"], [s["attributes"] for s in self.srv.searches])
        self.assertEqual(r["offices_detail"]["source"], "physicalDeliveryOfficeName")
        self.assertEqual(r["offices"], ["Омск", "Тверь"])
        self.assertEqual(len(r["positions"]), 7)
        self.assertEqual(r["domain"]["password_policy"]["min_length"], 10)
        self.assertTrue(any("не найден" in w for w in r["scan_info"]["warnings"]) or not r["scan_info"]["warnings"])

    def test_wrong_password(self):
        with self.assertRaises(ac.AuthError) as cm:
            ac.ADClient(f"127.0.0.1:{self.srv.port}", "u@fake.local", "bad", security="plain").connect()
        self.assertIn("Неверный логин или пароль", str(cm.exception))


class TestConnectionErrors(unittest.TestCase):
    def test_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(ac.UnreachableError) as cm:
            ac.ADClient(f"127.0.0.1:{port}", "u@x.local", "p", security="ldaps").connect()
        self.assertIn("отклонено", str(cm.exception))

    def test_silent_server_times_out(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(8)
        port = s.getsockname()[1]
        held = []
        threading.Thread(target=lambda: [held.append(s.accept()) for _ in range(4)], daemon=True).start()
        for mode in ("ldaps", "starttls", "plain"):
            t = time.monotonic()
            with self.assertRaises(ac.ADTimeout):
                ac.ADClient(f"127.0.0.1:{port}", "u@x.local", "p", security=mode, connect_timeout=1,
                            receive_timeout=2).connect()
            self.assertLess(time.monotonic() - t, 6, mode)
        s.close()

    def test_dns(self):
        with self.assertRaises(ac.UnreachableError) as cm:
            ac.ADClient("dc.nonexistent.invalid", "u@x.local", "p").connect()
        self.assertIn("DNS", str(cm.exception))

    def test_input_validation(self):
        for args in (("", "u", "p"), ("dc", "", "p"), ("dc", "u", "")):
            with self.assertRaises(ac.ADError):
                ac.ADClient(*args).connect()


@unittest.skipUnless(os.environ.get("AD_TEST_DC"), "нужны AD_TEST_DC, AD_TEST_USER, AD_TEST_PASSWORD")
class TestRealDC(unittest.TestCase):
    """Настоящий контроллер (проверено на Samba AD с данными из tests/samba/seed.py)."""
    dc = os.environ.get("AD_TEST_DC", "")
    user = os.environ.get("AD_TEST_USER", "")
    password = os.environ.get("AD_TEST_PASSWORD", "")
    security = os.environ.get("AD_TEST_SECURITY", "auto")

    def test_wrong_password(self):
        with self.assertRaises(ac.AuthError):
            ac.ADClient(self.dc, self.user, self.password + "x", security=self.security).connect()

    def test_collect(self):
        c = ac.ADClient(self.dc, self.user, self.password, security=self.security).connect()
        try:
            r = col.Collector(c).collect()
        finally:
            c.close()
        check_format(self, r)
        si = r["scan_info"]
        self.assertEqual(si["status"], "complete", si["errors"])
        self.assertTrue(si["encrypted"])
        if os.environ.get("AD_TEST_SEEDED"):                  # данные из tests/samba/seed.py
            self.assertGreater(si["total_users"], 1600)
            big = next(g for g in r["groups"] if g["cn"] == "Все сотрудники")
            self.assertEqual(big["member_count"], 1600)
            self.assertEqual(r["offices"], ["Площадка-А", "Площадка-В", "Санкт-Петербург"])
            names = [n["name"] for n in walk(r["ou_tree"])]
            self.assertIn("Отдел продаж, маркетинг", names)
            self.assertIn("Начальник отдела", r["positions"])
            self.assertIn("Площадка-А", [s["name"] for s in r["ad_sites"]])
            self.assertTrue(any(g["category"] == "distribution" for g in r["groups"]))


if __name__ == "__main__":
    unittest.main()
