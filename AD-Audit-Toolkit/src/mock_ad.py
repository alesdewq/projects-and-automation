"""Тестовый «домен» в памяти (ldap3 MOCK_SYNC) — для демо-режима и тестов без настоящего AD.

Адрес контроллера «mock». Пароль «wrong» — ошибка входа, «mock-timeout» — таймаут,
«mock-down» — DC недоступен, «mock-slow» — медленный DC (для проверки окна и кнопки «Остановить»).
"""
from __future__ import annotations

import random
import struct
import time
import uuid

import ldap3

from ad_client import ADClient, ADTimeout, AuthError, UnreachableError

BASE = "DC=demo,DC=local"
CONFIG = f"CN=Configuration,{BASE}"
DOMAIN_SID = (21, 1111111111, 2222222222, 3333333333)

SITES = {"Площадка-А": ["Производство", "Офис"], "Площадка-В": ["Продажи", "Бухгалтерия"], "Площадка-Б": ["Склад"]}
TITLES = {"Производство": ["Оператор", "Наладчик"], "Офис": ["Менеджер", "Инженер"], "Продажи": ["Менеджер"],
          "Бухгалтерия": ["Бухгалтер"], "Склад": ["Кладовщик"]}
SURNAMES = ["Иванов", "Петров", "Сидоров", "Кузнецов", "Смирнов", "Попов", "Соколов", "Волков"]
NAMES = ["Иван", "Пётр", "Алексей", "Сергей", "Дмитрий", "Андрей"]


def sid_bytes(rid: int | None) -> bytes:
    subs = DOMAIN_SID if rid is None else (*DOMAIN_SID, rid)
    return bytes([1, len(subs)]) + (5).to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)


def filetime(year, month, day) -> str:
    return str(int((time.mktime((year, month, day, 12, 0, 0, 0, 0, 0)) + 11644473600) * 10_000_000))


def demo_entries(n_users: int = 1100):
    """Детерминированный набор объектов домена demo.local: (dn, атрибуты)."""
    rnd = random.Random(7)
    rid = [1200]

    def next_sid():
        rid[0] += 1
        return sid_bytes(rid[0])

    out = []
    add = lambda dn, **a: out.append((dn, a))
    add(BASE, objectClass=["top", "domain", "domainDNS"], name="demo", objectSid=sid_bytes(None),
        minPwdLength="8", pwdHistoryLength="12", pwdProperties="1", maxPwdAge="-77760000000000",
        minPwdAge="-864000000000", lockoutThreshold="5", lockoutDuration="-18000000000",
        lockOutObservationWindow="-18000000000", **{"msDS-Behavior-Version": "7", "ms-DS-MachineAccountQuota": "10"},
        wellKnownObjects=[f"B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,{BASE}",
                          f"B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,{BASE}"],
        whenCreated="20200301090000.0Z")
    add(f"CN=Users,{BASE}", objectClass=["top", "container"], name="Users", description="Контейнер по умолчанию")
    add(f"CN=Computers,{BASE}", objectClass=["top", "container"], name="Computers")
    add(f"CN=Partitions,{CONFIG}", objectClass=["top", "crossRefContainer"], uPNSuffixes=["demo.example", "corp.demo.example"])
    add(f"CN=DEMO,CN=Partitions,{CONFIG}", objectClass=["top", "crossRef"], nETBIOSName="DEMO", dnsRoot="demo.local",
        nCName=BASE)
    add(f"CN=Sites,{CONFIG}", objectClass=["top", "sitesContainer"])
    add(f"CN=Subnets,CN=Sites,{CONFIG}", objectClass=["top", "subnetContainer"])
    for site, net in (("Site-A", "10.10.0.0/16"), ("Site-B", "10.20.0.0/16")):
        add(f"CN={site},CN=Sites,{CONFIG}", objectClass=["top", "site"], name=site, location=site)
        add(f"CN={net.replace('/', chr(92) + '/')},CN=Subnets,CN=Sites,{CONFIG}", objectClass=["top", "subnet"],
            name=net, siteObject=f"CN={site},CN=Sites,{CONFIG}")
    add(f"CN=DC01,CN=Servers,CN=Site-B,CN=Sites,{CONFIG}", objectClass=["top", "server"], name="DC01",
        dNSHostName="dc01.demo.local")
    add(f"CN=Policies,CN=System,{BASE}", objectClass=["top", "container"])
    gpo = f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{BASE}"
    add(gpo, objectClass=["top", "groupPolicyContainer"], cn="{31B2F340-016D-11D2-945F-00C04FB984F9}",
        displayName="Default Domain Policy", flags="0")

    sites_ou = f"OU=Площадки,{BASE}"
    add(sites_ou, objectClass=["top", "organizationalUnit"], name="Площадки", ou="Площадки",
        description="Города", gPLink=f"[LDAP://{gpo.lower()};0]")
    add(f"OU=Группы,{BASE}", objectClass=["top", "organizationalUnit"], name="Группы", ou="Группы")
    for site, depts in SITES.items():
        add(f"OU={site},{sites_ou}", objectClass=["top", "organizationalUnit"], name=site, ou=site,
            description=f"Площадка {site}")
        for d in depts:
            add(f"OU={d},OU={site},{sites_ou}", objectClass=["top", "organizationalUnit"], name=d, ou=d)

    groups = {}
    for site, depts in SITES.items():
        for d in depts:
            groups[(site, d)] = (f"CN=GG_{d}_{site},OU=Группы,{BASE}", [])
    all_staff = (f"CN=Все сотрудники,OU=Группы,{BASE}", [])
    users = []
    slots = [(s, d) for s, ds in SITES.items() for d in ds]
    for i in range(n_users):
        site, dept = slots[i % len(slots)]
        sn, gn = rnd.choice(SURNAMES), rnd.choice(NAMES)
        sam = f"user{i:04d}"
        dn = f"CN={sn} {gn} {i:04d},OU={dept},OU={site},{sites_ou}"
        gdn, gmembers = groups[(site, dept)]
        gmembers.append(dn)
        all_staff[1].append(dn)
        a = dict(objectClass=["top", "person", "organizationalPerson", "user"], cn=f"{sn} {gn} {i:04d}",
                 sAMAccountName=sam, userPrincipalName=f"{sam}@demo.example", givenName=gn, sn=sn,
                 displayName=f"{sn} {gn}", mail=f"{sam}@demo.example", telephoneNumber=f"+7 900 000-{i:04d}",
                 department=dept, company="ООО Демо", physicalDeliveryOfficeName=site,
                 title=rnd.choice(TITLES[dept]), userAccountControl="514" if i % 30 == 0 else "512",
                 whenCreated="20240115100000.0Z", lastLogonTimestamp=filetime(2026, 10, 1 + i % 12),
                 pwdLastSet=filetime(2026, 9, 1), accountExpires="9223372036854775807", primaryGroupID="513",
                 objectSid=next_sid(), objectGUID=uuid.UUID(int=i + 1).bytes_le, memberOf=[gdn, all_staff[0]])
        if i >= len(slots):
            a["manager"] = users[slots.index((site, dept))]
        users.append(dn)
        add(dn, **a)
    add(f"CN=Читатель AD,CN=Users,{BASE}", objectClass=["top", "person", "organizationalPerson", "user"],
        cn="Читатель AD", sAMAccountName="reader", userPrincipalName="reader@demo.local", userPassword="demo",
        userAccountControl="66048", primaryGroupID="513", objectSid=next_sid())
    add(f"CN=Domain Users,CN=Users,{BASE}", objectClass=["top", "group"], cn="Domain Users",
        sAMAccountName="Domain Users", groupType="-2147483646", objectSid=sid_bytes(513))
    for (site, d), (gdn, members) in groups.items():
        add(gdn, objectClass=["top", "group"], cn=gdn[3:].split(",")[0], sAMAccountName=gdn[3:].split(",")[0],
            groupType="-2147483646", description=f"{d} — {site}", member=members,
            objectSid=next_sid())
    add(all_staff[0], objectClass=["top", "group"], cn="Все сотрудники", sAMAccountName="Все_сотрудники",
        groupType="-2147483640", member=all_staff[1], objectSid=next_sid())
    for i in range(40):
        name = f"PC-{i:03d}"
        add(f"CN={name},CN=Computers,{BASE}", objectClass=["top", "person", "organizationalPerson", "user", "computer"],
            cn=name, sAMAccountName=name + "$", dNSHostName=f"{name.lower()}.demo.local",
            operatingSystem="Windows 11 Pro" if i % 2 else "Windows 10 Pro",
            operatingSystemVersion="10.0 (22631)" if i % 2 else "10.0 (19045)", userAccountControl="4096",
            lastLogonTimestamp=filetime(2026, 10, 12), objectSid=next_sid())
    add(f"CN=Поставщик,OU=Площадка-В,{sites_ou}", objectClass=["top", "person", "organizationalPerson", "contact"],
        cn="Поставщик", displayName="ООО Поставщик", mail="info@supplier.example")
    return out


class MockADClient(ADClient):
    """Как ADClient, но с доменом demo.local в памяти."""

    def __init__(self, *args, n_users: int = 1100, **kw):
        super().__init__(*args, **kw)
        self.n_users = n_users

    def connect(self):
        self._check_input()
        p = self.password
        if p == "wrong":
            raise AuthError("Неверный логин или пароль")
        if p == "mock-timeout":
            time.sleep(min(self.connect_timeout, 2))
            raise ADTimeout(f"Контроллер домена {self.address}:636 не ответил за {self.connect_timeout:g} с")
        if p == "mock-down":
            raise UnreachableError(f"Контроллер домена {self.address}:636 недоступен: соединение отклонено")
        server = ldap3.Server("mock", get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=f"CN=Читатель AD,CN=Users,{BASE}", password="demo",
                                client_strategy=ldap3.MOCK_SYNC, check_names=False, raise_exceptions=False)
        for dn, attrs in demo_entries(self.n_users):
            conn.strategy.add_entry(dn, attrs)
        conn.bind()
        if p == "mock-slow":                       # медленный DC: каждая страница поиска — 0,4 с
            search = conn.search

            def slow(*a, **kw):
                time.sleep(0.4)
                return search(*a, **kw)
            conn.search = slow
        self.conn, self.host, self.port, self.mode_used = conn, self.address, 636, "ldaps"
        self.root_dse = {"defaultNamingContext": [BASE], "configurationNamingContext": [CONFIG],
                         "rootDomainNamingContext": [BASE], "dnsHostName": ["dc01.demo.local"]}
        self.base_dn = self.base_dn_override or BASE
        self.domain = "demo.local"
        return self


def make_client(address: str, *args, **kw) -> ADClient:
    cls = MockADClient if address.strip().lower().startswith("mock") else ADClient
    return cls(address, *args, **kw)
