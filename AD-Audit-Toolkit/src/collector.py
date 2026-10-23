"""Сбор структуры Active Directory: OU, пользователи, группы, компьютеры, площадки, должности → словарь для JSON."""
from __future__ import annotations

import json
import logging
import os
import struct
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ldap3
from ldap3.core import exceptions as lx
from ldap3.utils.conv import escape_filter_chars

from ad_client import ADError, ADTimeout, UnreachableError, transport_error

__version__ = "1.0.0"
log = logging.getLogger("ad_collector.collect")

PAGED_OID = "1.2.840.113556.1.4.319"
PAGE_SIZE = 500                        # AD отдаёт не больше MaxPageSize (по умолчанию 1000) за страницу

USER_FILTER = "(&(objectClass=user)(!(objectClass=computer)))"
USER_ATTRS = ["sAMAccountName", "displayName", "givenName", "sn", "initials", "middleName", "cn", "mail",
              "telephoneNumber", "mobile", "ipPhone", "homePhone", "facsimileTelephoneNumber", "title", "department",
              "company", "physicalDeliveryOfficeName", "manager", "memberOf", "distinguishedName",
              "userAccountControl", "whenCreated", "whenChanged", "lastLogonTimestamp", "userPrincipalName",
              "description", "employeeID", "employeeNumber", "employeeType", "streetAddress", "l", "st", "postalCode",
              "co", "c", "primaryGroupID", "pwdLastSet", "accountExpires", "lockoutTime", "objectGUID", "objectSid",
              "directReports", "homeDirectory", "homeDrive", "scriptPath", "profilePath", "info", "wWWHomePage",
              "proxyAddresses", "objectClass"] + [f"extensionAttribute{i}" for i in range(1, 16)]
GROUP_ATTRS = ["cn", "name", "sAMAccountName", "description", "member", "memberOf", "groupType", "distinguishedName",
               "mail", "managedBy", "info", "objectSid", "objectGUID", "whenCreated"]
COMPUTER_ATTRS = ["cn", "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                  "operatingSystemServicePack", "lastLogonTimestamp", "distinguishedName", "description", "location",
                  "managedBy", "userAccountControl", "whenCreated", "pwdLastSet", "memberOf", "objectSid", "objectGUID"]
OU_ATTRS = ["name", "ou", "description", "distinguishedName", "whenCreated", "managedBy", "gPLink", "l", "st",
            "street", "postalCode", "co"]
CONTACT_ATTRS = ["cn", "displayName", "givenName", "sn", "mail", "telephoneNumber", "mobile", "company",
                 "department", "title", "description", "distinguishedName"]
DOMAIN_ATTRS = ["name", "objectSid", "whenCreated", "msDS-Behavior-Version", "minPwdLength", "minPwdAge", "maxPwdAge",
                "pwdHistoryLength", "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
                "ms-DS-MachineAccountQuota", "wellKnownObjects"]

# Названия OU, внутри которых обычно лежат площадки/города
OFFICE_CONTAINER_NAMES = {"площадки", "площадка", "филиалы", "филиал", "офисы", "города", "регионы", "территории",
                          "sites", "offices", "branches", "locations", "cities", "regions"}

UAC_FLAGS = {0x2: "ACCOUNTDISABLE", 0x10: "LOCKOUT", 0x20: "PASSWD_NOTREQD", 0x40: "PASSWD_CANT_CHANGE",
             0x80: "ENCRYPTED_TEXT_PWD_ALLOWED", 0x100: "TEMP_DUPLICATE_ACCOUNT", 0x200: "NORMAL_ACCOUNT",
             0x800: "INTERDOMAIN_TRUST_ACCOUNT", 0x1000: "WORKSTATION_TRUST_ACCOUNT",
             0x2000: "SERVER_TRUST_ACCOUNT", 0x10000: "DONT_EXPIRE_PASSWORD", 0x20000: "MNS_LOGON_ACCOUNT",
             0x40000: "SMARTCARD_REQUIRED", 0x80000: "TRUSTED_FOR_DELEGATION", 0x100000: "NOT_DELEGATED",
             0x200000: "USE_DES_KEY_ONLY", 0x400000: "DONT_REQ_PREAUTH", 0x800000: "PASSWORD_EXPIRED",
             0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION", 0x4000000: "PARTIAL_SECRETS_ACCOUNT"}
FUNCTIONAL_LEVELS = {0: "Windows 2000", 1: "Windows Server 2003 (промежуточный)", 2: "Windows Server 2003",
                     3: "Windows Server 2008", 4: "Windows Server 2008 R2", 5: "Windows Server 2012",
                     6: "Windows Server 2012 R2", 7: "Windows Server 2016", 10: "Windows Server 2025"}
WELL_KNOWN = {"A9D1CA15768811D1ADED00C04FD8D5CD": "users", "AA312825768811D1ADED00C04FD8D5CD": "computers",
              "A361B2FFFFD211D1AA4B00C04FD7D83A": "domain_controllers", "AB1D30F3768811D1ADED00C04FD8D5CD": "system",
              "18E2EA80684F11D2B9AA00C04F79F805": "deleted_objects", "2FBAC1870ADE11D297C400C04FD8D5CD": "infrastructure",
              "22B70C67D56E4EFB91E9300FCA3DC1AA": "foreign_security_principals",
              "AB8153B7768811D1ADED00C04FD8D5CD": "lost_and_found", "F4BE92A4C777485E878E9421D53087DB": "microsoft",
              "6227F0AF1FC2410D8E3BB10615BB5B0F": "ntds_quotas", "09460C08AE1E4A4EA0F64AEE7DAA1E5A": "program_data",
              "1EB93889E40C45DF9F0C64D23BBB6237": "managed_service_accounts"}
# Подсказка для второго приложения: ключ JSON → атрибут AD
ATTRIBUTE_MAP = {"users": {"dn": "distinguishedName", "office": "physicalDeliveryOfficeName", "city": "l",
                           "region": "st", "country": "co", "countryCode": "c", "fax": "facsimileTelephoneNumber"},
                 "groups": {"dn": "distinguishedName", "members": "member"},
                 "computers": {"dn": "distinguishedName", "dnsHostName": "dNSHostName"}}

SECTIONS = [("domain", 0.04), ("config", 0.04), ("ous", 0.07), ("users", 0.45), ("groups", 0.25),
            ("computers", 0.12), ("contacts", 0.03)]


class Cancelled(Exception):
    pass


# ---------- преобразование значений
def _s(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def first(a: dict, name: str) -> str | None:
    v = a.get(name.lower())
    return _s(v[0]) if v else None


def many(a: dict, name: str) -> list[str]:
    return [_s(x) for x in a.get(name.lower(), [])]


def as_int(value) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def generalized_time(value: str | None) -> str | None:
    """'20240115100000.0Z' → '2024-01-15T10:00:00+00:00'."""
    if not value:
        return None
    try:
        return datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return value


def filetime(value) -> str | None:
    """Время Windows (100 нс с 1601 г.) → ISO 8601 UTC; 0 и «никогда» → None."""
    v = as_int(value)
    if not v or v >= 0x7FFFFFFFFFFFFFFF or v < 0:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)).isoformat(timespec="seconds")
    except OverflowError:
        return None


def interval_minutes(value) -> float | None:
    """Интервалы политики паролей хранятся отрицательными (100 нс); «никогда» → None."""
    v = as_int(value)
    if v is None or v == -0x8000000000000000:
        return None
    return round(abs(v) / 600_000_000, 2)


def sid_to_str(raw: bytes | None) -> str | None:
    if not raw or len(raw) < 8:
        return None
    count = raw[1]
    if len(raw) < 8 + 4 * count:
        return None
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack(f"<{count}I", raw[8:8 + 4 * count])
    return "S-" + "-".join(str(x) for x in (raw[0], authority, *subs))


def guid_to_str(raw: bytes | None) -> str | None:
    if not raw or len(raw) != 16:
        return None
    return str(uuid.UUID(bytes_le=bytes(raw)))


def uac_flags(value: int | None) -> list[str]:
    return [name for bit, name in UAC_FLAGS.items() if value and value & bit]


def group_kind(group_type: int | None) -> tuple[str, str]:
    gt = (group_type or 0) & 0xFFFFFFFF
    category = "security" if gt & 0x80000000 else "distribution"
    scope = "domain_local" if gt & 0x4 else "global" if gt & 0x2 else "universal" if gt & 0x8 else "builtin" if gt & 0x1 else "unknown"
    return category, scope


def split_dn(dn: str) -> tuple[str, str]:
    """Первый RDN и родитель с учётом экранирования: 'OU=a\\,b,DC=x' → ('OU=a\\,b', 'DC=x')."""
    i, n = 0, len(dn)
    while i < n:
        ch = dn[i]
        if ch == "\\":
            i += 2
            continue
        if ch == ",":
            return dn[:i], dn[i + 1:].lstrip()
        i += 1
    return dn, ""


def rdn_value(dn: str) -> str:
    rdn = split_dn(dn)[0]
    value = rdn.split("=", 1)[1] if "=" in rdn else rdn
    out, i = [], 0
    while i < len(value):                       # снимаем экранирование: \, \+ \" \\ и \XX
        if value[i] == "\\" and i + 1 < len(value):
            pair = value[i + 1:i + 3]
            if len(pair) == 2 and all(c in "0123456789abcdefABCDEF" for c in pair):
                out.append(chr(int(pair, 16)))  # одиночный байт; многобайтовые последовательности ниже
                i += 3
                continue
            out.append(value[i + 1])
            i += 2
            continue
        out.append(value[i])
        i += 1
    s = "".join(out)
    try:                                         # \D0\98 → байты UTF-8 → «И»
        return s.encode("latin-1").decode("utf-8") if any(0x80 <= ord(c) <= 0xFF for c in s) else s
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def parent_dn(dn: str) -> str:
    return split_dn(dn)[1]


def norm(dn: str | None) -> str:
    return (dn or "").lower()


# ---------- сборщик
class Collector:
    def __init__(self, client, progress=None, is_cancelled=None, offices_ou: str | None = None,
                 page_size: int = PAGE_SIZE):
        self.client = client
        self.conn = client.conn
        self.progress = progress or (lambda frac, msg: None)
        self.is_cancelled = is_cancelled or (lambda: False)
        self.offices_ou = (offices_ou or "").strip() or None
        self.page_size = page_size
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self._frac = 0.0

    # --- LDAP
    def _check_cancel(self):
        if self.is_cancelled():
            raise Cancelled()

    def search(self, base: str, flt: str, attrs: list[str], scope=ldap3.SUBTREE, label: str = "", start=0.0, width=0.0):
        """Постраничный поиск (обходит лимит 1000 записей). Отдаёт (dn, атрибуты с ключами в нижнем регистре)."""
        cookie, pages, count = None, 0, 0
        while True:
            self._check_cancel()
            try:
                self.conn.search(base, flt, scope, attributes=attrs, paged_size=self.page_size, paged_cookie=cookie)
            except lx.LDAPException as e:
                raise transport_error(e, self.client.host, self.client.port, self.client.receive_timeout) from e
            res = self.conn.result
            code = res.get("result")
            if code not in (0, 4):          # 4 — sizeLimitExceeded: отдаём, что пришло
                raise LDAPSearchError(code, res.get("description"), res.get("message"), base)
            for e in self.conn.response or []:
                if e.get("type") != "searchResEntry":
                    continue
                attrs_out: dict[str, list] = {}
                for k, vals in e["raw_attributes"].items():
                    key = k.split(";", 1)[0].lower()         # member;range=0-* → member
                    attrs_out.setdefault(key, []).extend(vals or [])
                count += 1
                yield e["dn"], attrs_out
            pages += 1
            if width:
                self._report(start + width * (1 - 1 / (1 + pages * 0.35)), f"{label}: получено {count}")
            ctrl = (res.get("controls") or {}).get(PAGED_OID) or {}
            cookie = (ctrl.get("value") or {}).get("cookie")
            if not cookie:
                break

    def _report(self, frac, msg):
        self._frac = max(self._frac, min(frac, 1.0))
        self.progress(self._frac, msg)

    # --- разделы
    def _domain(self, base):
        info = {"dn": base, "dns_name": self.client.domain}
        for dn, a in self.search(base, "(objectClass=*)", DOMAIN_ATTRS, scope=ldap3.BASE):
            level = as_int(first(a, "msDS-Behavior-Version"))
            props = as_int(first(a, "pwdProperties")) or 0
            info.update({
                "name": first(a, "name"), "objectSid": sid_to_str((a.get("objectsid") or [None])[0]),
                "whenCreated": generalized_time(first(a, "whenCreated")),
                "functional_level": level, "functional_level_name": FUNCTIONAL_LEVELS.get(level),
                "machine_account_quota": as_int(first(a, "ms-DS-MachineAccountQuota")),
                "password_policy": {
                    "min_length": as_int(first(a, "minPwdLength")),
                    "history_length": as_int(first(a, "pwdHistoryLength")),
                    "complexity_required": bool(props & 1),
                    "max_age_days": _days(interval_minutes(first(a, "maxPwdAge"))),
                    "min_age_days": _days(interval_minutes(first(a, "minPwdAge"))),
                    "lockout_threshold": as_int(first(a, "lockoutThreshold")),
                    "lockout_duration_min": interval_minutes(first(a, "lockoutDuration")),
                    "lockout_window_min": interval_minutes(first(a, "lockOutObservationWindow")),
                },
                "well_known_containers": {
                    WELL_KNOWN[v.split(":")[2].upper()]: v.split(":", 3)[3]
                    for v in many(a, "wellKnownObjects")
                    if v.count(":") >= 3 and v.split(":")[2].upper() in WELL_KNOWN},
            })
        return info

    def _config(self, cfg: str, base: str):
        out = {"netbios_name": None, "forest_dns_name": None, "upn_suffixes": [], "sites": [], "gpos": []}
        parts = f"CN=Partitions,{cfg}"
        for _, a in self.search(parts, "(objectClass=*)", ["uPNSuffixes", "msDS-SPNSuffixes"], scope=ldap3.BASE):
            out["upn_suffixes"] = sorted(many(a, "uPNSuffixes"), key=str.casefold)
        for _, a in self.search(parts, f"(&(objectClass=crossRef)(nCName={escape_filter_chars(base)}))",
                                ["nETBIOSName", "dnsRoot"], scope=ldap3.LEVEL):
            out["netbios_name"] = first(a, "nETBIOSName")
        root = (self.client.root_dse.get("rootDomainNamingContext") or [""])[0]
        out["forest_dns_name"] = ".".join(p.split("=", 1)[1] for p in root.split(",") if "=" in p) or None

        sites_base = f"CN=Sites,{cfg}"
        sites = {}
        for dn, a in self.search(sites_base, "(objectClass=site)", ["name", "description", "location", "whenCreated"],
                                 scope=ldap3.LEVEL):
            sites[norm(dn)] = {"name": first(a, "name") or rdn_value(dn), "description": first(a, "description"),
                               "location": first(a, "location"), "dn": dn, "subnets": [], "domain_controllers": []}
        for dn, a in self.search(f"CN=Subnets,{sites_base}", "(objectClass=subnet)",
                                 ["name", "siteObject", "location", "description"], scope=ldap3.LEVEL):
            sn = {"subnet": first(a, "name") or rdn_value(dn), "location": first(a, "location"),
                  "description": first(a, "description")}
            site = sites.get(norm(first(a, "siteObject")))
            if site:
                site["subnets"].append(sn)
            else:
                sites.setdefault("", {"name": None, "description": "Подсети без сайта", "location": None, "dn": None,
                                      "subnets": [], "domain_controllers": []})["subnets"].append(sn)
        for dn, a in self.search(sites_base, "(objectClass=server)", ["name", "dNSHostName"]):
            site_dn = parent_dn(parent_dn(dn))           # CN=DC01,CN=Servers,CN=<сайт>,CN=Sites,...
            if norm(site_dn) in sites:
                sites[norm(site_dn)]["domain_controllers"].append(first(a, "dNSHostName") or first(a, "name"))
        out["sites"] = sorted(sites.values(), key=lambda s: (s["name"] is None, (s["name"] or "").casefold()))
        try:
            for dn, a in self.search(f"CN=Policies,CN=System,{base}", "(objectClass=groupPolicyContainer)",
                                     ["cn", "displayName", "whenCreated", "flags"], scope=ldap3.LEVEL):
                out["gpos"].append({"guid": first(a, "cn"), "name": first(a, "displayName"), "dn": dn,
                                    "whenCreated": generalized_time(first(a, "whenCreated")),
                                    "flags": as_int(first(a, "flags"))})
        except LDAPSearchError as e:
            self.warnings.append(f"Групповые политики не прочитаны: {e}")
        out["gpos"].sort(key=lambda g: (g["name"] or "").casefold())
        return out

    # --- главный метод
    def collect(self) -> dict:
        c = self.client
        started, t0 = datetime.now().astimezone(), time.monotonic()
        base = c.base_dn
        cfg = (c.root_dse.get("configurationNamingContext") or [""])[0]
        data = {"domain": {"dn": base, "dns_name": c.domain}, "config": {}, "ous": [], "users": [], "groups": [],
                "computers": [], "contacts": [], "containers": []}
        status = "complete"
        offsets, acc = {}, 0.0
        for name, w in SECTIONS:
            offsets[name] = (acc, w)
            acc += w

        def section(name, label, fn):
            start, width = offsets[name]
            self._report(start, label + "…")
            log.info("%s…", label)
            try:
                fn(start, width)
            except LDAPSearchError as e:
                if e.code == 32 and name != "domain":     # noSuchObject — раздела нет / не виден этой учётке
                    self.warnings.append(f"{label}: раздел не найден ({e.base})")
                elif e.code in (50,):                     # insufficientAccessRights
                    self.warnings.append(f"{label}: недостаточно прав ({e.base})")
                else:
                    raise
                log.warning("%s: %s", label, e)
            self._report(start + width, f"{label}: готово")

        def do_domain(start, width):
            data["domain"] = self._domain(base)

        def do_config(start, width):
            if cfg:
                data["config"] = self._config(cfg, base)

        def do_ous(start, width):
            for dn, a in self.search(base, "(objectClass=organizationalUnit)", OU_ATTRS, label="OU", start=start, width=width):
                data["ous"].append({"dn": dn, "name": first(a, "name") or first(a, "ou") or rdn_value(dn),
                                    "description": first(a, "description") or "",
                                    "whenCreated": generalized_time(first(a, "whenCreated")),
                                    "managedBy": first(a, "managedBy"), "gPLink": first(a, "gPLink"),
                                    "city": first(a, "l"), "region": first(a, "st"), "street": first(a, "street"),
                                    "postalCode": first(a, "postalCode"), "country": first(a, "co")})
            for dn, a in self.search(base, "(|(objectClass=container)(objectClass=builtinDomain))",
                                     ["name", "description"], scope=ldap3.LEVEL):
                data["containers"].append({"dn": dn, "name": first(a, "name") or rdn_value(dn),
                                           "description": first(a, "description") or ""})
            log.info("  OU: %d, контейнеров верхнего уровня: %d", len(data["ous"]), len(data["containers"]))

        def do_users(start, width):
            for dn, a in self.search(base, USER_FILTER, USER_ATTRS, label="Пользователи", start=start, width=width):
                data["users"].append(_user(dn, a))
            log.info("  пользователей: %d", len(data["users"]))

        def do_groups(start, width):
            for dn, a in self.search(base, "(objectClass=group)", GROUP_ATTRS, label="Группы", start=start, width=width):
                data["groups"].append(_group(dn, a))
            log.info("  групп: %d", len(data["groups"]))

        def do_computers(start, width):
            for dn, a in self.search(base, "(objectClass=computer)", COMPUTER_ATTRS, label="Компьютеры",
                                     start=start, width=width):
                data["computers"].append(_computer(dn, a))
            log.info("  компьютеров: %d", len(data["computers"]))

        def do_contacts(start, width):
            for dn, a in self.search(base, "(objectClass=contact)", CONTACT_ATTRS, label="Контакты", start=start, width=width):
                data["contacts"].append({"cn": first(a, "cn"), "displayName": first(a, "displayName"),
                                         "givenName": first(a, "givenName"), "sn": first(a, "sn"),
                                         "mail": first(a, "mail"), "telephoneNumber": first(a, "telephoneNumber"),
                                         "mobile": first(a, "mobile"), "company": first(a, "company"),
                                         "department": first(a, "department"), "title": first(a, "title"),
                                         "description": first(a, "description"), "dn": dn})

        steps = [("domain", "Сведения о домене", do_domain), ("config", "Сайты, суффиксы UPN, политики", do_config),
                 ("ous", "Дерево OU", do_ous), ("users", "Пользователи", do_users), ("groups", "Группы", do_groups),
                 ("computers", "Компьютеры", do_computers), ("contacts", "Контакты", do_contacts)]
        for name, label, fn in steps:
            try:
                section(name, label, fn)
            except Cancelled:
                status = "cancelled"
                self.warnings.append(f"Сбор остановлен пользователем на разделе «{label}» — данные неполные")
                log.warning("Сбор остановлен пользователем (%s)", label)
                break
            except (ADError, LDAPSearchError) as e:
                status = "failed"
                self.errors.append(f"{label}: {e}")
                log.error("%s: %s", label, e)
                if isinstance(e, (ADTimeout, UnreachableError)):
                    break                      # связь с DC потеряна — дальше смысла нет
        result = build_result(data, c, started, time.monotonic() - t0, status, self.errors, self.warnings,
                              self.offices_ou)
        self._report(1.0, "Готово" if status == "complete" else "Сбор прерван" if status == "failed" else "Остановлено")
        return result


class LDAPSearchError(ADError):
    def __init__(self, code, description, message, base):
        self.code, self.description, self.message, self.base = code, description, message, base
        super().__init__(f"{description} ({code}) {(message or '').strip()[:200]} — {base}".replace("  ", " "))


def _days(minutes):
    return None if minutes is None else round(minutes / 1440, 2)


def _user(dn, a) -> dict:
    uac = as_int(first(a, "userAccountControl"))
    lockout = filetime(first(a, "lockoutTime"))
    u = {
        "sAMAccountName": first(a, "sAMAccountName"), "displayName": first(a, "displayName"),
        "givenName": first(a, "givenName"), "sn": first(a, "sn"), "mail": first(a, "mail"),
        "telephoneNumber": first(a, "telephoneNumber"), "title": first(a, "title"),
        "department": first(a, "department"), "office": first(a, "physicalDeliveryOfficeName"),
        "company": first(a, "company"), "manager": first(a, "manager"), "memberOf": many(a, "memberOf"), "dn": dn,
        "userAccountControl": uac, "whenCreated": generalized_time(first(a, "whenCreated")),
        "lastLogonTimestamp": filetime(first(a, "lastLogonTimestamp")),
        # дополнительно
        "userPrincipalName": first(a, "userPrincipalName"), "enabled": None if uac is None else not uac & 0x2,
        "locked": bool(lockout), "uac_flags": uac_flags(uac), "cn": first(a, "cn"), "initials": first(a, "initials"),
        "middleName": first(a, "middleName"), "description": first(a, "description"), "mobile": first(a, "mobile"),
        "ipPhone": first(a, "ipPhone"), "homePhone": first(a, "homePhone"), "fax": first(a, "facsimileTelephoneNumber"),
        "employeeID": first(a, "employeeID"), "employeeNumber": first(a, "employeeNumber"),
        "employeeType": first(a, "employeeType"), "streetAddress": first(a, "streetAddress"), "city": first(a, "l"),
        "region": first(a, "st"), "postalCode": first(a, "postalCode"), "country": first(a, "co"),
        "countryCode": first(a, "c"), "ou": parent_dn(dn), "ou_path": None, "primaryGroupID": as_int(first(a, "primaryGroupID")),
        "primaryGroup": None, "pwdLastSet": filetime(first(a, "pwdLastSet")),
        "mustChangePassword": first(a, "pwdLastSet") == "0", "accountExpires": filetime(first(a, "accountExpires")),
        "lockoutTime": lockout, "whenChanged": generalized_time(first(a, "whenChanged")),
        "objectGUID": guid_to_str((a.get("objectguid") or [None])[0]),
        "objectSid": sid_to_str((a.get("objectsid") or [None])[0]), "directReports": many(a, "directReports"),
        "homeDirectory": first(a, "homeDirectory"), "homeDrive": first(a, "homeDrive"),
        "scriptPath": first(a, "scriptPath"), "profilePath": first(a, "profilePath"), "info": first(a, "info"),
        "wWWHomePage": first(a, "wWWHomePage"), "proxyAddresses": many(a, "proxyAddresses"),
        "extensionAttributes": {f"extensionAttribute{i}": first(a, f"extensionAttribute{i}") for i in range(1, 16)
                                if first(a, f"extensionAttribute{i}")},
        "objectClass": many(a, "objectClass"),
    }
    return u


def _group(dn, a) -> dict:
    gt = as_int(first(a, "groupType"))
    category, scope = group_kind(gt)
    sid = sid_to_str((a.get("objectsid") or [None])[0])
    members = many(a, "member")
    return {"cn": first(a, "cn"), "sAMAccountName": first(a, "sAMAccountName"),
            "description": first(a, "description") or "", "members": members, "memberOf": many(a, "memberOf"),
            "groupType": None if gt is None else str(gt), "dn": dn,
            # дополнительно
            "name": first(a, "name"), "category": category, "scope": scope, "member_count": len(members),
            "mail": first(a, "mail"), "managedBy": first(a, "managedBy"), "info": first(a, "info"),
            "objectSid": sid, "rid": int(sid.rsplit("-", 1)[1]) if sid else None,
            "objectGUID": guid_to_str((a.get("objectguid") or [None])[0]),
            "whenCreated": generalized_time(first(a, "whenCreated")), "ou": parent_dn(dn), "ou_path": None}


def _computer(dn, a) -> dict:
    uac = as_int(first(a, "userAccountControl"))
    return {"cn": first(a, "cn"), "dnsHostName": first(a, "dNSHostName"),
            "operatingSystem": first(a, "operatingSystem"), "operatingSystemVersion": first(a, "operatingSystemVersion"),
            "lastLogonTimestamp": filetime(first(a, "lastLogonTimestamp")), "dn": dn,
            # дополнительно
            "sAMAccountName": first(a, "sAMAccountName"), "operatingSystemServicePack": first(a, "operatingSystemServicePack"),
            "description": first(a, "description"), "location": first(a, "location"), "managedBy": first(a, "managedBy"),
            "enabled": None if uac is None else not uac & 0x2, "userAccountControl": uac,
            "is_domain_controller": bool(uac and uac & 0x2000), "is_rodc": bool(uac and uac & 0x4000000),
            "whenCreated": generalized_time(first(a, "whenCreated")), "pwdLastSet": filetime(first(a, "pwdLastSet")),
            "memberOf": many(a, "memberOf"), "objectSid": sid_to_str((a.get("objectsid") or [None])[0]),
            "objectGUID": guid_to_str((a.get("objectguid") or [None])[0]), "ou": parent_dn(dn), "ou_path": None}


# ---------- сборка итогового JSON
def build_ou_tree(ous: list[dict], counts: dict[str, Counter], gpo_names: dict[str, str]) -> tuple[list, dict]:
    """Плоский список OU → дерево {dn, name, description, children}; возвращает (корни, dn→путь)."""
    nodes = {}
    for o in ous:
        links = [gpo_names.get(g.lower(), g) for g in _gp_links(o.get("gPLink"))]
        nodes[norm(o["dn"])] = {"dn": o["dn"], "name": o["name"], "description": o["description"], "children": [],
                                "path": None, "counts": dict(counts.get(norm(o["dn"]), Counter())),
                                "gpo_links": links, "whenCreated": o.get("whenCreated"),
                                "managedBy": o.get("managedBy"), "city": o.get("city")}
    roots = []
    for key, node in nodes.items():
        parent = nodes.get(norm(parent_dn(node["dn"])))
        (parent["children"] if parent else roots).append(node)
    paths = {}

    def walk(items, prefix):
        items.sort(key=lambda n: n["name"].casefold())
        for n in items:
            n["path"] = f"{prefix}/{n['name']}" if prefix else n["name"]
            paths[norm(n["dn"])] = n["path"]
            walk(n["children"], n["path"])
    walk(roots, "")
    return roots, paths


def _gp_links(gplink: str | None) -> list[str]:
    """'[LDAP://cn={GUID},cn=policies,...;0][...]' → ['cn={GUID},cn=policies,...']."""
    out = []
    for part in (gplink or "").split("]"):
        part = part.strip().lstrip("[")
        if part.lower().startswith("ldap://"):
            out.append(part[7:].rsplit(";", 1)[0])
    return out


def _unique(values) -> list[dict]:
    c = Counter(v.strip() for v in values if v and v.strip())
    return [{"name": k, "users": n} for k, n in sorted(c.items(), key=lambda kv: kv[0].casefold())]


def find_office_ous(ous: list[dict], override: str | None) -> list[dict]:
    if override:
        o = override.strip().casefold()
        return [x for x in ous if norm(x["dn"]) == o or x["name"].casefold() == o]
    cands = [x for x in ous if x["name"].casefold() in OFFICE_CONTAINER_NAMES]
    if not cands:
        return []
    depth = min(x["dn"].count("=") for x in cands)
    return [x for x in cands if x["dn"].count("=") == depth]


def build_result(data: dict, client, started: datetime, duration: float, status: str, errors, warnings,
                 offices_ou: str | None = None) -> dict:
    users, groups, computers, ous = data["users"], data["groups"], data["computers"], data["ous"]
    cfg = data.get("config") or {}
    gpo_names = {norm(g["dn"]): g["name"] or g["guid"] for g in cfg.get("gpos", [])}

    # сколько объектов прямо в каждой OU
    counts: dict[str, Counter] = {}
    for kind, items in (("users", users), ("groups", groups), ("computers", computers)):
        for it in items:
            counts.setdefault(norm(it["ou"]), Counter())[kind] += 1
    tree, paths = build_ou_tree(ous, counts, gpo_names)
    for it in users + groups + computers:
        it["ou_path"] = paths.get(norm(it["ou"]))

    # основная группа (её нет в memberOf) — по RID
    by_rid = {g["rid"]: g["dn"] for g in groups if g.get("rid") is not None}
    by_dn = {norm(u["dn"]): u["sAMAccountName"] for u in users}
    for u in users:
        u["primaryGroup"] = by_rid.get(u["primaryGroupID"])
        u["manager_sAMAccountName"] = by_dn.get(norm(u["manager"])) if u["manager"] else None

    # площадки: из OU-контейнера («Площадки», «Филиалы», ...), иначе — из атрибута «Офис»
    containers = find_office_ous(ous, offices_ou)
    from_ou = []
    for cont in containers:
        for child in [o for o in ous if norm(parent_dn(o["dn"])) == norm(cont["dn"])]:
            suffix = "," + norm(child["dn"])
            sub = lambda items: sum(1 for x in items if norm(x["dn"]).endswith(suffix))
            from_ou.append({"name": child["name"], "dn": child["dn"], "description": child["description"],
                            "users": sub(users), "computers": sub(computers),
                            "departments": sorted((o["name"] for o in ous if norm(parent_dn(o["dn"])) == norm(child["dn"])),
                                                  key=str.casefold)})
    from_ou.sort(key=lambda x: x["name"].casefold())
    from_attr = _unique(u["office"] for u in users)
    offices = [o["name"] for o in from_ou] if from_ou else [o["name"] for o in from_attr]
    if offices_ou and not containers:
        warnings.append(f"OU площадок «{offices_ou}» не найдена — площадки взяты из атрибута «Офис» пользователей")

    positions = _unique(u["title"] for u in users)
    enabled = sum(1 for u in users if u["enabled"])
    domain = dict(data.get("domain") or {})
    domain.update({k: cfg.get(k) for k in ("netbios_name", "forest_dns_name", "upn_suffixes") if k in cfg})
    finished = datetime.now().astimezone()
    return {
        "scan_info": {
            "domain": client.domain, "netbios_name": cfg.get("netbios_name"), "dc_address": client.address,
            "dc_hostname": client.dc_name, "base_dn": client.base_dn, "scan_date": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"), "duration_s": round(duration, 1),
            "connection": client.mode_used, "encrypted": client.encrypted, "collected_by": client.user,
            "total_users": len(users), "total_groups": len(groups), "total_ous": len(ous),
            "total_computers": len(computers), "total_contacts": len(data.get("contacts", [])),
            "enabled_users": enabled, "disabled_users": len(users) - enabled,
            "status": status, "complete": status == "complete", "errors": list(errors), "warnings": list(warnings),
            "program": f"ad-collector {__version__}",
        },
        "domain": domain,
        "ou_tree": tree,
        "users": sorted(users, key=lambda u: (u["sAMAccountName"] or "").casefold()),
        "groups": sorted(groups, key=lambda g: (g["sAMAccountName"] or g["cn"] or "").casefold()),
        "computers": sorted(computers, key=lambda c: (c["cn"] or "").casefold()),
        "contacts": data.get("contacts", []),
        "offices": offices,
        "offices_detail": {"source": "ou" if from_ou else "physicalDeliveryOfficeName" if from_attr else "none",
                           "ou_containers": [c["dn"] for c in containers], "from_ou": from_ou,
                           "from_attribute": from_attr},
        "positions": [p["name"] for p in positions],
        "positions_detail": positions,
        "departments": [d["name"] for d in _unique(u["department"] for u in users)],
        "departments_detail": _unique(u["department"] for u in users),
        "companies": [d["name"] for d in _unique(u["company"] for u in users)],
        "ad_sites": cfg.get("sites", []),
        "containers": data.get("containers", []),
        "gpos": cfg.get("gpos", []),
        "attribute_map": ATTRIBUTE_MAP,
    }


def save_json(result: dict, path: str | os.PathLike) -> Path:
    """Атомарная запись: недописанный файл не появится даже при сбое."""
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def default_filename(result: dict) -> str:
    dom = (result.get("scan_info", {}).get("domain") or "ad").replace(":", "_")
    return f"ad_structure_{dom}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
