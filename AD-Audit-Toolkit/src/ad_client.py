"""Подключение к контроллеру домена Active Directory (ldap3): LDAPS / StartTLS / LDAP, понятные ошибки."""
from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import struct

import ldap3
from ldap3.core import exceptions as lx

log = logging.getLogger("ad_collector.client")

SECURITY_MODES = {
    "auto": "Авто (LDAPS → StartTLS → NTLM)",
    "ldaps": "LDAPS, порт 636",
    "starttls": "StartTLS, порт 389",
    "plain": "Без шифрования, порт 389",
}
ROOT_DSE_ATTRS = ["defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
                  "rootDomainNamingContext", "dnsHostName", "serverName", "domainFunctionality",
                  "forestFunctionality", "domainControllerFunctionality", "isGlobalCatalogReady", "currentTime"]

# коды из сообщения AD при ошибке входа: «... AcceptSecurityContext error, data 52e, ...»
BIND_DATA_CODES = {
    "525": "Пользователь не найден",
    "52e": "Неверный логин или пароль",
    "530": "Вход в это время запрещён",
    "531": "Вход с этого компьютера запрещён",
    "532": "Срок действия пароля истёк",
    "533": "Учётная запись отключена",
    "701": "Срок действия учётной записи истёк",
    "773": "Нужно сменить пароль при следующем входе",
    "775": "Учётная запись заблокирована",
}


class ADError(Exception):
    """Ошибка, текст которой можно показать пользователю."""


class AuthError(ADError):
    pass


class UnreachableError(ADError):
    pass


class ADTimeout(ADError):
    pass


class TLSFailure(ADError):
    pass


class StrongAuthRequired(ADError):
    pass


# --- MD4 для NTLM: в OpenSSL 3 (свежие Python на Windows и Linux) его нет, а ldap3 без него не умеет NTLM
def md4(data: bytes) -> bytes:
    """MD4 по RFC 1320 (нужен только для NTLM-хеша пароля)."""
    def rotl(v, s):
        v &= 0xFFFFFFFF
        return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF
    rounds = (
        (lambda x, y, z: (x & y) | (~x & z), 0, list(range(16)), (3, 7, 11, 19)),
        (lambda x, y, z: (x & y) | (x & z) | (y & z), 0x5A827999,
         [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15], (3, 5, 9, 13)),
        (lambda x, y, z: x ^ y ^ z, 0x6ED9EBA1, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15], (3, 9, 11, 15)),
    )
    msg = bytearray(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64) + struct.pack("<Q", (len(data) * 8) & 0xFFFFFFFFFFFFFFFF)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        v = list(h)
        for fn, const, order, shifts in rounds:
            for i, k in enumerate(order):
                t = (-i) % 4                     # a, d, c, b, a, d, ...
                v[t] = rotl(v[t] + fn(v[(t + 1) % 4], v[(t + 2) % 4], v[(t + 3) % 4]) + x[k] + const, shifts[i % 4])
        h = [(a + b) & 0xFFFFFFFF for a, b in zip(h, v)]
    return struct.pack("<4I", *h)


class _Md4:
    def __init__(self, data=b""):
        self._data = bytes(data)

    def update(self, data):
        self._data += bytes(data)

    def digest(self):
        return md4(self._data)

    def hexdigest(self):
        return self.digest().hex()


class _HashlibWithMd4:
    """Подменяет hashlib только внутри ldap3.utils.ntlm: всё как обычно, плюс MD4."""
    def __getattr__(self, name):
        return getattr(hashlib, name)

    @staticmethod
    def new(name, data=b"", **kw):
        try:
            return hashlib.new(name, data, **kw)
        except ValueError:
            if name.lower() == "md4":
                return _Md4(data)
            raise


def _enable_ntlm():
    try:
        hashlib.new("md4")
    except ValueError:
        from ldap3.utils import ntlm
        if not isinstance(ntlm.hashlib, _HashlibWithMd4):
            ntlm.hashlib = _HashlibWithMd4()


# --- разбор ответов
def raw_str(values) -> str | None:
    if not values:
        return None
    v = values[0]
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def split_address(address: str) -> tuple[str, int | None]:
    """'dc01', 'dc01:3268', '10.0.0.5', '[fe80::1]:636', 'ldaps://dc01' → (хост, порт или None)."""
    a = address.strip()
    for prefix in ("ldaps://", "ldap://"):
        if a.lower().startswith(prefix):
            a = a[len(prefix):]
    a = a.rstrip("/")
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if a.count(":") == 1:
        host, port = a.split(":")
        if not port.isdigit():
            raise ADError(f"Неверный порт в адресе: {address}")
        return host, int(port)
    return a, None


def login_kind(user: str) -> str:
    """'DOMAIN\\user' → ntlm; 'user@domain' или DN → simple; просто 'user' → bare (допишем домен)."""
    if "\\" in user:
        return "ntlm"
    if "@" in user or "=" in user:
        return "simple"
    return "bare"


def bind_error_text(result: dict) -> tuple[type[ADError], str]:
    code, msg = result.get("result"), result.get("message") or ""
    if code == 49:
        low = msg.lower()
        for data, text in BIND_DATA_CODES.items():
            if f"data {data}" in low:
                return AuthError, text
        return AuthError, "Неверный логин или пароль"
    if code in (8, 13):
        return StrongAuthRequired, ("Контроллер домена требует защищённого подключения (подпись LDAP). "
                                    "Выберите LDAPS/StartTLS или войдите как ДОМЕН\\пользователь (NTLM)")
    return ADError, f"Вход не выполнен: {result.get('description')} {msg}".strip()


def transport_error(exc: Exception, host: str, port: int, timeout: float | None) -> ADError:
    text = str(exc)
    low = text.lower()
    if "certificate" in low or "ssl" in low and "verify" in low:
        return TLSFailure(f"Сертификат контроллера домена не прошёл проверку ({text[:160]}). "
                          "Выключите «Проверять сертификат» или установите корневой сертификат домена")
    if "timed out" in low or "timeout" in low:
        return ADTimeout(f"Контроллер домена {host}:{port} не ответил вовремя"
                         + (f" (таймаут {timeout:g} с)" if timeout else ""))
    if "refused" in low:
        return UnreachableError(f"Контроллер домена {host}:{port} недоступен: соединение отклонено")
    if isinstance(exc, (lx.LDAPSocketReceiveError, lx.LDAPSessionTerminatedByServerError)):
        return UnreachableError(f"Контроллер домена {host}:{port} разорвал соединение")
    if "ssl" in low or "tls" in low or "handshake" in low:
        return TLSFailure(f"Не удалось установить TLS с {host}:{port}: {text[:160]}")
    return UnreachableError(f"Контроллер домена {host}:{port} недоступен: {text[:200]}")


def dn_to_domain(dn: str) -> str:
    return ".".join(p.split("=", 1)[1] for p in dn.split(",") if p.strip().lower().startswith("dc="))


class ADClient:
    """Подключение с учёткой только на чтение. После connect(): conn, base_dn, domain, root_dse, mode_used."""

    def __init__(self, address: str, user: str, password: str, security: str = "auto", verify_cert: bool = False,
                 connect_timeout: float = 10, receive_timeout: float = 60, base_dn: str | None = None):
        if security not in SECURITY_MODES:
            raise ADError(f"Неизвестный режим защиты: {security}")
        self.address, self.user, self.password = address.strip(), user.strip(), password
        self.security, self.verify_cert = security, verify_cert
        self.connect_timeout, self.receive_timeout = connect_timeout, receive_timeout
        self.base_dn_override = (base_dn or "").strip() or None
        self.conn: ldap3.Connection | None = None
        self.root_dse: dict = {}
        self.base_dn = self.domain = self.mode_used = None
        self.host, self.port = None, None

    def __repr__(self):
        return f"ADClient({self.address!r}, user={self.user!r}, security={self.security!r})"

    @property
    def connected(self) -> bool:
        return bool(self.conn and self.conn.bound)

    def _check_input(self):
        if not self.address:
            raise ADError("Укажите адрес контроллера домена")
        if not self.user:
            raise ADError("Укажите логин")
        if not self.password:   # пустой пароль AD принимает как анонимный вход — не допускаем
            raise ADError("Укажите пароль")

    def _plan(self, kind: str, explicit_port: int | None) -> list[tuple[str, int]]:
        if self.security == "auto":
            modes = ["ldaps", "starttls"] + ([] if self.verify_cert or kind != "ntlm" else ["plain"])
        else:
            modes = [self.security]
            if self.security == "plain" and kind != "ntlm":
                log.warning("Режим без шифрования и вход не NTLM: пароль уйдёт по сети открытым текстом")
        default = {"ldaps": 636, "starttls": 389, "plain": 389}
        return [(m, explicit_port or default[m]) for m in modes]

    def _tls(self):
        return ldap3.Tls(validate=ssl.CERT_REQUIRED if self.verify_cert else ssl.CERT_NONE)

    def _open(self, mode: str, port: int) -> ldap3.Connection:
        server = ldap3.Server(self.host, port=port, use_ssl=(mode == "ldaps"), tls=self._tls(),
                              get_info=ldap3.NONE, connect_timeout=self.connect_timeout)
        conn = ldap3.Connection(server, receive_timeout=self.receive_timeout, auto_referrals=False,
                                read_only=True, raise_exceptions=False, check_names=False, auto_range=True)
        try:
            conn.open()
            if mode == "starttls" and not conn.start_tls():
                raise TLSFailure(f"Контроллер домена не поддерживает StartTLS: {conn.result.get('message') or ''}")
        except lx.LDAPException as e:
            conn.unbind()
            raise transport_error(e, self.host, port, None) from e
        except ADError:
            conn.unbind()
            raise
        return conn

    def _read_root_dse(self, conn) -> dict:
        try:
            conn.search("", "(objectClass=*)", ldap3.BASE, attributes=ROOT_DSE_ATTRS)
        except lx.LDAPException as e:
            raise transport_error(e, self.host, self.port, self.receive_timeout) from e
        for e in conn.response or []:
            if e.get("type") == "searchResEntry":
                return {k: [v.decode("utf-8", "replace") for v in vals] for k, vals in e["raw_attributes"].items()}
        return {}

    def _bind(self, conn, kind: str, mode: str):
        user = self.user
        if kind == "bare":   # «ivanov» → «ivanov@домен» (имя домена — из rootDSE, его можно читать без входа)
            dse = self._read_root_dse(conn)
            dom = dn_to_domain((dse.get("defaultNamingContext") or [""])[0])
            if not dom:
                raise ADError("Не удалось определить домен — укажите логин как user@домен или ДОМЕН\\user")
            user = f"{self.user}@{dom}"
        conn.user, conn.password = user, self.password
        # внутри TLS — обычный вход (AD принимает и «ДОМЕН\\user»); NTLM — только без шифрования, чтобы не слать пароль открыто
        ntlm = kind == "ntlm" and mode == "plain"
        conn.authentication = ldap3.NTLM if ntlm else ldap3.SIMPLE
        if ntlm:
            _enable_ntlm()
        try:
            ok = conn.bind()
        except lx.LDAPException as e:
            raise transport_error(e, self.host, self.port, self.receive_timeout) from e
        if not ok:
            cls, text = bind_error_text(conn.result)
            log.warning("Вход не выполнен (%s): %s %s", user, conn.result.get("description"),
                        (conn.result.get("message") or "")[:200])
            raise cls(text)
        return user

    def connect(self) -> "ADClient":
        self._check_input()
        host, explicit_port = split_address(self.address)
        self.host = host
        try:
            socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            raise UnreachableError(f"Имя «{host}» не найдено в DNS") from e
        kind = login_kind(self.user)
        plan = self._plan(kind, explicit_port)
        last: ADError | None = None
        for mode, port in plan:
            self.port = port
            log.info("Подключение к %s:%s (%s), вход: %s", host, port, mode, self.user)
            try:
                conn = self._open(mode, port)
            except (UnreachableError, TLSFailure, ADTimeout) as e:
                log.warning("  %s", e)
                last = e
                if self.security == "auto" and not (isinstance(e, TLSFailure) and self.verify_cert):
                    continue
                raise
            try:
                user = self._bind(conn, kind, mode)
                dse = self._read_root_dse(conn)
            except BaseException:
                conn.unbind()
                raise
            self.conn, self.root_dse, self.mode_used = conn, dse, mode
            self.base_dn = self.base_dn_override or (dse.get("defaultNamingContext") or [""])[0]
            if not self.base_dn:
                self.close()
                raise ADError("Контроллер не сообщил DN домена (defaultNamingContext) — укажите его вручную")
            self.domain = dn_to_domain(self.base_dn)
            log.info("Подключено: %s как %s, режим %s, домен %s", self.dc_name, user, mode, self.domain)
            return self
        if self.security == "auto" and kind != "ntlm" and isinstance(last, TLSFailure):
            raise type(last)(f"{last}. Шифрованное подключение (LDAPS/StartTLS) не удалось; без шифрования программа "
                             "сама не подключается: войдите как ДОМЕН\\пользователь (NTLM) или выберите режим явно")
        raise last or ADError("Не удалось подключиться")

    @property
    def dc_name(self) -> str:
        return (self.root_dse.get("dnsHostName") or [self.host])[0]

    @property
    def encrypted(self) -> bool:
        return self.mode_used in ("ldaps", "starttls")

    def close(self):
        if self.conn:
            try:
                self.conn.unbind()
            except Exception:
                pass
        self.conn = None
