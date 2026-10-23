"""Крошечный LDAP-сервер, который ведёт себя как Active Directory в двух важных местах:

* MaxPageSize = 1000: без постраничного поиска отдаёт 1000 записей и sizeLimitExceeded;
* MaxValRange = 1500: большой атрибут member отдаёт кусками «member;range=0-1499», «member;range=1500-*»...

Нужен для тестов (ни Samba, ни ldap3-mock так не делают). Понимает bind, поиск, unbind.
"""
from __future__ import annotations

import socket
import threading

from ldap3.protocol import rfc4511
from ldap3.protocol.rfc2696 import RealSearchControlValue
from ldap3.protocol.rfc4511 import (BindResponse, Control, Controls, LDAPMessage, PartialAttribute,
                                    PartialAttributeList, ProtocolOp, ResultCode, SearchResultDone,
                                    SearchResultEntry, Vals)
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import namedtype, univ

PAGED = "1.2.840.113556.1.4.319"
MAX_PAGE, MAX_RANGE = 1000, 1500
BASE = "DC=fake,DC=local"


# ldap3 описывает Filter так, что pyasn1 не может разобрать вложенный (!(...)) — фильтр берём как сырые байты
def _replace(named_types, name, new):
    return namedtype.NamedTypes(*[
        (namedtype.OptionalNamedType if isinstance(n, namedtype.OptionalNamedType) else namedtype.NamedType)(
            n.name, new if n.name == name else n.asn1Object) for n in named_types.namedTypes])


class _SearchRequest(univ.Sequence):
    tagSet = rfc4511.SearchRequest.tagSet
    componentType = _replace(rfc4511.SearchRequest.componentType, "filter", univ.Any())


class _ProtocolOp(univ.Choice):
    componentType = _replace(rfc4511.ProtocolOp.componentType, "searchRequest", _SearchRequest())


class _Request(univ.Sequence):
    componentType = _replace(rfc4511.LDAPMessage.componentType, "protocolOp", _ProtocolOp())


def build_directory(n_users=2500, n_big=3200):
    users = [(f"CN=User {i:05d},OU=Staff,{BASE}",
              {"objectClass": ["top", "person", "user"], "sAMAccountName": [f"u{i:05d}"], "title": [f"Должность {i % 7}"],
               "physicalDeliveryOfficeName": [["Тверь", "Омск"][i % 2]], "userAccountControl": ["512"]})
             for i in range(n_users)]
    big = (f"CN=Big Group,OU=Staff,{BASE}", {"objectClass": ["top", "group"], "cn": ["Big Group"],
                                             "sAMAccountName": ["Big_Group"], "groupType": ["-2147483646"],
                                             "member": [u[0] for u in users[:n_big]] +
                                                       [f"CN=Ext {i},{BASE}" for i in range(max(0, n_big - n_users))]})
    small = (f"CN=Small,OU=Staff,{BASE}", {"objectClass": ["top", "group"], "cn": ["Small"], "sAMAccountName": ["Small"],
                                           "groupType": ["2"], "member": [users[0][0]]})
    domain = (BASE, {"objectClass": ["top", "domain"], "name": ["fake"], "minPwdLength": ["10"]})
    return {"users": users, "groups": [big, small], "domain": domain}


class FakeAD:
    def __init__(self, directory=None, password="pass"):
        self.dir = directory or build_directory()
        self.password = password
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.searches: list[dict] = []
        self._pages: dict[bytes, list] = {}
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self):
        self._stop = True
        self.sock.close()

    # --- сеть
    def _serve(self):
        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(c,), daemon=True).start()

    def _client(self, c):
        buf = b""
        with c:
            while True:
                try:
                    data = c.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                buf += data
                while buf:
                    try:
                        msg, rest = decoder.decode(buf, asn1Spec=_Request())
                    except SubstrateUnderrunError:
                        break
                    buf = rest
                    out = self._handle(msg)
                    if out is None:
                        return
                    c.sendall(b"".join(out))

    # --- кодирование ответов
    @staticmethod
    def _msg(mid, name, op, controls=None):
        m = LDAPMessage()
        m["messageID"] = mid
        po = ProtocolOp()
        po.setComponentByName(name, op)
        m["protocolOp"] = po
        if controls is not None:
            m["controls"] = controls
        return encoder.encode(m)

    @staticmethod
    def _done(cls, code, text=""):
        r = cls()
        r["resultCode"] = ResultCode(code)
        r["matchedDN"] = ""
        r["diagnosticMessage"] = text
        return r

    def _entry(self, mid, dn, attrs):
        e = SearchResultEntry()
        e["object"] = dn
        pal = PartialAttributeList()
        for i, (k, vals) in enumerate(attrs.items()):
            pa = PartialAttribute()
            pa["type"] = k
            v = Vals()
            for j, x in enumerate(vals):
                v.setComponentByPosition(j, x.encode() if isinstance(x, str) else x)
            pa["vals"] = v
            pal.setComponentByPosition(i, pa)
        e["attributes"] = pal
        return self._msg(mid, "searchResEntry", e)

    def _page_control(self, cookie: bytes):
        v = RealSearchControlValue()
        v["size"] = 0
        v["cookie"] = cookie
        ctl = Control()
        ctl["controlType"] = PAGED
        ctl["controlValue"] = encoder.encode(v)
        ctls = Controls()
        ctls.setComponentByPosition(0, ctl)
        return ctls

    # --- логика
    def _handle(self, msg):
        mid = int(msg["messageID"])
        op = msg["protocolOp"]
        name = op.getName()
        if name == "unbindRequest":
            return None
        if name == "bindRequest":
            pw = bytes(op[name]["authentication"]["simple"]).decode()
            ok = pw == self.password
            return [self._msg(mid, "bindResponse", self._done(
                BindResponse, "success" if ok else "invalidCredentials",
                "" if ok else "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"))]
        if name != "searchRequest":
            return [self._msg(mid, "searchResDone", self._done(SearchResultDone, "unwillingToPerform"))]
        sr = op[name]
        req = {"base": str(sr["baseObject"]), "scope": int(sr["scope"]), "filter": bytes(sr["filter"]),
               "attributes": [str(a) for a in sr["attributes"]]}
        self.searches.append(req)
        paged = None
        if msg["controls"].isValue:
            for ctl in msg["controls"]:
                if str(ctl["controlType"]) == PAGED:
                    paged, _ = decoder.decode(bytes(ctl["controlValue"]), asn1Spec=RealSearchControlValue())
        objs = self._select(req)
        if objs is None:
            return [self._msg(mid, "searchResDone", self._done(SearchResultDone, "noSuchObject", "0000208D: no such object"))]
        objs = [(dn, self._project(a, req["attributes"])) for dn, a in objs]
        out, controls, code = [], None, "success"
        if paged is not None:
            size = min(int(paged["size"]) or MAX_PAGE, MAX_PAGE)
            cookie = bytes(paged["cookie"])
            remaining = self._pages.pop(cookie, None) if cookie else objs
            if remaining is None:
                return [self._msg(mid, "searchResDone", self._done(SearchResultDone, "unwillingToPerform", "bad cookie"))]
            page, rest = remaining[:size], remaining[size:]
            nxt = b""
            if rest:
                nxt = f"c{mid}-{len(rest)}".encode()
                self._pages[nxt] = rest
            controls = self._page_control(nxt)
        else:
            page = objs[:MAX_PAGE]
            if len(objs) > MAX_PAGE:
                code = "sizeLimitExceeded"
        out += [self._entry(mid, dn, a) for dn, a in page]
        out.append(self._msg(mid, "searchResDone", self._done(SearchResultDone, code), controls))
        return out

    def _select(self, req):
        base, flt, scope = req["base"].lower(), req["filter"], req["scope"]
        if base == "" and scope == 0:
            return [("", {"defaultNamingContext": [BASE], "dnsHostName": ["dc.fake.local"]})]
        everything = self.dir["users"] + self.dir["groups"] + [self.dir["domain"]]
        if scope == 0:
            return [o for o in everything if o[0].lower() == base] or None
        if not base.endswith(BASE.lower()):
            return None
        if b"group" in flt:
            return list(self.dir["groups"])
        if b"user" in flt and b"computer" in flt:      # (&(objectClass=user)(!(objectClass=computer)))
            return list(self.dir["users"])
        return []

    @staticmethod
    def _project(attrs, wanted):
        out = {}
        for w in wanted:
            name, _, rng = w.partition(";range=")
            vals = next((v for k, v in attrs.items() if k.lower() == name.lower()), None)
            if vals is None:
                continue
            if name.lower() == "member" and (rng or len(vals) > MAX_RANGE):
                lo = int(rng.split("-")[0]) if rng else 0
                chunk = vals[lo:lo + MAX_RANGE]
                hi = "*" if lo + MAX_RANGE >= len(vals) else str(lo + MAX_RANGE - 1)
                out[f"member;range={lo}-{hi}"] = chunk     # как AD: данные только под именем с ;range=
            else:
                out[name] = vals
        return out
