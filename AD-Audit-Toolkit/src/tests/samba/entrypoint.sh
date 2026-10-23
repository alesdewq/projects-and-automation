#!/bin/bash
# Поднимает домен COMPANY.LOCAL (если ещё не поднят) и запускает samba на переднем плане.
set -e
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision --realm=COMPANY.LOCAL --domain=COMPANY --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="${ADMIN_PASS:-Adm1n-Pass!2026}" --use-rfc2307 \
    --option="dns forwarder = 127.0.0.1" --option="ldap server require strong auth = no"
fi
exec samba -i -M single --debug-stdout
