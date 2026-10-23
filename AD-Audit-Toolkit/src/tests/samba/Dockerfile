# Тестовый контроллер домена Samba AD (совместим с Active Directory по LDAP) + Python/tkinter/Xvfb для проверки окна.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision winbind krb5-user ldb-tools python3 python3-venv python3-tk xvfb x11-apps imagemagick \
      fonts-dejavu-core ca-certificates iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
