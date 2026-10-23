#!/bin/sh
# Запуск тестов. На Linux под root — в отдельном сетевом пространстве имён (unshare -n):
# имитация устройств занимает стандартные порты (22, 445, 9100…) на 127.0.0.x, не мешая
# настоящим службам и не отправляя ни одного пакета в реальную сеть.
cd "$(dirname "$0")/.." || exit 1
PY=${PYTHON:-python3}
[ -x .venv/bin/python ] && PY=.venv/bin/python
if [ "$(id -u)" = 0 ] && command -v unshare >/dev/null 2>&1 && [ -z "$VCSIM_URL" ]; then
    exec unshare -n sh -c "ip link set lo up && exec $PY -m unittest discover -s tests -v"
fi
exec $PY -m unittest discover -s tests -v
