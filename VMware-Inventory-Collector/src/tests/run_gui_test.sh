#!/bin/sh
# Сквозная проверка окна (Linux + Docker): приложение запускается как обычно, но вместо окна браузера
# — заглушка, которая запоминает адрес; затем окно «открывает» headless Chromium в одноразовом контейнере.
# Параметры: VC=адрес vCenter (по умолчанию mock), VC_USER, VC_PASS, OUT=папка для отчётов и скриншотов.
set -eu
cd "$(dirname "$0")/.."
VC=${VC:-mock}; VC_USER=${VC_USER:-administrator@vsphere.local}; VC_PASS=${VC_PASS:-demo}
WORK=$(mktemp -d); OUT=${OUT:-$WORK/out}; mkdir -p "$OUT/reports" "$OUT/shots"
cat > "$WORK/fake-browser" <<'SH'
#!/bin/sh
for a in "$@"; do case "$a" in --app=*) echo "${a#--app=}" > "$FAKE_URL_FILE";; esac; done
exec sleep 600
SH
chmod +x "$WORK/fake-browser"
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 FAKE_URL_FILE=$WORK/url ZEPYGUI_BROWSER=$WORK/fake-browser XDG_CONFIG_HOME=$WORK/cfg DISPLAY= WAYLAND_DISPLAY= \
    $PY main.py --log-file "$OUT/gui.log" > "$WORK/app.out" 2>&1 &
APP=$!
trap 'kill $APP 2>/dev/null; pkill -f "$WORK/fake-browser" 2>/dev/null; true' EXIT
for i in $(seq 50); do [ -s "$WORK/url" ] && break; sleep 0.2; done
URL=$(cat "$WORK/url")
echo "Окно: ${URL%%\?*}"
docker run --rm --network host --memory 768m -v "$PWD/tests/gui_e2e.js:/e2e/gui_e2e.js:ro" -v "$OUT/shots:/shots" \
    node:22-alpine sh -c "apk upgrade -q --no-cache >/dev/null && apk add -q --no-cache chromium font-noto >/dev/null && cd /e2e && npm i -s puppeteer-core@23.11.1 >/dev/null 2>&1 && \
    node gui_e2e.js '$URL' '$VC' '$VC_USER' '$VC_PASS' '$OUT/reports' /shots" && RC=0 || RC=$?
kill -0 $APP 2>/dev/null || { echo "Приложение завершилось во время теста:"; tail -40 "$WORK/app.out"; }
echo "Отчёты: $(ls "$OUT/reports")"; echo "Скриншоты: $OUT/shots"
exit $RC
