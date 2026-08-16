#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'WORKER_WEB_UPDATE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
source=/tmp/openclash-sync-web-deploy
app=/opt/openclash-sync-web
helper=/usr/local/sbin/openclash-web-helper
service=/etc/systemd/system/openclash-sync-web.service
sudoers=/etc/sudoers.d/openclash-sync-web
[ -d "$app" ] && [ ! -L "$app" ] && [ -d "$app/static" ] && [ ! -L "$app/static" ] || hold INSTALLED_ASSET 11
for path in "$helper" "$service" "$sudoers"; do [ -f "$path" ] && [ ! -L "$path" ] || hold INSTALLED_ASSET 11; done
for file in server.py openclash_web_helper.py openclash-sync-web.service auth-ha1; do [ -f "$source/$file" ] && [ ! -L "$source/$file" ] || hold SOURCE_ASSET 12; done
for file in static/index.html static/app.css static/app.js; do [ -f "$source/$file" ] && [ ! -L "$source/$file" ] || hold STATIC_ASSET 13; done
python3 -B - <<PY
from pathlib import Path
for name in ("$source/server.py", "$source/openclash_web_helper.py"):
    compile(Path(name).read_bytes(), name, "exec")
PY
python3 -c 'import yaml; assert yaml.__version__ == "6.0.2"' || hold PYYAML 15
systemd-analyze verify "$source/openclash-sync-web.service" >/dev/null 2>&1 || hold SERVICE_UNIT 16
auth_lines=$(wc -l < "$source/auth-ha1" | tr -d ' ')
case "$auth_lines" in
  1) grep -Eq '^[0-9a-f]{64}$' "$source/auth-ha1" || hold AUTH_HA1 17 ;;
  2) grep -Eq '^sha256:[0-9a-f]{64}$' "$source/auth-ha1" && grep -Eq '^md5:[0-9a-f]{32}$' "$source/auth-ha1" || hold AUTH_HA1 17 ;;
  *) hold AUTH_HA1 17 ;;
esac
backup=/opt/openclash-sync-web-update-backup-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir "$backup"
chmod 0700 "$backup"
cp -a "$app" "$backup/app"
cp -p "$helper" "$backup/helper"
cp -p "$service" "$backup/service"
rollback(){
  systemctl stop openclash-sync-web.service >/dev/null 2>&1 || true
  rm -rf "$app"
  cp -a "$backup/app" "$app"
  cp -p "$backup/helper" "$helper"
  cp -p "$backup/service" "$service"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl start openclash-sync-web.service >/dev/null 2>&1 || true
}
trap rollback EXIT HUP INT TERM
install -m 0555 -o root -g root "$source/server.py" "$app/server.py"
install -m 0440 -o root -g syncsvc "$source/auth-ha1" "$app/auth-ha1"
install -m 0444 -o root -g root "$source/static/index.html" "$app/static/index.html"
install -m 0444 -o root -g root "$source/static/app.css" "$app/static/app.css"
install -m 0444 -o root -g root "$source/static/app.js" "$app/static/app.js"
install -m 0555 -o root -g root "$source/openclash_web_helper.py" "$helper"
install -m 0644 -o root -g root "$source/openclash-sync-web.service" "$service"
systemctl daemon-reload
systemctl restart openclash-sync-web.service
attempt=0
healthy=false
while [ "$attempt" -lt 20 ]; do
  attempt=$((attempt+1))
  if systemctl is-active --quiet openclash-sync-web.service && python3 - <<'PY' 2>/dev/null
import json, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open('http://192.0.2.20:8088/healthz', timeout=3) as response:
    assert response.status == 200 and json.load(response) == {'ok': True}
PY
  then
    healthy=true
    break
  fi
  sleep 1
done
[ "$healthy" = true ] || hold HEALTH 19
ss -ltn | awk 'NR>1 {print $4}' | grep -qx '192.0.2.20:8088' || hold LISTEN 20
trap - EXIT HUP INT TERM
rm -rf "$source"
printf '%s\n' 'WORKER_WEB_UPDATE=PASS' 'LISTEN=192.0.2.20:8088' 'SERVICE=ACTIVE' "BACKUP=$backup" 'FIREWALL_CHANGED=false'
