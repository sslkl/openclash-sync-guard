#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
hold(){ printf 'WORKER_WEB_INSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
source=/tmp/openclash-sync-web-deploy
app=/opt/openclash-sync-web
helper=/usr/local/sbin/openclash-web-helper
service=/etc/systemd/system/openclash-sync-web.service
sudoers=/etc/sudoers.d/openclash-sync-web
keys=/etc/openclash-web
for path in "$app" "$helper" "$service" "$sudoers" "$keys"; do [ ! -e "$path" ] || hold TARGET_EXISTS 11; done
for file in server.py openclash_web_helper.py openclash-sync-web.service auth-ha1 router_a router_b known_hosts; do [ -f "$source/$file" ] && [ ! -L "$source/$file" ] || hold ASSET 12; done
for file in static/index.html static/app.css static/app.js; do [ -f "$source/$file" ] && [ ! -L "$source/$file" ] || hold STATIC_ASSET 13; done
python3 -m py_compile "$source/server.py" "$source/openclash_web_helper.py" || hold PYTHON_SYNTAX 14
python3 -c 'import yaml; assert yaml.__version__ == "6.0.2"' || hold PYYAML 15
systemd-analyze verify "$source/openclash-sync-web.service" >/dev/null 2>&1 || hold SERVICE_UNIT 16
visudo -cf /dev/null >/dev/null 2>&1 || true
ss -ltn | awk 'NR>1 {print $4}' | grep -q ':8088$' && hold PORT_IN_USE 17
rollback(){
  systemctl disable --now openclash-sync-web.service >/dev/null 2>&1 || true
  rm -f "$service" "$sudoers" "$helper"
  rm -rf "$app" "$keys"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap rollback EXIT HUP INT TERM
mkdir -p "$app/static" "$keys/keys"
chmod 0755 "$app" "$app/static"
chmod 0700 "$keys" "$keys/keys"
install -m 0555 -o root -g root "$source/server.py" "$app/server.py"
auth_lines=$(wc -l < "$source/auth-ha1" | tr -d ' ')
case "$auth_lines" in
  1) grep -Eq '^[0-9a-f]{64}$' "$source/auth-ha1" || hold AUTH_HA1 23 ;;
  2) grep -Eq '^sha256:[0-9a-f]{64}$' "$source/auth-ha1" && grep -Eq '^md5:[0-9a-f]{32}$' "$source/auth-ha1" || hold AUTH_HA1 23 ;;
  *) hold AUTH_HA1 23 ;;
esac
install -m 0440 -o root -g syncsvc "$source/auth-ha1" "$app/auth-ha1"
install -m 0444 -o root -g root "$source/static/index.html" "$app/static/index.html"
install -m 0444 -o root -g root "$source/static/app.css" "$app/static/app.css"
install -m 0444 -o root -g root "$source/static/app.js" "$app/static/app.js"
install -m 0555 -o root -g root "$source/openclash_web_helper.py" "$helper"
install -m 0600 -o root -g root "$source/router_a" "$keys/keys/router_a"
install -m 0600 -o root -g root "$source/router_b" "$keys/keys/router_b"
install -m 0600 -o root -g root "$source/known_hosts" "$keys/known_hosts"
install -m 0644 -o root -g root "$source/openclash-sync-web.service" "$service"
printf '%s\n' 'syncsvc ALL=(root) NOPASSWD: /usr/local/sbin/openclash-web-helper' >"$sudoers"
chmod 0440 "$sudoers"
visudo -cf "$sudoers" >/dev/null || hold SUDOERS 18
systemctl daemon-reload
systemctl enable --now openclash-sync-web.service >/dev/null
sleep 1
systemctl is-active --quiet openclash-sync-web.service || hold SERVICE_START 19
python3 - <<'PY'
import json, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open('http://192.0.2.20:8088/healthz', timeout=5) as response:
    assert response.status == 200 and json.load(response) == {'ok': True}
PY
trap - EXIT HUP INT TERM
rm -rf "$source"
printf '%s\n' 'WORKER_WEB_INSTALL=PASS' 'LISTEN=192.0.2.20:8088' 'SERVICE=ACTIVE' 'FIREWALL_CHANGED=false'
