#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
root=/etc/openclash/publisher-v4
ssh_dir=/root/.ssh
[ "$(id -u)" -eq 0 ] || exit 10
[ "$#" -eq 1 ] || exit 11
case "$1" in router_a|router_b) ;; *) exit 12;; esac
[ -f "$root/COMMITTED" ] && [ ! -L "$root" ] || exit 13
grep -qx "TARGET=$1" "$root/INSTALL-RECEIPT" || exit 13
[ "$(uci -q get openclash.config.config_path)" = /etc/openclash/config/ProviderBase-ProviderSource.yaml ] || exit 14
/etc/init.d/openclash running >/dev/null 2>&1 || exit 15
find "$root" -xdev -type l | grep -q . && exit 16
[ -f "$ssh_dir/known_hosts" ] && [ ! -L "$ssh_dir/known_hosts" ] || exit 17
[ "$(wc -l <"$ssh_dir/known_hosts" | tr -d ' ')" -eq 1 ] || exit 18
grep -q '^192\.0\.2\.20 ssh-ed25519 ' "$ssh_dir/known_hosts" || exit 19
rm -rf "$root"
rm -f "$ssh_dir/known_hosts"
rmdir "$ssh_dir" 2>/dev/null || true
printf '%s\n' 'UNINSTALL=PASS' "TARGET=$1" 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
