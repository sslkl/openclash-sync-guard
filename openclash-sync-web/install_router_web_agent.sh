#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
hold(){ printf 'ROUTER_WEB_INSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
case "$1" in router_a|router_b) target=$1;; *) hold TARGET 12;; esac
pub_file=/tmp/openclash-sync-web.pub
[ -f "$pub_file" ] && [ ! -L "$pub_file" ] || hold PUBLIC_KEY 13
pub=$(sed -n '1p' "$pub_file")
case "$pub" in ssh-ed25519\ *) ;; *) hold PUBLIC_KEY 13;; esac
[ "$(wc -l <"$pub_file" | tr -d ' ')" -eq 1 ] || hold PUBLIC_KEY 13
[ "$(printf '%s' "$pub" | wc -c | tr -d ' ')" -le 512 ] || hold PUBLIC_KEY 13
key_type=$(printf '%s\n' "$pub" | awk '{print $1}')
key_data=$(printf '%s\n' "$pub" | awk '{print $2}')
case "$key_data" in ''|*[!A-Za-z0-9+/=]*) hold PUBLIC_KEY 13;; esac
pub="$key_type $key_data"
root=/etc/openclash/publisher-v4/web
auth=/etc/dropbear/authorized_keys
[ ! -e "$root" ] || hold WEB_ROOT_EXISTS 22
agent_source=/tmp/openclash-sync-web-agent.lua
forced_source=/tmp/openclash-sync-web-forced-command.sh
customizer_source=/tmp/openclash-sync-web-customizer.rb
transaction_source=/tmp/openclash-sync-web-custom-transaction.sh
guard_source=/tmp/openclash-sync-web-custom-rollback-guard.sh
for file in "$agent_source" "$forced_source" "$customizer_source" "$transaction_source" "$guard_source" "$auth"; do [ -f "$file" ] && [ ! -L "$file" ] || hold ASSET 14; done
[ "$(ls -ln "$auth" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold AUTHORIZED_KEYS_MODE 14
lua -e 'assert(loadfile("/tmp/openclash-sync-web-agent.lua"))' || hold LUA_SYNTAX 15
/bin/sh -n "$forced_source" || hold SHELL_SYNTAX 16
ruby -c "$customizer_source" >/dev/null || hold RUBY_SYNTAX 19
/bin/sh -n "$transaction_source" || hold TRANSACTION_SYNTAX 20
/bin/sh -n "$guard_source" || hold GUARD_SYNTAX 21
grep -q 'openclash-web-router_' "$auth" && hold EXISTING_KEY 17
backup=/etc/openclash/publisher-v4/web-install-backup-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$backup"
chmod 0700 "$backup"
cp -p "$auth" "$backup/authorized_keys"
rollback(){
  cp -p "$backup/authorized_keys" "$auth" 2>/dev/null || true
  rm -rf "$root" 2>/dev/null || true
}
trap rollback EXIT HUP INT TERM
mkdir -p "$root"
chmod 0700 "$root"
cp "$agent_source" "$root/openclash_web_router_agent.lua"
cp "$forced_source" "$root/openclash_web_forced_command.sh"
cp "$customizer_source" "$root/openclash_customizer.rb"
cp "$transaction_source" "$root/openclash_custom_transaction.sh"
cp "$guard_source" "$root/openclash_custom_rollback_guard.sh"
chmod 0500 "$root/openclash_web_router_agent.lua" "$root/openclash_web_forced_command.sh" "$root/openclash_customizer.rb" "$root/openclash_custom_transaction.sh" "$root/openclash_custom_rollback_guard.sh"
entry="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,command=\"$root/openclash_web_forced_command.sh $target\" $pub openclash-web-$target"
printf '%s\n' "$entry" >>"$auth"
chmod 0600 "$auth"
[ "$(grep -c " openclash-web-$target$" "$auth")" -eq 1 ] || hold KEY_COUNT 18
trap - EXIT HUP INT TERM
rm -f "$agent_source" "$forced_source" "$customizer_source" "$transaction_source" "$guard_source" "$pub_file"
printf 'ROUTER_WEB_INSTALL=PASS\nTARGET=%s\nBACKUP=%s\n' "$target" "$backup"
