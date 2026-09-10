#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'ROUTER_ASSET_ROLLBACK=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 2 ] || hold ARGS 11
target=$1
deployment_id=$2
case "$target" in router_a|router_b) ;; *) hold TARGET 11;; esac
case "$deployment_id" in *[!0-9A-Z-]*|'') hold DEPLOYMENT_ID 11;; esac
[ "${#deployment_id}" -ge 8 ] && [ "${#deployment_id}" -le 48 ] || hold DEPLOYMENT_ID 11

root=/etc/openclash/publisher-v4
bin=$root/bin
backup=$root/backups/router-assets-$target-$deployment_id
builder=openclash_router_stage_builder.rb
client=openclash_router_stage_client.sh
audit_script=router-openclash-sync-capability-audit.sh
uci_digest(){
  uci_value=$(uci -q show openclash) || return 1
  printf '%s' "$uci_value" | sha256sum | awk '{print $1}'
  unset uci_value
}

[ -d "$root" ] && [ ! -L "$root" ] && [ -d "$bin" ] && [ ! -L "$bin" ] || hold PUBLISHER_ROOT 12
[ -d "$backup" ] && [ ! -L "$backup" ] || hold BACKUP 13
[ "$(ls -ldn "$backup" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold BACKUP_MODE 13
[ -f "$backup/COMMITTED" ] && [ ! -L "$backup/COMMITTED" ] || hold COMMITTED 13
[ "$(ls -ln "$backup/COMMITTED" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold COMMITTED_MODE 13
[ ! -e "$backup/ROLLBACK-COMMITTED" ] || hold ALREADY_ROLLED_BACK 13
[ ! -e "$backup/rollback-current" ] || hold ROLLBACK_STATE_EXISTS 13
find "$root" -xdev -type l | grep -q . && hold PUBLISHER_SYMLINK 14
(cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1) || hold BACKUP_HASH 15

receipt_value(){
  key=$1
  value=$(sed -n "s/^$key=//p" "$backup/COMMITTED")
  [ "$(printf '%s\n' "$value" | wc -l | tr -d ' ')" -eq 1 ] || return 1
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}
audit_before=$(receipt_value AUDIT_PRESENT_BEFORE) || hold RECEIPT 16
case "$audit_before" in true|false) ;; *) hold RECEIPT 16;; esac
builder_expected=$(receipt_value BUILDER_AFTER_SHA256) || hold RECEIPT 16
client_expected=$(receipt_value CLIENT_AFTER_SHA256) || hold RECEIPT 16
audit_expected=$(receipt_value AUDIT_AFTER_SHA256) || hold RECEIPT 16
uci_expected=$(receipt_value UCI_SHA256) || hold RECEIPT 16
active_expected=$(receipt_value ACTIVE_PATH_SHA256) || hold RECEIPT 16
pid_expected=$(receipt_value CORE_PID) || hold RECEIPT 16
for digest in "$builder_expected" "$client_expected" "$audit_expected" "$uci_expected" "$active_expected"; do
  case "$digest" in *[!0-9a-f]*|'') hold RECEIPT 16;; esac
  [ "${#digest}" -eq 64 ] || hold RECEIPT 16
done
case "$pid_expected" in ''|*[!0-9]*) hold RECEIPT 16;; esac

exec 9>"$root/stage.lock"
flock -n 9 || hold LOCK 17
for pair in "$builder:$builder_expected" "$client:$client_expected" "$audit_script:$audit_expected"; do
  file=${pair%%:*}
  expected=${pair#*:}
  [ -f "$bin/$file" ] && [ ! -L "$bin/$file" ] || hold CURRENT_ASSET 18
  [ "$(sha256sum "$bin/$file" | awk '{print $1}')" = "$expected" ] || hold CURRENT_DRIFT 18
done
uci_current=$(uci_digest) || hold UCI 18
active_current=$(uci -q get openclash.config.config_path || true)
[ "$uci_current" = "$uci_expected" ] || hold UCI_DRIFT 18
[ "$(printf '%s' "$active_current" | sha256sum | awk '{print $1}')" = "$active_expected" ] || hold ACTIVE_DRIFT 18
[ "$(pidof clash_meta 2>/dev/null || true)" = "$pid_expected" ] || hold CORE_DRIFT 18
/etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 18

current_backup=$backup/rollback-current
mkdir "$current_backup"
chmod 0700 "$current_backup"
for file in "$builder" "$client" "$audit_script"; do
  cp "$bin/$file" "$current_backup/$file"
  chmod 0600 "$current_backup/$file"
done
(cd "$current_backup" && sha256sum "$builder" "$client" "$audit_script" >SHA256SUMS)
chmod 0600 "$current_backup/SHA256SUMS"

atomic_install(){
  source_file=$1
  target_file=$2
  temporary=$target_file.rollback-$deployment_id
  [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 31
  cp "$source_file" "$temporary"
  chmod 0500 "$temporary"
  cmp -s "$source_file" "$temporary" || return 32
  mv -f "$temporary" "$target_file"
}
cleanup_temporaries(){
  rm -f "$bin/$builder.rollback-$deployment_id" "$bin/$client.rollback-$deployment_id" "$bin/$audit_script.rollback-$deployment_id"
}
restore_updated(){
  set +e
  restore_ok=true
  cleanup_temporaries
  atomic_install "$current_backup/$builder" "$bin/$builder" || restore_ok=false
  atomic_install "$current_backup/$audit_script" "$bin/$audit_script" || restore_ok=false
  atomic_install "$current_backup/$client" "$bin/$client" || restore_ok=false
  [ "$(uci_digest)" = "$uci_current" ] || restore_ok=false
  [ "$(uci -q get openclash.config.config_path || true)" = "$active_current" ] || restore_ok=false
  [ "$(pidof clash_meta 2>/dev/null || true)" = "$pid_expected" ] || restore_ok=false
  marker=ROLLBACK_RECOVERY_FAILED
  [ "$restore_ok" = true ] && marker=ROLLBACK_RECOVERED_TO_UPDATED
  printf '%s\n' "$marker" >"$backup/$marker"
  chmod 0600 "$backup/$marker"
  printf 'ROUTER_ASSET_ROLLBACK=%s\n' "$marker"
}
committed=false
finish(){ [ "$committed" = true ] || restore_updated; }
trap finish EXIT
trap 'exit 128' HUP INT TERM

# The stage lock excludes concurrent Candidate generation while the previous
# client, builder, and optional audit asset are restored.
atomic_install "$backup/$client.before" "$bin/$client" || hold ATOMIC_CLIENT 30
atomic_install "$backup/$builder.before" "$bin/$builder" || hold ATOMIC_BUILDER 30
if [ "$audit_before" = true ]; then
  atomic_install "$backup/$audit_script.before" "$bin/$audit_script" || hold ATOMIC_AUDIT 30
else
  rm -f "$bin/$audit_script" || hold AUDIT_REMOVE 30
fi
for file in "$builder" "$client"; do
  cmp -s "$backup/$file.before" "$bin/$file" || hold RESTORE_HASH 31
  [ "$(ls -ln "$bin/$file" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold RESTORE_MODE 31
done
if [ "$audit_before" = true ]; then
  cmp -s "$backup/$audit_script.before" "$bin/$audit_script" || hold RESTORE_HASH 31
else
  [ ! -e "$bin/$audit_script" ] || hold RESTORE_AUDIT 31
fi
/bin/sh -n "$bin/$client" || hold RESTORE_SHELL 32
ruby -c "$bin/$builder" >/dev/null 2>&1 || hold RESTORE_RUBY 32
[ "$(uci_digest)" = "$uci_current" ] || hold UCI_DRIFT 32
[ "$(uci -q get openclash.config.config_path || true)" = "$active_current" ] || hold ACTIVE_DRIFT 32
[ "$(pidof clash_meta 2>/dev/null || true)" = "$pid_expected" ] || hold CORE_DRIFT 32
/etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 32
cleanup_temporaries

printf '%s\n' 'ROLLBACK-COMMITTED' "TARGET=$target" "DEPLOYMENT_ID=$deployment_id" "AUDIT_PRESENT_AFTER=$audit_before" \
  'UPDATED_STATE_BACKED_UP=true' 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false' \
  >"$backup/ROLLBACK-COMMITTED"
chmod 0600 "$backup/ROLLBACK-COMMITTED"
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'ROUTER_ASSET_ROLLBACK=PASS' "TARGET=$target" "DEPLOYMENT_ID=$deployment_id" \
  "AUDIT_PRESENT_AFTER=$audit_before" 'UPDATED_STATE_BACKED_UP=true' \
  'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
