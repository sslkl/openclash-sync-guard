#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'UNINSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
key_id=$1
case "$key_id" in router_a|router_b) ;; *) hold KEY_ID 12;; esac

root=/opt/publisher-v4-openclash-worker
auth=/home/syncsvc/.ssh/authorized_keys
backup_root=/home/syncsvc/.ssh/sync-backups
[ -d "$root" ] && [ ! -L "$root" ] || hold WORKER_ROOT 13
[ -f "$auth" ] && [ ! -L "$auth" ] || hold AUTHORIZED_KEYS 14
[ -d "$backup_root" ] && [ ! -L "$backup_root" ] || hold BACKUP_ROOT 15
backup=
active_backups=0
for candidate in "$backup_root/publisher-v4-openclash-worker-v1-$key_id" "$backup_root"/publisher-v4-openclash-worker-v1-$key_id-*; do
  [ -d "$candidate" ] || continue
  [ -f "$candidate/COMMITTED" ] || continue
  [ ! -e "$candidate/UNINSTALLED" ] || continue
  backup=$candidate
  active_backups=$((active_backups + 1))
done
[ "$active_backups" -eq 1 ] || hold ACTIVE_BACKUP_COUNT 15
[ -f "$backup/authorized_keys.before" ] || hold BACKUP 15
sha256sum -c "$backup/SHA256SUMS" >/dev/null 2>&1 || hold BACKUP_HASH 16

label="publisher-v4-openclash-$key_id"
matches=$(grep -c " $label$" "$auth" || true)
[ "$matches" -eq 1 ] || hold ENTRY_COUNT 17
temporary=$backup/authorized_keys.after-uninstall
rollback_auth=$backup/authorized_keys.before-uninstall
install -m 0600 -o syncsvc -g syncsvc "$auth" "$rollback_auth"
awk -v suffix=" $label" 'substr($0,length($0)-length(suffix)+1)==suffix {next} {print}' "$auth" >"$temporary"
chmod 0600 "$temporary"
chown syncsvc:syncsvc "$temporary"
[ "$(grep -c " $label$" "$temporary" || true)" -eq 0 ] || hold ENTRY_REMAINS 18
committed=false
quarantined_root=
rollback(){
  set +e
  install -m 0600 -o syncsvc -g syncsvc "$rollback_auth" "$auth"
  if [ -n "$quarantined_root" ] && [ -d "$quarantined_root" ] && [ ! -e "$root" ]; then
    mv "$quarantined_root" "$root"
  fi
  rm -f "$backup/UNINSTALLED"
  rm -f "$temporary"
  printf 'UNINSTALL=ROLLED_BACK\n'
}
finish(){ [ "$committed" = true ] || rollback; }
trap finish EXIT
trap 'exit 128' HUP INT TERM
mv "$temporary" "$auth"
chmod 0600 "$auth"
chown syncsvc:syncsvc "$auth"

remaining=$(grep -Ec ' publisher-v4-openclash-(router_a|router_b)$' "$auth" || true)
if [ "$remaining" -eq 0 ]; then
  find "$root" -xdev -type l | grep -q . && hold WORKER_SYMLINK 19
  quarantined_root=/opt/.publisher-v4-openclash-worker-uninstall-$key_id-$$
  [ ! -e "$quarantined_root" ] || hold WORKER_QUARANTINE_EXISTS 20
  mv "$root" "$quarantined_root"
fi
printf 'UNINSTALLED\n' >"$backup/UNINSTALLED"
chmod 0600 "$backup/UNINSTALLED"
chown syncsvc:syncsvc "$backup/UNINSTALLED"
committed=true
trap - EXIT HUP INT TERM
[ -z "$quarantined_root" ] || rm -rf "$quarantined_root"
printf '%s\n' 'UNINSTALL=PASS' "KEY_ID=$key_id" "REMAINING_WORKER_KEYS=$remaining" 'AUTHORIZED_KEYS_OTHER_ENTRIES_PRESERVED=true'
