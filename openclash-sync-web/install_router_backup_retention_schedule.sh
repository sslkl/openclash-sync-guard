#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'RETENTION_SCHEDULE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 2 ] || hold ARGS 11
action=$1
target=$2
case "$action" in install|remove) ;; *) hold ACTION 11;; esac
case "$target" in router_a|router_b) ;; *) hold TARGET 11;; esac

cron_file=/etc/crontabs/root
cron_init=/etc/init.d/cron
publisher_root=/etc/openclash/publisher-v4
web=$publisher_root/web
customizer=$web/openclash_customizer.rb
state_root=$publisher_root/web-state
transaction_lock=$state_root/customizations.lock
backup_root=$publisher_root/web-schedule-backups
install_lock=/etc/openclash/.publisher-v4-install.lock
expected_customizer=62ca66cfe84c7cec4338871b692014a320e2e7a94f183a120f4c35d7f59bee22
begin_marker='# OPENCLASH_SYNC_WEB_RETENTION_BEGIN'
end_marker='# OPENCLASH_SYNC_WEB_RETENTION_END'
schedule='23 4 * * * /usr/bin/flock -n /etc/openclash/publisher-v4/web-state/customizations.lock /usr/bin/ruby /etc/openclash/publisher-v4/web/openclash_customizer.rb prune-backups-scheduled /etc/openclash/publisher-v4/web-backups >/dev/null 2>&1'
backup=
work=
mutated=false
committed=false

sha(){ sha256sum "$1" | awk '{print $1}'; }
trusted_cron(){
  [ -f "$cron_file" ] && [ ! -L "$cron_file" ] &&
    [ "$(ls -ln "$cron_file" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ]
}
sync_path(){ command -v fsync >/dev/null 2>&1 && fsync "$1" >/dev/null 2>&1 || sync; }
reload_cron(){ "$cron_init" reload >/dev/null 2>&1 && "$cron_init" running >/dev/null 2>&1; }
cleanup_work(){
  [ -z "$work" ] || case "$work" in /tmp/openclash-sync-retention.*) rm -rf "$work";; *) return 1;; esac
}
restore(){
  [ -n "$backup" ] && [ -f "$backup/root.crontab.before" ] && [ ! -L "$backup/root.crontab.before" ] || return 1
  restore_tmp=$(mktemp /etc/crontabs/.root.openclash-retention-rollback.XXXXXX) || return 1
  cp "$backup/root.crontab.before" "$restore_tmp" || { rm -f "$restore_tmp"; return 1; }
  chown 0:0 "$restore_tmp" || { rm -f "$restore_tmp"; return 1; }
  chmod 0600 "$restore_tmp" || { rm -f "$restore_tmp"; return 1; }
  [ "$(sha "$restore_tmp")" = "$(sha "$backup/root.crontab.before")" ] || { rm -f "$restore_tmp"; return 1; }
  mv -f "$restore_tmp" "$cron_file" || { rm -f "$restore_tmp"; return 1; }
  sync_path "$cron_file"
  reload_cron
}
finish(){
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_work || true
  if [ "$status" -ne 0 ] && [ "$mutated" = true ] && [ "$committed" = false ]; then
    if restore; then printf '%s\n' 'RETENTION_SCHEDULE_ROLLBACK=PASS' >&2
    else printf '%s\n' 'RETENTION_SCHEDULE_ROLLBACK=HOLD' >&2
    fi
  fi
  exit "$status"
}
trap finish EXIT HUP INT TERM

for command in flock sha256sum mktemp ruby awk grep sed cmp cut cat cp chown chmod mv date ls id mkdir rm sync; do
  command -v "$command" >/dev/null 2>&1 || hold TOOL 12
done
[ -x "$cron_init" ] || hold CRON_INIT 13
"$cron_init" enabled >/dev/null 2>&1 || hold CRON_DISABLED 13
"$cron_init" running >/dev/null 2>&1 || hold CRON_STOPPED 13
[ -d /etc/crontabs ] && [ ! -L /etc/crontabs ] || hold CRON_DIRECTORY 13
[ "$(ls -ldn /etc/crontabs | awk '{print $1 ":" $3 ":" $4}')" = 'drwxr-xr-x:0:0' ] || hold CRON_DIRECTORY_MODE 13
trusted_cron || hold CRONTAB 14

exec 8>"$install_lock"
flock -n 8 || hold INSTALL_LOCK 15
[ -d "$web" ] && [ ! -L "$web" ] || hold WEB 16
[ -f "$customizer" ] && [ ! -L "$customizer" ] || hold CUSTOMIZER 16
[ "$(ls -ln "$customizer" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold CUSTOMIZER_MODE 16
[ "$(sha "$customizer")" = "$expected_customizer" ] || hold CUSTOMIZER_SHA256 16

for directory in "$state_root" "$publisher_root/web-backups" "$backup_root"; do
  [ ! -e "$directory" ] || { [ -d "$directory" ] && [ ! -L "$directory" ]; } || hold DIRECTORY 17
  mkdir -p "$directory"
  chown 0:0 "$directory"
  chmod 0700 "$directory"
  [ "$(ls -ldn "$directory" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold DIRECTORY_MODE 17
done
[ ! -e "$transaction_lock" ] || { [ -f "$transaction_lock" ] && [ ! -L "$transaction_lock" ]; } || hold TRANSACTION_LOCK 18
if [ ! -e "$transaction_lock" ]; then
  : >"$transaction_lock"
  chown 0:0 "$transaction_lock"
  chmod 0600 "$transaction_lock"
fi
[ "$(ls -ln "$transaction_lock" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold TRANSACTION_LOCK_MODE 18
exec 9>"$transaction_lock"
flock -n 9 || hold TRANSACTION_BUSY 18

work=$(mktemp -d /tmp/openclash-sync-retention.XXXXXX) || hold TEMP 19
chmod 0700 "$work"
printf '%s\n' "$begin_marker" "$schedule" "$end_marker" >"$work/expected"
chmod 0600 "$work/expected"
begin_count=$(grep -Fxc "$begin_marker" "$cron_file" || true)
end_count=$(grep -Fxc "$end_marker" "$cron_file" || true)
[ "$begin_count" = "$end_count" ] || hold MARKER_DRIFT 20
case "$begin_count" in 0|1) ;; *) hold MARKER_DUPLICATE 20;; esac
present=false
if [ "$begin_count" -eq 1 ]; then
  begin_line=$(grep -Fn "$begin_marker" "$cron_file" | cut -d: -f1)
  end_line=$(grep -Fn "$end_marker" "$cron_file" | cut -d: -f1)
  [ "$end_line" -eq $((begin_line + 2)) ] || hold MARKER_DRIFT 20
  sed -n "${begin_line},${end_line}p" "$cron_file" >"$work/existing"
  cmp -s "$work/expected" "$work/existing" || hold SCHEDULE_DRIFT 20
  present=true
fi

if { [ "$action" = install ] && [ "$present" = true ]; } ||
   { [ "$action" = remove ] && [ "$present" = false ]; }; then
  committed=true
  printf '%s\n' 'RETENTION_SCHEDULE=PASS' "TARGET=$target" "ACTION=$action" 'CONFIG_CHANGED=false' 'CRON_RELOADED=false' 'BACKUP=NONE'
  exit 0
fi

backup=$backup_root/$(date -u +%Y%m%dT%H%M%SZ)-$$-$action
[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 21
mkdir "$backup"
chmod 0700 "$backup"
cp "$cron_file" "$backup/root.crontab.before"
chown 0:0 "$backup/root.crontab.before"
chmod 0600 "$backup/root.crontab.before"
before_sha=$(sha "$backup/root.crontab.before")

if [ "$action" = install ]; then
  awk '1' "$cron_file" >"$work/new"
  cat "$work/expected" >>"$work/new"
else
  awk -v begin="$begin_marker" -v end="$end_marker" '
    $0 == begin { skip=1; next }
    $0 == end { skip=0; next }
    !skip { print }
    END { if (skip) exit 2 }
  ' "$cron_file" >"$work/new" || hold REMOVE_RENDER 22
fi
chmod 0600 "$work/new"
new_tmp=$(mktemp /etc/crontabs/.root.openclash-retention.XXXXXX) || hold CRONTAB_TEMP 22
cp "$work/new" "$new_tmp" || { rm -f "$new_tmp"; hold CRONTAB_COPY 22; }
chown 0:0 "$new_tmp"
chmod 0600 "$new_tmp"
mutated=true
mv -f "$new_tmp" "$cron_file"
sync_path "$cron_file"
trusted_cron || hold CRONTAB_AFTER 23
after_sha=$(sha "$cron_file")
[ "$after_sha" != "$before_sha" ] || hold CRONTAB_UNCHANGED 23

after_begin=$(grep -Fxc "$begin_marker" "$cron_file" || true)
after_end=$(grep -Fxc "$end_marker" "$cron_file" || true)
if [ "$action" = install ]; then [ "$after_begin:$after_end" = 1:1 ] || hold SCHEDULE_VERIFY 23
else [ "$after_begin:$after_end" = 0:0 ] || hold SCHEDULE_VERIFY 23
fi
reload_cron || hold CRON_RELOAD 24

printf '%s\n' 'STATUS=COMMITTED' 'SCHEMA=OPENCLASH_SYNC_WEB_RETENTION_SCHEDULE_V1' \
  "TARGET=$target" "ACTION=$action" "BEFORE_SHA256=$before_sha" "AFTER_SHA256=$after_sha" \
  "COMMITTED_AT_EPOCH=$(date -u +%s)" >"$backup/COMMITTED.partial"
chmod 0600 "$backup/COMMITTED.partial"
mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED"
sync_path "$backup/COMMITTED"
committed=true
printf '%s\n' 'RETENTION_SCHEDULE=PASS' "TARGET=$target" "ACTION=$action" 'CONFIG_CHANGED=true' 'CRON_RELOADED=true' "BACKUP=$backup"
