#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'ROUTER_ASSET_UPDATE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 3 ] || hold ARGS 11
target=$1
source_dir=$2
deployment_id=$3
case "$target" in router_a|router_b) ;; *) hold TARGET 11;; esac
case "$source_dir" in /*) ;; *) hold SOURCE_DIR 11;; esac
case "$deployment_id" in *[!0-9A-Z-]*|'') hold DEPLOYMENT_ID 11;; esac
[ "${#deployment_id}" -ge 8 ] && [ "${#deployment_id}" -le 48 ] || hold DEPLOYMENT_ID 11

root=/etc/openclash/publisher-v4
bin=$root/bin
backup_root=$root/backups
backup=$backup_root/router-assets-$target-$deployment_id
builder=openclash_router_stage_builder.rb
client=openclash_router_stage_client.sh
audit_script=router-openclash-sync-capability-audit.sh
uci_digest(){
  uci_value=$(uci -q show openclash) || return 1
  printf '%s' "$uci_value" | sha256sum | awk '{print $1}'
  unset uci_value
}

[ -d "$source_dir" ] && [ ! -L "$source_dir" ] || hold SOURCE_DIR 12
[ "$(ls -ldn "$source_dir" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold SOURCE_DIR_MODE 12
for file in "$builder" "$client" "$audit_script"; do
  [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ] || hold SOURCE_ASSET 13
done
[ -d "$root" ] && [ ! -L "$root" ] && [ -d "$bin" ] && [ ! -L "$bin" ] || hold PUBLISHER_ROOT 14
[ "$(ls -ldn "$root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold PUBLISHER_ROOT_MODE 14
[ "$(ls -ldn "$bin" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold PUBLISHER_ROOT_MODE 14
for file in "$builder" "$client"; do
  [ -f "$bin/$file" ] && [ ! -L "$bin/$file" ] || hold INSTALLED_ASSET 15
  [ "$(ls -ln "$bin/$file" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold INSTALLED_MODE 15
done
audit_before=false
if [ -e "$bin/$audit_script" ]; then
  [ -f "$bin/$audit_script" ] && [ ! -L "$bin/$audit_script" ] || hold INSTALLED_AUDIT 15
  [ "$(ls -ln "$bin/$audit_script" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold INSTALLED_MODE 15
  audit_before=true
fi
find "$root" -xdev -type l | grep -q . && hold PUBLISHER_SYMLINK 16
command -v flock >/dev/null 2>&1 || hold FLOCK 17
command -v cmp >/dev/null 2>&1 || hold CMP 17
/bin/sh -n "$source_dir/$client" "$source_dir/$audit_script" || hold SOURCE_SHELL 18
ruby -c "$source_dir/$builder" >/dev/null 2>&1 || hold SOURCE_RUBY 18

active_before=$(uci -q get openclash.config.config_path || true)
[ -n "$active_before" ] || hold ACTIVE 19
uci_before=$(uci_digest) || hold UCI 19
/etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 19
pid_before=$(pidof clash_meta 2>/dev/null || true)
case "$pid_before" in ''|*' '*) hold CORE_CARDINALITY 19;; esac

exec 9>"$root/stage.lock"
flock -n 9 || hold LOCK 20
if [ ! -e "$backup_root" ]; then
  mkdir "$backup_root"
  chmod 0700 "$backup_root"
fi
[ -d "$backup_root" ] && [ ! -L "$backup_root" ] || hold BACKUP_ROOT 21
[ "$(ls -ldn "$backup_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold BACKUP_ROOT_MODE 21
[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 21
mkdir "$backup"
chmod 0700 "$backup"
cp "$bin/$builder" "$backup/$builder.before"
cp "$bin/$client" "$backup/$client.before"
chmod 0600 "$backup/$builder.before" "$backup/$client.before"
if [ "$audit_before" = true ]; then
  cp "$bin/$audit_script" "$backup/$audit_script.before"
  chmod 0600 "$backup/$audit_script.before"
fi
(cd "$backup" && sha256sum "$builder.before" "$client.before" >SHA256SUMS.before)
if [ "$audit_before" = true ]; then
  (cd "$backup" && sha256sum "$audit_script.before" >>SHA256SUMS.before)
fi
chmod 0600 "$backup/SHA256SUMS.before"

atomic_install(){
  source_file=$1
  target_file=$2
  temporary=$target_file.update-$deployment_id
  [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 31
  cp "$source_file" "$temporary"
  chmod 0500 "$temporary"
  cmp -s "$source_file" "$temporary" || return 32
  mv -f "$temporary" "$target_file"
}
staging=$root/.router-assets-$deployment_id
cleanup_temporaries(){
  rm -f "$bin/$builder.update-$deployment_id" "$bin/$client.update-$deployment_id" "$bin/$audit_script.update-$deployment_id"
  if [ -d "$staging" ] && [ ! -L "$staging" ]; then
    rm -f "$staging/$builder" "$staging/$client" "$staging/$audit_script"
    rmdir "$staging" 2>/dev/null || true
  fi
}
rollback(){
  set +e
  rollback_ok=true
  cleanup_temporaries
  atomic_install "$backup/$client.before" "$bin/$client" || rollback_ok=false
  atomic_install "$backup/$builder.before" "$bin/$builder" || rollback_ok=false
  if [ "$audit_before" = true ]; then
    atomic_install "$backup/$audit_script.before" "$bin/$audit_script" || rollback_ok=false
  else
    rm -f "$bin/$audit_script" || rollback_ok=false
  fi
  [ "$(uci_digest)" = "$uci_before" ] || rollback_ok=false
  [ "$(uci -q get openclash.config.config_path || true)" = "$active_before" ] || rollback_ok=false
  [ "$(pidof clash_meta 2>/dev/null || true)" = "$pid_before" ] || rollback_ok=false
  /etc/init.d/openclash running >/dev/null 2>&1 || rollback_ok=false
  marker=ROLLBACK_FAILED
  [ "$rollback_ok" = true ] && marker=ROLLED_BACK
  printf '%s\n' "$marker" >"$backup/$marker"
  chmod 0600 "$backup/$marker"
  printf 'ROUTER_ASSET_UPDATE=%s\n' "$marker"
}
committed=false
finish(){ [ "$committed" = true ] || rollback; }
trap finish EXIT
trap 'exit 128' HUP INT TERM

[ ! -e "$staging" ] && [ ! -L "$staging" ] || hold STAGING_EXISTS 29
mkdir "$staging"
chmod 0700 "$staging"
for file in "$builder" "$client" "$audit_script"; do
  cp "$source_dir/$file" "$staging/$file"
  chmod 0500 "$staging/$file"
  cmp -s "$source_dir/$file" "$staging/$file" || hold STAGING_HASH 29
done
/bin/sh -n "$staging/$client" "$staging/$audit_script" || hold STAGING_SHELL 29
ruby -c "$staging/$builder" >/dev/null 2>&1 || hold STAGING_RUBY 29

# The stage lock excludes concurrent Candidate generation. Publish the builder
# and audit first, then the client that depends on their new receipt contract.
atomic_install "$staging/$builder" "$bin/$builder" || hold ATOMIC_BUILDER 30
atomic_install "$staging/$audit_script" "$bin/$audit_script" || hold ATOMIC_AUDIT 30
atomic_install "$staging/$client" "$bin/$client" || hold ATOMIC_CLIENT 30
for file in "$builder" "$client" "$audit_script"; do
  cmp -s "$staging/$file" "$bin/$file" || hold UPDATED_HASH 31
  [ "$(ls -ln "$bin/$file" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold UPDATED_MODE 31
done
[ "$(uci_digest)" = "$uci_before" ] || hold UCI_DRIFT 32
[ "$(uci -q get openclash.config.config_path || true)" = "$active_before" ] || hold ACTIVE_DRIFT 32
[ "$(pidof clash_meta 2>/dev/null || true)" = "$pid_before" ] || hold CORE_DRIFT 32
/etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 32
cleanup_temporaries
[ ! -e "$staging" ] || hold STAGING_CLEANUP 33

{
  printf '%s\n' 'COMMITTED' "TARGET=$target" "DEPLOYMENT_ID=$deployment_id" "AUDIT_PRESENT_BEFORE=$audit_before"
  printf 'BUILDER_AFTER_SHA256=%s\n' "$(sha256sum "$bin/$builder" | awk '{print $1}')"
  printf 'CLIENT_AFTER_SHA256=%s\n' "$(sha256sum "$bin/$client" | awk '{print $1}')"
  printf 'AUDIT_AFTER_SHA256=%s\n' "$(sha256sum "$bin/$audit_script" | awk '{print $1}')"
  printf '%s\n' "UCI_SHA256=$uci_before" "ACTIVE_PATH_SHA256=$(printf '%s' "$active_before" | sha256sum | awk '{print $1}')" \
    "CORE_PID=$pid_before" 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
} >"$backup/COMMITTED"
chmod 0600 "$backup/COMMITTED"
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'ROUTER_ASSET_UPDATE=PASS' "TARGET=$target" "DEPLOYMENT_ID=$deployment_id" \
  'BUILDER_PUBLISHED=true' 'CLIENT_PUBLISHED_LAST=true' 'CAPABILITY_AUDIT_PUBLISHED=true' \
  'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
