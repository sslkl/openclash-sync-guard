#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

[ "$#" -eq 4 ] || exit 10
target=$1
backup=$2
arm=$3
mode=$4
case "$target" in router_a|router_b) ;; *) exit 11;; esac

backup_root=/etc/openclash/publisher-v4/web-backups
state_root=/etc/openclash/publisher-v4/web-state
lock=$state_root/customizations.lock
main=/etc/openclash/config/ProviderBase-ProviderSource.yaml
state=$state_root/customizations.state
runtime=/etc/openclash/${main##*/}
customizer=/etc/openclash/publisher-v4/web/openclash_customizer.rb
expected_core_sha=0000000000000000000000000000000000000000000000000000000000000000
backup_name=${backup##*/}
arm_name=${arm##*/}

[ "$backup" = "$backup_root/$backup_name" ] || exit 12
case "$backup_name" in ''|*[!A-Za-z0-9_-]*) exit 12;; esac
[ -d "$backup" ] && [ ! -L "$backup" ] || exit 12
[ "$arm" = "$state_root/$arm_name" ] || exit 13
case "$arm_name" in guard.*.armed) ;; *) exit 13;; esac
[ -e "$arm" ] || exit 0
[ -f "$arm" ] && [ ! -L "$arm" ] || exit 17
[ -d "$state_root" ] && [ ! -L "$state_root" ] || exit 13
[ ! -e "$lock" ] || { [ -f "$lock" ] && [ ! -L "$lock" ]; } || exit 13
case "$mode" in wait-runtime|wait-static|restore-runtime|restore-static|recover-runtime|recover-static) ;; *) exit 14;; esac
[ -f "$backup/main.yaml" ] && [ ! -L "$backup/main.yaml" ] || exit 15
[ -f "$main" ] && [ ! -L "$main" ] || exit 16
arm_token=UNKNOWN

process_starttime(){
  process_pid=$1
  awk '{print $22}' "/proc/$process_pid/stat" 2>/dev/null
}

hash_file(){
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

uci_digest(){
  uci_value=$(uci -q show openclash) || return 1
  # Keep this projection byte-identical to the transaction. OpenClash owns
  # these two dnsmasq integration fields during restart; every other complete
  # UCI line/value remains generation-bound and fail-closed.
  uci_protected=$(
    printf '%s\n' "$uci_value" |
      sed -e '/^openclash\.config\.dnsmasq_noresolv=/d' \
          -e '/^openclash\.config\.dnsmasq_resolvfile=/d' |
      LC_ALL=C sort
  ) || { unset uci_value; return 1; }
  [ -n "$uci_protected" ] || { unset uci_value uci_protected; return 1; }
  printf '%s' "$uci_protected" | sha256sum | awk '{print $1}'
  unset uci_value
  unset uci_protected
}

wait_uci_digest(){
  expected_uci_sha=$1
  case "$expected_uci_sha" in ''|*[!0-9a-f]*) return 1;; esac
  [ "${#expected_uci_sha}" -eq 64 ] || return 1
  uci_attempt=0
  while [ "$uci_attempt" -lt 30 ]; do
    uci_attempt=$((uci_attempt+1))
    [ "$(uci_digest 2>/dev/null || true)" = "$expected_uci_sha" ] && return 0
    sleep 1
  done
  return 1
}

sync_file(){
  sync_target=$1
  if command -v fsync >/dev/null 2>&1; then
    fsync "$sync_target" >/dev/null 2>&1
  else
    sync
  fi
}

sync_dir(){
  sync_target=$1
  if command -v fsync >/dev/null 2>&1; then
    fsync "$sync_target" >/dev/null 2>&1 || sync
  else
    sync
  fi
}

connectivity(){
  # POSIX shell variables are otherwise shared with the caller's retry loop.
  (
    dns_ok=false
    https_ok=false
    attempt=0
    while [ "$attempt" -lt 3 ]; do
      attempt=$((attempt+1))
      nslookup www.gstatic.com 127.0.0.1 >/dev/null 2>&1 && dns_ok=true || true
      HTTP_PROXY='' HTTPS_PROXY='' ALL_PROXY='' http_proxy='' https_proxy='' all_proxy='' \
        curl -q --noproxy '*' -fsS --connect-timeout 4 --max-time 8 -o /dev/null https://www.gstatic.com/generate_204 >/dev/null 2>&1 || \
        HTTP_PROXY='' HTTPS_PROXY='' ALL_PROXY='' http_proxy='' https_proxy='' all_proxy='' \
          curl -q --noproxy '*' -fsS --connect-timeout 4 --max-time 8 -o /dev/null https://cp.cloudflare.com/generate_204 >/dev/null 2>&1 && https_ok=true || true
      [ "$dns_ok:$https_ok" = true:true ] && return 0
      sleep 2
    done
    return 1
  )
}

stop_owned_restart(){
  [ -f "$backup/RESTART" ] && [ ! -L "$backup/RESTART" ] || return 0
  restart_pid=$(sed -n 's/^PID=//p' "$backup/RESTART" | sed -n '1p')
  restart_start=$(sed -n 's/^START=//p' "$backup/RESTART" | sed -n '1p')
  case "$restart_pid:$restart_start" in *[!0-9:]*|:*|*:0) return 0;; esac
  [ "$(process_starttime "$restart_pid" || true)" = "$restart_start" ] || return 0
  kill "$restart_pid" 2>/dev/null || return 0
  remaining=10
  while [ "$remaining" -gt 0 ]; do
    [ "$(process_starttime "$restart_pid" || true)" = "$restart_start" ] || return 0
    sleep 1
    remaining=$((remaining-1))
  done
  [ "$(process_starttime "$restart_pid" || true)" != "$restart_start" ] || kill -9 "$restart_pid" 2>/dev/null || true
}

restart_with_timeout(){
  /etc/init.d/openclash restart 9>&- >/dev/null 2>&1 &
  rollback_restart_pid=$!
  rollback_restart_start=$(process_starttime "$rollback_restart_pid" || true)
  case "$rollback_restart_start" in ''|*[!0-9]*) wait "$rollback_restart_pid"; return $?;; esac
  (
    sleep 180
    [ "$(process_starttime "$rollback_restart_pid" || true)" = "$rollback_restart_start" ] || exit 0
    kill "$rollback_restart_pid" 2>/dev/null || exit 0
    sleep 10
    [ "$(process_starttime "$rollback_restart_pid" || true)" = "$rollback_restart_start" ] || exit 0
    kill -9 "$rollback_restart_pid" 2>/dev/null || true
  ) 9>&- >/dev/null 2>&1 &
  rollback_watchdog=$!
  rollback_restart_ok=false
  wait "$rollback_restart_pid" && rollback_restart_ok=true || true
  kill "$rollback_watchdog" 2>/dev/null || true
  wait "$rollback_watchdog" 2>/dev/null || true
  [ "$rollback_restart_ok" = true ]
}

arm_value(){
  arm_key=$1
  sed -n "s/^${arm_key}=//p" "$arm" | sed -n '1p'
}

fail_marker(){
  failure_reason=$1
  failure_marker=$backup/ROLLBACK_FAILED
  [ ! -e "$failure_marker" ] || [ ! -L "$failure_marker" ] || return 1
  failure_partial=$(mktemp "$backup/.rollback-failed.XXXXXX") || return 1
  chmod 0600 "$failure_partial"
  printf '%s\n' 'STATUS=ROLLBACK_FAILED' "TOKEN=$arm_token" "TARGET=$target" "REASON=$failure_reason" >"$failure_partial" || {
    rm -f "$failure_partial"
    return 1
  }
  sync_file "$failure_partial" || {
    rm -f "$failure_partial"
    return 1
  }
  mv -f "$failure_partial" "$failure_marker" || {
    rm -f "$failure_partial"
    return 1
  }
  sync_dir "$backup" || return 1
  return 0
}

write_rolled_back(){
  recovery_kind=$1
  rolled_back_partial=$(mktemp "$backup/.rolled-back.XXXXXX") || return 1
  chmod 0600 "$rolled_back_partial"
  printf '%s\n' 'STATUS=ROLLED_BACK' "TOKEN=$arm_token" "TARGET=$target" "RECOVERY_KIND=$recovery_kind" >"$rolled_back_partial" || {
    rm -f "$rolled_back_partial"
    return 1
  }
  sync_file "$rolled_back_partial" || { rm -f "$rolled_back_partial"; return 1; }
  mv -f "$rolled_back_partial" "$backup/ROLLED_BACK" || { rm -f "$rolled_back_partial"; return 1; }
  sync_dir "$backup"
}

validate_arm(){
  [ "$(sed -n '1p' "$arm")" = "$backup" ] || return 1
  [ "$(arm_value SCHEMA)" = 'publisher-v4-openclash-custom-arm-v3' ] || return 1
  arm_token=$(arm_value TOKEN)
  case "$arm_token" in ''|*[!A-Za-z0-9_-]*) return 1;; esac
  [ "$(arm_value TARGET)" = "$target" ] || return 1
  [ "$(arm_value BACKUP)" = "$backup" ] || return 1
  owner_pid=$(arm_value OWNER_PID)
  owner_start=$(arm_value OWNER_STARTTIME)
  case "$owner_pid:$owner_start" in *[!0-9:]*|:*) return 1;; esac
  [ "$(arm_value GUARD_KIND)" = "${mode#wait-}" ] || [ "$(arm_value GUARD_KIND)" = "${mode#restore-}" ] || \
    [ "$(arm_value GUARD_KIND)" = "${mode#recover-}" ] || return 1
  arm_main_sha=$(arm_value BACKUP_MAIN_SHA256)
  arm_state_sha=$(arm_value BACKUP_STATE_SHA256)
  arm_uci_sha=$(arm_value UCI_SHA256)
  case "$arm_main_sha:$arm_state_sha:$arm_uci_sha" in *[!0-9a-f:]*|:*|*:|*::* ) return 1;; esac
  [ "${#arm_main_sha}" -eq 64 ] && [ "${#arm_state_sha}" -eq 64 ] && [ "${#arm_uci_sha}" -eq 64 ] || return 1
  arm_state_present=$(arm_value STATE_PRESENT)
  case "$arm_state_present" in 0|1) ;; *) return 1;; esac
  [ "$(hash_file "$backup/main.yaml")" = "$arm_main_sha" ] || return 1
  if [ "$arm_state_present" = 1 ]; then
    [ -f "$backup/customizations.state" ] && [ ! -L "$backup/customizations.state" ] || return 1
    [ "$(hash_file "$backup/customizations.state")" = "$arm_state_sha" ] || return 1
  else
    [ "$arm_state_sha" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] || return 1
    [ ! -e "$backup/customizations.state" ] || return 1
  fi
  if [ "$(arm_value RUNTIME_PRESENT)" = 1 ]; then
    [ -f "$backup/runtime.before.yaml" ] && [ ! -L "$backup/runtime.before.yaml" ] || return 1
    arm_runtime_sha=$(arm_value BACKUP_RUNTIME_SHA256)
    case "$arm_runtime_sha" in ''|*[!0-9a-f]*) return 1;; esac
    [ "${#arm_runtime_sha}" -eq 64 ] || return 1
    [ "$(hash_file "$backup/runtime.before.yaml")" = "$arm_runtime_sha" ] || return 1
  else
    [ ! -e "$backup/runtime.before.yaml" ] || return 1
  fi
  arm_selection_present=$(arm_value SELECTION_PRESENT)
  case "$arm_selection_present" in 0|1) ;; *) return 1;; esac
  arm_selection_sha=$(arm_value BACKUP_SELECTION_SHA256)
  case "$arm_selection_sha" in ''|*[!0-9a-f]*) return 1;; esac
  [ "${#arm_selection_sha}" -eq 64 ] || return 1
  if [ "$arm_selection_present" = 1 ]; then
    [ -f "$backup/selections.before" ] && [ ! -L "$backup/selections.before" ] || return 1
    [ "$(hash_file "$backup/selections.before")" = "$arm_selection_sha" ] || return 1
  else
    [ "$arm_selection_sha" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] || return 1
    [ ! -e "$backup/selections.before" ] || return 1
  fi
  return 0
}

valid_commit(){
  commit=$backup/COMMITTED
  [ -f "$commit" ] && [ ! -L "$commit" ] || return 1
  [ "$(sed -n 's/^STATUS=//p' "$commit" | sed -n '1p')" = COMMITTED ] ||
    [ "$(sed -n '1p' "$commit")" = COMMITTED ] || return 1
  [ "$(sed -n 's/^TOKEN=//p' "$commit" | sed -n '1p')" = "$arm_token" ] || return 1
  commit_config=$(sed -n 's/^CONFIG_SHA256=//p' "$commit" | sed -n '1p')
  commit_state=$(sed -n 's/^STATE_SHA256=//p' "$commit" | sed -n '1p')
  case "$commit_config:$commit_state" in *[!0-9a-f:]*|:*|*:) return 1;; esac
  [ "${#commit_config}" -eq 64 ] && [ "${#commit_state}" -eq 64 ] || return 1
  [ -f "$main" ] && [ ! -L "$main" ] || return 1
  [ "$(hash_file "$main")" = "$commit_config" ] || return 1
  # STATE_PRESENT describes the pre-transaction backup only. A successful
  # customizer render always publishes a new state file, so COMMITTED must
  # validate the committed hash independently of the old-state presence.
  [ -f "$state" ] && [ ! -L "$state" ] || return 1
  [ "$(hash_file "$state")" = "$commit_state" ] || return 1
  [ "$(sed -n 's/^SCHEMA=//p' "$commit" | sed -n '1p')" = publisher-v4-openclash-custom-commit-v3 ] || return 1
  [ "$(sed -n 's/^TARGET=//p' "$commit" | sed -n '1p')" = "$target" ] || return 1
  [ "$(sed -n 's/^SELECTION_PRESENT=//p' "$commit" | sed -n '1p')" = "$arm_selection_present" ] || return 1
  [ "$(sed -n 's/^SELECTIONS_SHA256=//p' "$commit" | sed -n '1p')" = "$arm_selection_sha" ] || return 1
  commit_selections_restored=$(sed -n 's/^SELECTIONS_RESTORED=//p' "$commit" | sed -n '1p')
  if [ "$arm_selection_present" = 1 ]; then
    [ "$commit_selections_restored" = true ] || return 1
    ruby "$customizer" selection-verify "$runtime" "$backup/selections.before" >/dev/null 2>&1 || return 1
  else
    [ "$commit_selections_restored" = false ] || return 1
  fi
  [ "$(sed -n 's/^UCI_SHA256=//p' "$commit" | sed -n '1p')" = "$arm_uci_sha" ] || return 1
  wait_uci_digest "$arm_uci_sha" || return 1
  return 0
}

atomic_restore(){
  restore_source=$1
  restore_target=$2
  restore_expected=$3
  [ -f "$restore_source" ] && [ ! -L "$restore_source" ] || return 1
  [ "$(hash_file "$restore_source")" = "$restore_expected" ] || return 1
  restore_dir=${restore_target%/*}
  restore_partial=$(mktemp "$restore_dir/.openclash-rollback.XXXXXX") || return 1
  chmod 0600 "$restore_partial"
  cp -p "$restore_source" "$restore_partial" || {
    rm -f "$restore_partial"
    return 1
  }
  [ "$(hash_file "$restore_partial")" = "$restore_expected" ] || {
    rm -f "$restore_partial"
    return 1
  }
  sync_file "$restore_partial" || {
    rm -f "$restore_partial"
    return 1
  }
  mv -f "$restore_partial" "$restore_target" || {
    rm -f "$restore_partial"
    return 1
  }
  sync_dir "$restore_dir" || return 1
  [ "$(hash_file "$restore_target")" = "$restore_expected" ] || return 1
  return 0
}

restore_state_absent(){
  [ ! -e "$state" ] || { [ ! -L "$state" ] && rm -f "$state"; } || return 1
  sync_dir "$state_root" || return 1
  [ ! -e "$state" ]
}

restore_transaction(){
  recovery_kind=$1
  require_owner=${2:-false}
  if [ "$require_owner" = true ]; then
    [ "$(process_starttime "$owner_pid" || true)" = "$owner_start" ] || return 1
  fi
  [ "$(arm_value BACKUP_MAIN_SHA256)" = "$arm_main_sha" ] || return 1
  atomic_restore "$backup/main.yaml" "$main" "$arm_main_sha" || return 1
  if [ "$arm_state_present" = 1 ]; then
    atomic_restore "$backup/customizations.state" "$state" "$arm_state_sha" || return 1
  else
    restore_state_absent || return 1
  fi
  if [ "$recovery_kind" = runtime ]; then
    [ "$(arm_value RUNTIME_PRESENT)" = 1 ] || return 1
    stop_owned_restart || return 1
    restart_with_timeout || return 1
    # OpenClash may regenerate the runtime file during restart. Restore it
    # once more after the service is ready, then verify the final hash.
    atomic_restore "$backup/runtime.before.yaml" "$runtime" "$arm_runtime_sha" || return 1
    [ "$(hash_file "$main")" = "$arm_main_sha" ] || return 1
    if [ "$arm_state_present" = 1 ]; then
      [ "$(hash_file "$state")" = "$arm_state_sha" ] || return 1
    else
      [ ! -e "$state" ] || return 1
    fi
    [ -f "$runtime" ] && [ ! -L "$runtime" ] || return 1
    /etc/init.d/openclash running >/dev/null 2>&1 || return 1
    core_pid=$(pidof clash_meta 2>/dev/null || true)
    case "$core_pid" in ''|*' '*) return 1;; esac
    core=$(readlink "/proc/$core_pid/exe" 2>/dev/null || true)
    [ -f "$core" ] && [ "$(hash_file "$core")" = "$expected_core_sha" ] || return 1
    SAFE_PATHS=/usr/share/openclash:/etc/ssl "$core" -t -d /etc/openclash -f "$runtime" >/dev/null 2>&1 || return 1
    ruby "$customizer" verify-runtime "$main" "$runtime" "$state" >/dev/null 2>&1 || return 1
    [ "$(hash_file "$runtime")" = "$arm_runtime_sha" ] || return 1
    if [ "$arm_selection_present" = 1 ]; then
      ruby "$customizer" selection-restore "$runtime" "$backup/selections.before" >/dev/null 2>&1 || return 1
    fi
    connectivity || return 1
  fi
  wait_uci_digest "$arm_uci_sha" || return 1
  return 0
}

# An explicit restore is called by the transaction while fd 9 already owns
# the lock. A background guard has fd 9 closed by its parent and acquires the
# same lock for each check, then releases it while waiting.
lock_owned=false
if [ "${OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD:-0}" = 1 ]; then
  lock_owned=true
else
  exec 9>"$lock"
  chmod 0600 "$lock"
fi

if ! validate_arm; then
  fail_marker STALE_ARM || true
  exit 17
fi

release_lock(){
  [ "$lock_owned" = true ] || flock -u 9 2>/dev/null || true
}

if [ "$mode" != restore-runtime ] && [ "$mode" != restore-static ] && [ "$mode" != recover-runtime ] && [ "$mode" != recover-static ]; then
  remaining=240
  while [ "$remaining" -gt 0 ]; do
    [ -f "$arm" ] && [ ! -L "$arm" ] || exit 0
    [ "$lock_owned" = true ] || flock 9
    if ! validate_arm; then
      fail_marker STALE_ARM || true
      release_lock
      exit 17
    fi
    if valid_commit; then
      rm -f "$arm"
      sync_dir "$state_root" || true
      release_lock
      exit 0
    fi
    current_owner_start=$(process_starttime "$owner_pid" || true)
    if [ "$current_owner_start" = "$owner_start" ]; then
      release_lock
      sleep 1
      remaining=$((remaining-1))
      continue
    fi
    if restore_transaction "${mode#wait-}"; then
      write_rolled_back "${mode#wait-}" || { fail_marker RECEIPT || true; release_lock; exit 18; }
      rm -f "$arm"
      sync_dir "$state_root" || true
      release_lock
      exit 0
    fi
    fail_marker RESTORE || true
    release_lock
    exit 18
  done
  [ "$lock_owned" = true ] || flock 9
  if valid_commit; then
    rm -f "$arm"
    sync_dir "$state_root" || true
    release_lock
    exit 0
  fi
  if restore_transaction "${mode#wait-}"; then
    write_rolled_back "${mode#wait-}" || { fail_marker RECEIPT || true; release_lock; exit 18; }
    rm -f "$arm"
    sync_dir "$state_root" || true
    release_lock
    exit 0
  fi
  fail_marker TIMEOUT || true
  release_lock
  exit 18
fi

require_owner=true
recovery_kind=${mode#restore-}
case "$mode" in
  recover-*) require_owner=false; recovery_kind=${mode#recover-} ;;
esac
if ! restore_transaction "$recovery_kind" "$require_owner"; then
  fail_marker RESTORE || true
  exit 18
fi
write_rolled_back "$recovery_kind" || { fail_marker RECEIPT || true; exit 18; }
rm -f "$arm"
sync_dir "$state_root" || true
exit 0
