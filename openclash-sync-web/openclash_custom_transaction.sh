#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'CUSTOM_TRANSACTION=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -ge 2 ] || hold ARGS 11
action=$1
target=$2
case "$target" in router_a|router_b) ;; *) hold TARGET 12;; esac

web=/etc/openclash/publisher-v4/web
state_root=/etc/openclash/publisher-v4/web-state
state=$state_root/customizations.state
customizer=$web/openclash_customizer.rb
guard=$web/openclash_custom_rollback_guard.sh
main=/etc/openclash/config/ProviderBase-ProviderSource.yaml
runtime=/etc/openclash/${main##*/}
expected_core_sha=0000000000000000000000000000000000000000000000000000000000000000
backup_root=/etc/openclash/publisher-v4/web-backups
lock=$state_root/customizations.lock
runtime_verifier=/etc/openclash/publisher-v4/bin/openclash_runtime_verifier.rb
global_rollback_marker=/etc/openclash/publisher-v4/ROLLBACK-PREPARED
[ -d "$web" ] && [ ! -L "$web" ] || hold WEB_ROOT 13
[ -f "$customizer" ] && [ ! -L "$customizer" ] || hold CUSTOMIZER 13
[ -x "$guard" ] && [ ! -L "$guard" ] || hold GUARD 13
[ -f "$runtime_verifier" ] && [ ! -L "$runtime_verifier" ] || hold RUNTIME_VERIFIER 13
[ -f "$main" ] && [ ! -L "$main" ] || hold MAIN 14
for directory in "$state_root" "$backup_root"; do
  [ ! -e "$directory" ] || { [ -d "$directory" ] && [ ! -L "$directory" ]; } || hold DIRECTORY 14
  mkdir -p "$directory"
done
[ ! -e "$state" ] || { [ -f "$state" ] && [ ! -L "$state" ]; } || hold STATE 14
[ ! -e "$lock" ] || { [ -f "$lock" ] && [ ! -L "$lock" ]; } || hold LOCK 15
chmod 0700 "$state_root" "$backup_root"
for directory in "$web" "$state_root" "$backup_root"; do
  [ "$(ls -ldn "$directory" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold DIRECTORY_MODE 14
done
for file in "$customizer" "$guard" "$runtime_verifier"; do
  [ "$(ls -ln "$file" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold ASSET_MODE 14
done
[ "$(ls -ln "$main" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold MAIN_MODE 14
[ ! -f "$state" ] || [ "$(ls -ln "$state" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold STATE_MODE 14
exec 9>"$lock"
flock -n 9 || hold LOCK 15

empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

process_starttime(){
  process_pid=$1
  awk '{print $22}' "/proc/$process_pid/stat" 2>/dev/null
}

write_restart_record(){
  record_status=$1
  restart_partial=$(mktemp "$backup/.restart.XXXXXX") || return 1
  chmod 0600 "$restart_partial"
  printf '%s\n' "PID=$restart_pid" "START=$restart_start" "STATUS=$record_status" >"$restart_partial" || {
    rm -f "$restart_partial"
    return 1
  }
  sync_file "$restart_partial" || { rm -f "$restart_partial"; return 1; }
  mv -f "$restart_partial" "$backup/RESTART" || { rm -f "$restart_partial"; return 1; }
  sync_dir "$backup"
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

uci_digest(){
  uci_value=$(uci -q show openclash) || return 1
  # OpenClash restart may reorder `uci show` and maintains these two dnsmasq
  # integration fields itself. Bind every other complete UCI line/value while
  # ignoring only that proven runtime-owned surface and presentation order.
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

new_token(){
  token_random=$(hexdump -n 32 -v -e '1/1 "%02x"' /dev/urandom 2>/dev/null) || return 1
  [ "${#token_random}" -eq 64 ] || return 1
  token="$(timestamp)-$$-$token_random"
  case "$token" in *[!A-Za-z0-9_-]*|'') return 1;; esac
  printf '%s\n' "$token"
}

reconcile_arms(){
  for candidate_arm in "$state_root"/guard.*.armed; do
    [ -e "$candidate_arm" ] || continue
    [ -f "$candidate_arm" ] && [ ! -L "$candidate_arm" ] || hold STALE_ARM 25
    candidate_pid=$(sed -n 's/^OWNER_PID=//p' "$candidate_arm" | sed -n '1p')
    candidate_start=$(sed -n 's/^OWNER_STARTTIME=//p' "$candidate_arm" | sed -n '1p')
    case "$candidate_pid:$candidate_start" in *[!0-9:]*|:*) hold STALE_ARM 25;; esac
    if [ "$(process_starttime "$candidate_pid" || true)" = "$candidate_start" ]; then
      hold ACTIVE_ARM 25
    fi
    candidate_backup=$(sed -n 's/^BACKUP=//p' "$candidate_arm" | sed -n '1p')
    candidate_kind=$(sed -n 's/^GUARD_KIND=//p' "$candidate_arm" | sed -n '1p')
    case "$candidate_kind" in runtime|static) ;; *) hold STALE_ARM 25;; esac
    OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD=1 "$guard" "$target" "$candidate_backup" "$candidate_arm" "recover-$candidate_kind" >/dev/null 2>&1 || hold STALE_ARM 25
    [ ! -e "$candidate_arm" ] || hold STALE_ARM 25
  done
}

run_runtime_verifier(){
  [ -f "$runtime_verifier" ] && [ ! -L "$runtime_verifier" ] || return 1
  OPENCLASH_CUSTOMIZATION_LOCK_FD=9 ruby "$runtime_verifier" "$1" "$2" "$3" "$4" 9>&9 >/dev/null 2>&1
}

validate(){
  candidate=$1
  ruby -e 'require "yaml"; v=YAML.safe_load(File.binread(ARGV[0]), permitted_classes:[Symbol], aliases:false); abort unless v.is_a?(Hash) && v["rules"].is_a?(Array) && v["dns"].is_a?(Hash) && v["dns"]["fake-ip-filter"].is_a?(Array)' "$candidate" >/dev/null 2>&1 || return 1
  pid=$(pidof clash_meta 2>/dev/null || true)
  case "$pid" in ''|*' '*) return 1;; esac
  core=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
  [ -f "$core" ] || return 1
  SAFE_PATHS=/usr/share/openclash:/etc/ssl "$core" -t -d /etc/openclash -f "$candidate" >/dev/null 2>&1
}

timestamp(){ date -u +%Y%m%dT%H%M%SZ; }

arm_guard(){
  activation_backup=$1
  guard_kind=$2
  case "$guard_kind" in runtime|static) ;; *) hold GUARD_MODE 25;; esac
  reconcile_arms
  owner_start=$(process_starttime "$$" || true)
  case "$owner_start" in ''|*[!0-9]*) hold OWNER_IDENTITY 25;; esac
  arm_token=$(new_token) || hold TOKEN 25
  arm=$state_root/guard.$$.$arm_token.armed
  [ ! -e "$arm" ] || hold ARM_PATH 25
  state_present=0
  state_backup_sha=$empty_sha
  if [ -f "$activation_backup/customizations.state" ] && [ ! -L "$activation_backup/customizations.state" ]; then
    state_present=1
    state_backup_sha=$(sha256sum "$activation_backup/customizations.state" | awk '{print $1}')
  fi
  runtime_present=0
  runtime_backup_sha=$empty_sha
  if [ -f "$activation_backup/runtime.before.yaml" ] && [ ! -L "$activation_backup/runtime.before.yaml" ]; then
    runtime_present=1
    runtime_backup_sha=$(sha256sum "$activation_backup/runtime.before.yaml" | awk '{print $1}')
  fi
  selection_present=0
  selection_backup_sha=$empty_sha
  if [ -f "$activation_backup/selections.before" ] && [ ! -L "$activation_backup/selections.before" ]; then
    selection_present=1
    selection_backup_sha=$(sha256sum "$activation_backup/selections.before" | awk '{print $1}')
  fi
  backup_main_sha=$(sha256sum "$activation_backup/main.yaml" | awk '{print $1}')
  arm_partial=$(mktemp "$state_root/.guard-arm.XXXXXX") || hold ARM_PATH 25
  chmod 0600 "$arm_partial" || { rm -f "$arm_partial"; hold ARM_PATH 25; }
  printf '%s\n' "$activation_backup" \
    'SCHEMA=publisher-v4-openclash-custom-arm-v3' \
    "TOKEN=$arm_token" "TARGET=$target" "BACKUP=$activation_backup" \
    "OWNER_PID=$$" "OWNER_STARTTIME=$owner_start" "GUARD_KIND=$guard_kind" \
    "BACKUP_MAIN_SHA256=$backup_main_sha" "BACKUP_STATE_SHA256=$state_backup_sha" \
    "STATE_PRESENT=$state_present" "RUNTIME_PRESENT=$runtime_present" \
    "BACKUP_RUNTIME_SHA256=$runtime_backup_sha" "SELECTION_PRESENT=$selection_present" \
    "BACKUP_SELECTION_SHA256=$selection_backup_sha" "UCI_SHA256=$uci_before_sha" >"$arm_partial" || {
      rm -f "$arm_partial"
      hold ARM_WRITE 25
    }
  sync_file "$arm_partial" || { rm -f "$arm_partial"; hold ARM_SYNC 25; }
  mv "$arm_partial" "$arm" || { rm -f "$arm_partial"; hold ARM_WRITE 25; }
  sync_dir "$state_root" || hold ARM_SYNC 25
  # guard 与其 sleep 子进程不得继承事务锁；后台 guard 会重新打开同一
  # lock，并在每次检查/恢复时持锁，避免旧代际覆盖新事务。
  nohup "$guard" "$target" "$activation_backup" "$arm" "wait-$guard_kind" 9>&- >/dev/null 2>&1 &
  guard_pid=$!
  sleep 1
  kill -0 "$guard_pid" 2>/dev/null || hold GUARD_START 25
}

activate(){
  activation_backup=$1
  expected_config_sha=$2
  expected_state_sha=$3
  active=$(uci -q get openclash.config.config_path || true)
  [ "$active" = "$main" ] || hold ACTIVE_PATH 25
  runtime=/etc/openclash/${main##*/}
  old_pid=$(pidof clash_meta 2>/dev/null || true)
  case "$old_pid" in ''|*' '*) hold CORE_BEFORE 25;; esac
  old_start=$(awk '{print $22}' "/proc/$old_pid/stat" 2>/dev/null || true)
  case "$old_start" in ''|*[!0-9]*) hold CORE_BEFORE 25;; esac
  old_identity=$old_pid:$old_start
  /etc/init.d/openclash restart 9>&- >/dev/null 2>&1 &
  restart_pid=$!
  restart_start=$(process_starttime "$restart_pid" || true)
  case "$restart_start" in ''|*[!0-9]*)
    wait "$restart_pid" || {
      OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD=1 "$guard" "$target" "$activation_backup" "$arm" restore-runtime >/dev/null 2>&1 || true
      hold RESTART 26
    }
    restart_start=0
    ;;
  esac
  if [ "$restart_start" -ne 0 ]; then
    write_restart_record RUNNING || hold RESTART_RECORD 26
    (
      sleep 180
      [ "$(process_starttime "$restart_pid" || true)" = "$restart_start" ] || exit 0
      kill "$restart_pid" 2>/dev/null || exit 0
      sleep 10
      [ "$(process_starttime "$restart_pid" || true)" = "$restart_start" ] || exit 0
      kill -9 "$restart_pid" 2>/dev/null || true
    ) 9>&- >/dev/null 2>&1 &
    restart_watchdog=$!
    restart_ok=false
    wait "$restart_pid" && restart_ok=true || true
    kill "$restart_watchdog" 2>/dev/null || true
    wait "$restart_watchdog" 2>/dev/null || true
    [ "$restart_ok" = true ] || {
      OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD=1 "$guard" "$target" "$activation_backup" "$arm" restore-runtime >/dev/null 2>&1 || true
      hold RESTART 26
    }
    write_restart_record EXITED_0 || hold RESTART_RECORD 26
  fi
  attempt=0
  while [ "$attempt" -lt 90 ]; do
    attempt=$((attempt+1))
    sleep 1
    current=$(uci -q get openclash.config.config_path || true)
    [ "$current" = "$main" ] || continue
    /etc/init.d/openclash running >/dev/null 2>&1 || continue
    pid=$(pidof clash_meta 2>/dev/null || true)
    case "$pid" in ''|*' '*) continue;; esac
    start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)
    case "$start" in ''|*[!0-9]*) continue;; esac
    [ "$pid:$start" != "$old_identity" ] || continue
    core=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    [ -f "$core" ] && [ "$(sha256sum "$core" | awk '{print $1}')" = "$expected_core_sha" ] || continue
    [ -f "$arm" ] && [ ! -L "$arm" ] || hold GUARD_DISARMED 26
    [ "$(sha256sum "$main" | awk '{print $1}')" = "$expected_config_sha" ] || continue
    [ "$(sha256sum "$state" | awk '{print $1}')" = "$expected_state_sha" ] || continue
    [ -f "$runtime" ] && [ ! -L "$runtime" ] || continue
    ruby "$customizer" verify-runtime "$main" "$runtime" "$state" >/dev/null 2>&1 || continue
    run_runtime_verifier "$main" "$runtime" "$backup/runtime.before.yaml" "$backup/main.yaml" || continue
    ruby "$customizer" selection-restore "$runtime" "$backup/selections.before" >/dev/null 2>&1 || continue
    # Connectivity already has its own three-attempt budget. Do not multiply
    # it by the runtime-readiness loop while holding the transaction lock.
    connectivity || break
    activation_verified=true
    return 0
  done
  OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD=1 "$guard" "$target" "$activation_backup" "$arm" restore-runtime >/dev/null 2>&1 || true
  kill "$guard_pid" 2>/dev/null || true
  wait "$guard_pid" 2>/dev/null || true
  hold ACTIVATE 26
}

commit_render(){
  input=$1
  request=$2
  label=$3
  activate_after=${4:-false}
  old_state_input=${5:-$state}
  ownership_mode=${6:-remove}
  case "$ownership_mode" in remove|overlay) ;; *) hold OWNERSHIP_MODE 19;; esac
  activation_verified=false
  arm=
  guard_pid=
  backup=
  selection_present=0
  selection_snapshot_sha=$empty_sha
  selections_restored=false
  committed_partial=
  main_partial=
  state_partial=
  tx=
  cleanup_render_request(){
    case "$request" in
      "$state_root/replay.request"|/tmp/openclash-web-custom.*/*) rm -f "$request" || true;;
    esac
  }
  rollback(){
    [ -z "$main_partial" ] || rm -f "$main_partial" || true
    [ -z "$state_partial" ] || rm -f "$state_partial" || true
    if [ -n "$tx" ]; then
      case "$tx" in "$state_root"/transaction.*) rm -rf "$tx" || true;; esac
    fi
    if [ -n "$backup" ]; then
      rm -f "$backup/COMMITTED" "$committed_partial" || true
    fi
    cleanup_render_request
    # 恢复必须由持有同一事务锁的 guard 完成；失败时 arm 保留并留下
    # ROLLBACK_FAILED，避免 EXIT trap 吞掉部分恢复。
    if [ -n "$arm" ] && [ -f "$arm" ]; then
      OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD=1 "$guard" "$target" "$backup" "$arm" "restore-$guard_kind" >/dev/null 2>&1 || true
      [ -z "$guard_pid" ] || kill "$guard_pid" 2>/dev/null || true
      [ -z "$guard_pid" ] || wait "$guard_pid" 2>/dev/null || true
    elif [ "$activation_verified" = true ]; then
      /etc/init.d/openclash restart >/dev/null 2>&1 || true
    fi
  }
  abort_transaction(){
    trap - EXIT HUP INT TERM
    rollback
    exit 128
  }
  trap rollback EXIT
  trap abort_transaction HUP INT TERM
  active_before=$(uci -q get openclash.config.config_path || true)
  [ "$active_before" = "$main" ] || hold ACTIVE_PATH 19
  uci_before_sha=$(uci_digest) || hold UCI 19
  /etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 19
  core_before_pid=$(pidof clash_meta 2>/dev/null || true)
  case "$core_before_pid" in ''|*' '*) hold CORE_BEFORE 19;; esac
  core_before_start=$(process_starttime "$core_before_pid" || true)
  case "$core_before_start" in ''|*[!0-9]*) hold CORE_BEFORE 19;; esac
  core_before=$(readlink "/proc/$core_before_pid/exe" 2>/dev/null || true)
  [ -f "$core_before" ] && [ "$(sha256sum "$core_before" | awk '{print $1}')" = "$expected_core_sha" ] || hold CORE_BEFORE 19
  tx=$(mktemp -d "$state_root/transaction.XXXXXX")
  chmod 0700 "$tx"
  output=$tx/main.new
  output_state=$tx/state.new
  if ! ruby "$customizer" render "$input" "$old_state_input" "$request" "$output" "$output_state" "$ownership_mode" >"$tx/receipt" 2>/dev/null; then rm -rf "$tx"; hold RENDER 20; fi
  chmod 0600 "$output" "$output_state" "$tx/receipt"
  validate "$output" || { rm -rf "$tx"; hold MIHOMO 21; }
  backup=$backup_root/$(timestamp)-$$-$label
  case "$backup" in *[!A-Za-z0-9_./-]*) rm -rf "$tx"; hold BACKUP_PATH 22;; esac
  mkdir "$backup"
  chmod 0700 "$backup"
  cp -p "$main" "$backup/main.yaml"
  previous_config_sha=$(sha256sum "$backup/main.yaml" | awk '{print $1}')
  candidate_config_sha=$(sha256sum "$output" | awk '{print $1}')
  [ ! -f "$state" ] || cp -p "$state" "$backup/customizations.state"
  if [ -f "$runtime" ] && [ ! -L "$runtime" ]; then
    cp -p "$runtime" "$backup/runtime.before.yaml"
  elif [ "$activate_after" = true ] && [ "$candidate_config_sha" != "$previous_config_sha" ]; then
    rm -rf "$tx" "$backup"
    hold RUNTIME_BEFORE 22
  fi
  if [ "$activate_after" = true ] && [ "$candidate_config_sha" != "$previous_config_sha" ]; then
    ruby "$customizer" selection-snapshot "$backup/runtime.before.yaml" "$backup/selections.before" >/dev/null 2>&1 || {
      rm -rf "$tx" "$backup"
      hold SELECTION_SNAPSHOT 22
    }
    chmod 0600 "$backup/selections.before" || { rm -rf "$tx" "$backup"; hold SELECTION_SNAPSHOT 22; }
    selection_present=1
    selection_snapshot_sha=$(sha256sum "$backup/selections.before" | awk '{print $1}')
  fi
  sync_file "$backup/main.yaml" || { rm -rf "$tx" "$backup"; hold BACKUP_SYNC 22; }
  [ ! -f "$state" ] || sync_file "$backup/customizations.state" || { rm -rf "$tx" "$backup"; hold BACKUP_SYNC 22; }
  [ ! -f "$backup/runtime.before.yaml" ] || sync_file "$backup/runtime.before.yaml" || { rm -rf "$tx" "$backup"; hold BACKUP_SYNC 22; }
  [ ! -f "$backup/selections.before" ] || sync_file "$backup/selections.before" || { rm -rf "$tx" "$backup"; hold BACKUP_SYNC 22; }
  sync_dir "$backup" || { rm -rf "$tx" "$backup"; hold BACKUP_SYNC 22; }
  committed_partial=$backup/COMMITTED.partial
  printf '%s\n' 'STATUS=COMMITTED' "ACTION=$label" >"$committed_partial"
  chmod 0600 "$committed_partial"
  main_partial=$main.custom.partial
  state_partial=$state.partial
  rm -f "$main_partial" "$state_partial"
  cp "$output" "$main_partial"
  cp "$output_state" "$state_partial"
  chmod 0600 "$main_partial" "$state_partial"
  if [ "$activate_after" = true ] && [ "$candidate_config_sha" != "$previous_config_sha" ]; then guard_kind=runtime; else guard_kind=static; fi
  arm_guard "$backup" "$guard_kind"
  mv "$main_partial" "$main"
  mv "$state_partial" "$state"
  validate "$main" || hold POST_COMMIT 23
  rule_count=$(sed -n 's/^RULE_COUNT=//p' "$tx/receipt")
  filter_count=$(sed -n 's/^FAKE_FILTER_COUNT=//p' "$tx/receipt")
  case "$rule_count" in ''|*[!0-9]*) hold RECEIPT 24;; esac
  case "$filter_count" in ''|*[!0-9]*) hold RECEIPT 24;; esac
  config_sha=$(sha256sum "$main" | awk '{print $1}')
  state_sha=$(sha256sum "$state" | awk '{print $1}')
  printf '%s\n' "TOKEN=$arm_token" "SCHEMA=publisher-v4-openclash-custom-commit-v3" \
    "TARGET=$target" "CONFIG_SHA256=$config_sha" "STATE_SHA256=$state_sha" \
    "SELECTION_PRESENT=$selection_present" "SELECTIONS_SHA256=$selection_snapshot_sha" >>"$committed_partial"
  rm -rf "$tx"
  restart_performed=false
  if [ "$activate_after" = true ] && [ "$config_sha" != "$previous_config_sha" ]; then
    activate "$backup" "$config_sha" "$state_sha"
    restart_performed=true
    selections_restored=true
  fi
  [ "$(uci -q get openclash.config.config_path || true)" = "$active_before" ] || hold ACTIVE_DRIFT 25
  wait_uci_digest "$uci_before_sha" || hold UCI_DRIFT 25
  [ "$(sha256sum "$main" | awk '{print $1}')" = "$config_sha" ] || hold CONFIG_DRIFT 25
  [ "$(sha256sum "$state" | awk '{print $1}')" = "$state_sha" ] || hold STATE_DRIFT 25
  /etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 25
  if [ "$restart_performed" = true ]; then
    ruby "$customizer" verify-runtime "$main" "$runtime" "$state" >/dev/null 2>&1 || hold FINAL_CUSTOM_RUNTIME 25
    run_runtime_verifier "$main" "$runtime" "$backup/runtime.before.yaml" "$backup/main.yaml" || hold FINAL_RUNTIME_VERIFIER 25
    ruby "$customizer" selection-verify "$runtime" "$backup/selections.before" >/dev/null 2>&1 || hold FINAL_SELECTION_VERIFY 25
    connectivity || hold FINAL_CONNECTIVITY 25
  else
    current_pid=$(pidof clash_meta 2>/dev/null || true)
    current_start=$(process_starttime "$current_pid" || true)
    [ "$current_pid:$current_start" = "$core_before_pid:$core_before_start" ] || hold CORE_DRIFT 25
  fi
  printf '%s\n' "UCI_SHA256=$uci_before_sha" "CORE_BEFORE_PID=$core_before_pid" "CORE_BEFORE_START=$core_before_start" \
    "SERVICE_RESTARTED=$restart_performed" "SELECTIONS_RESTORED=$selections_restored" \
    "COMMITTED_AT_EPOCH=$(date -u +%s)" >>"$committed_partial"
  sync_file "$committed_partial" || hold COMMIT_SYNC 25
  mv "$committed_partial" "$backup/COMMITTED" || hold COMMIT 25
  sync_dir "$backup" || hold COMMIT_SYNC 25
  if [ -n "$arm" ]; then
    rm -f "$arm"
    sync_dir "$state_root" || hold DISARM_SYNC 25
    kill "$guard_pid" 2>/dev/null || true
    wait "$guard_pid" 2>/dev/null || true
  fi
  cleanup_render_request
  trap - EXIT HUP INT TERM
  if retention_count=$(ruby "$customizer" prune-backups "$backup_root" "$backup" 2>/dev/null) &&
     printf '%s\n' "$retention_count" | grep -Eq '^BACKUPS_REMOVED=[0-9]+$'; then
    retention_status=PASS
  else
    retention_status=HOLD
    retention_count=BACKUPS_REMOVED=UNKNOWN
  fi
  printf '%s\n' 'CUSTOM_TRANSACTION=PASS' "RULE_COUNT=$rule_count" "FAKE_FILTER_COUNT=$filter_count" "CONFIG_SHA256=$config_sha" "STATE_SHA256=$state_sha" "BACKUP=$backup" 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' "SERVICE_RESTARTED=$restart_performed" "BACKUP_RETENTION=$retention_status" "$retention_count"
}

residue_preflight(){
  [ ! -e "$main.custom.partial" ] && [ ! -e "$state.partial" ] && [ ! -e "$state_root/replay.request" ] || hold PARTIAL_RESIDUE 25
  if find "$state_root" -maxdepth 1 \( -type f -name '.guard-arm.*' -o -type d -name 'transaction.*' -o -type d -name 'preview.*' \) -print 2>/dev/null | grep -q .; then
    hold PARTIAL_RESIDUE 25
  fi
  if find "$backup_root" -mindepth 2 -maxdepth 2 -type f \
    \( -name 'COMMITTED.partial' -o -name '.restart.*' -o -name '.rolled-back.*' -o -name '.rollback-failed.*' \) \
    -print 2>/dev/null | grep -q .; then
    hold BACKUP_PARTIAL_RESIDUE 25
  fi
}

check_expected_snapshot(){
  expected_state=$1
  expected_config=$2
  case "$expected_state:$expected_config" in *[!0-9a-f:]*|:*) hold EXPECTED_SHA 32;; esac
  [ "${#expected_state}" -eq 64 ] && [ "${#expected_config}" -eq 64 ] || hold EXPECTED_SHA 32
  if [ -f "$state" ]; then
    current_state_sha=$(sha256sum "$state" | awk '{print $1}')
  else
    current_state_sha=$empty_sha
  fi
  current_config_sha=$(sha256sum "$main" | awk '{print $1}')
  [ "$current_state_sha:$current_config_sha" = "$expected_state:$expected_config" ] || hold CONCURRENT_CHANGE 33
}

preview_render(){
  request=$1
  case "$request" in /tmp/openclash-web-custom.*/*) ;; *) hold REQUEST_PATH 30;; esac
  [ -f "$request" ] && [ ! -L "$request" ] || hold REQUEST 31
  preview=$(mktemp -d "$state_root/preview.XXXXXX") || hold PREVIEW_PATH 34
  chmod 0700 "$preview"
  old_state_input=$state
  [ -f "$state" ] || old_state_input=/dev/null
  if ! ruby "$customizer" render "$main" "$old_state_input" "$request" "$preview/main.new" "$preview/state.new" remove >"$preview/receipt" 2>/dev/null; then
    rm -rf "$preview"
    hold PREVIEW_RENDER 34
  fi
  chmod 0600 "$preview/main.new" "$preview/state.new" "$preview/receipt"
  if ! validate "$preview/main.new"; then
    rm -rf "$preview"
    hold PREVIEW_MIHOMO 34
  fi
  preview_config_sha=$(sha256sum "$preview/main.new" | awk '{print $1}')
  preview_state_sha=$(sha256sum "$preview/state.new" | awk '{print $1}')
  rm -rf "$preview"
  printf '%s\n' 'CUSTOM_PREVIEW=PASS' "CONFIG_SHA256=$preview_config_sha" "STATE_SHA256=$preview_state_sha" 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
}

reconcile_arms
if [ -e "$global_rollback_marker" ] || [ -L "$global_rollback_marker" ]; then
  [ -f "$global_rollback_marker" ] && [ ! -L "$global_rollback_marker" ] && \
    [ "$(ls -ln "$global_rollback_marker" 2>/dev/null | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || \
    hold ROLLBACK_PREPARED_INVALID 25
  hold ROLLBACK_PREPARED 25
fi
residue_preflight
case "$action" in
  chain-read)
    [ "$#" -eq 2 ] || hold ARGS 11
    ruby "$customizer" chain-read "$main" "$state" 2>/dev/null || hold CHAIN_READ 50
    ;;
  chain-test)
    [ "$#" -eq 3 ] || hold ARGS 11
    case "$3" in /tmp/openclash-web-custom.*/*) ;; *) hold REQUEST_PATH 30;; esac
    [ -f "$3" ] && [ ! -L "$3" ] || hold REQUEST 31
    [ -f "$runtime" ] && [ ! -L "$runtime" ] || hold RUNTIME 31
    ruby "$customizer" chain-test "$main" "$runtime" "$state" "$3" 2>/dev/null || hold CHAIN_TEST 50
    ;;
  chain-apply)
    [ "$#" -eq 5 ] || hold ARGS 11
    check_expected_snapshot "$4" "$5"
    case "$3" in /tmp/openclash-web-custom.*/*) ;; *) hold REQUEST_PATH 30;; esac
    [ -f "$3" ] && [ ! -L "$3" ] || hold REQUEST 31
    chain_manifest=${3%/*}/chain.state
    ruby "$customizer" chain-request "$state" "$3" "$chain_manifest" 2>/dev/null || hold CHAIN_REQUEST 31
    preview_render "$chain_manifest" >/dev/null
    commit_render "$main" "$chain_manifest" custom-apply true "$state" remove
    ;;
  preview)
    [ "$#" -eq 5 ] || hold ARGS 11
    check_expected_snapshot "$4" "$5"
    preview_render "$3"
    ;;
  apply)
    [ "$#" -eq 5 ] || hold ARGS 11
    request=$3
    check_expected_snapshot "$4" "$5"
    case "$request" in /tmp/openclash-web-custom.*/*) ;; *) hold REQUEST_PATH 30;; esac
    [ -f "$request" ] && [ ! -L "$request" ] || hold REQUEST 31
    commit_render "$main" "$request" custom-apply true "$state" remove
    rm -f "$request"
    rmdir "${request%/*}" 2>/dev/null || true
    ;;
  replace)
    [ "$#" -ge 4 ] && [ "$#" -le 5 ] || hold ARGS 11
    input=$3
    label=$4
    case "$label" in stage-main|manual-write|converter-apply|rollback) ;; *) hold LABEL 40;; esac
    if [ "$label" = manual-write ] || [ "$label" = converter-apply ]; then
      [ "$#" -eq 5 ] || hold ARGS 11
      expected=$5
      case "$expected" in *[!0-9a-f]*|'') hold EXPECTED_SHA 43;; esac
      [ "${#expected}" -eq 64 ] || hold EXPECTED_SHA 43
      current_sha=$(sha256sum "$main" | awk '{print $1}')
      [ "$current_sha" = "$expected" ] || hold CONCURRENT_CHANGE 44
    else
      [ "$#" -eq 4 ] || hold ARGS 11
    fi
    case "$input" in /etc/openclash/publisher-v4/stage/*/candidate.yaml|/etc/openclash/config/.openclash-web-*|/etc/openclash/config/*.rollback.partial) ;; *) hold INPUT_PATH 41;; esac
    [ -f "$input" ] && [ ! -L "$input" ] || hold INPUT 42
    request=$state_root/replay.request
    rm -f "$request"
    if [ -f "$state" ]; then sed '/^OWNED_/d' "$state" >"$request"; else printf '%s\n' 'OPENCLASH_SYNC_CUSTOM_V1' >"$request"; fi
    chmod 0600 "$request"
    if [ "$label" = stage-main ]; then
      commit_render "$input" "$request" "$label" true /dev/null overlay
    elif [ "$label" = converter-apply ]; then
      commit_render "$input" "$request" "$label" true "$state" remove
    else
      commit_render "$input" "$request" "$label" false "$state" remove
    fi
    rm -f "$request"
    case "$input" in /etc/openclash/config/.openclash-web-*|/etc/openclash/config/*.rollback.partial) rm -f "$input";; esac
    ;;
  rollback-latest)
    [ "$#" -eq 2 ] || hold ARGS 11
    current_sha=$(sha256sum "$main" | awk '{print $1}')
    committed=$(find "$backup_root" -mindepth 2 -maxdepth 2 -type f -name COMMITTED 2>/dev/null | while IFS= read -r marker; do
      grep -Eq '^(STATUS=COMMITTED|COMMITTED=PASS)$' "$marker" || continue
      candidate=${marker%/COMMITTED}/main.yaml
      [ -f "$candidate" ] && [ ! -L "$candidate" ] || continue
      [ "$(sha256sum "$candidate" | awk '{print $1}')" = "$current_sha" ] && continue
      printf '%s\n' "$marker"
    done | LC_ALL=C sort | tail -n 1)
    if [ -n "$committed" ]; then
      previous=${committed%/COMMITTED}/main.yaml
      previous_state=${committed%/COMMITTED}/customizations.state
    else
      previous=$(find "$backup_root" -mindepth 1 -maxdepth 1 -type f -name "*-${main##*/}" 2>/dev/null | while IFS= read -r candidate; do [ "$(sha256sum "$candidate" | awk '{print $1}')" = "$current_sha" ] || printf '%s\n' "$candidate"; done | LC_ALL=C sort | tail -n 1)
      previous_state=
    fi
    [ -n "$previous" ] && [ -f "$previous" ] && [ ! -L "$previous" ] || hold NO_BACKUP 50
    request=$state_root/replay.request
    rm -f "$request"
    if [ -f "$state" ]; then sed '/^OWNED_/d' "$state" >"$request"; else printf '%s\n' 'OPENCLASH_SYNC_CUSTOM_V1' >"$request"; fi
    chmod 0600 "$request"
    if [ -n "$previous_state" ] && [ -f "$previous_state" ] && [ ! -L "$previous_state" ]; then
      commit_render "$previous" "$request" rollback false "$previous_state" remove
    else
      commit_render "$previous" "$request" rollback false /dev/null overlay
    fi
    rm -f "$request"
    ;;
  inspect)
    [ "$#" -eq 2 ] || hold ARGS 11
    ruby "$customizer" inspect "$main" "$state" || hold INSPECT 50
    if [ -f "$state" ]; then state_sha=$(sha256sum "$state" | awk '{print $1}'); else state_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; fi
    printf 'STATE_SHA256\t%s\n' "$state_sha"
    printf 'CONFIG_SHA256\t%s\n' "$(sha256sum "$main" | awk '{print $1}')"
    ;;
  *) hold ACTION 60;;
esac
