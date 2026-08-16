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
backup_root=/etc/openclash/publisher-v4/web-backups
lock=$state_root/customizations.lock
[ -d "$web" ] && [ ! -L "$web" ] || hold WEB_ROOT 13
[ -f "$customizer" ] && [ ! -L "$customizer" ] || hold CUSTOMIZER 13
[ -x "$guard" ] && [ ! -L "$guard" ] || hold GUARD 13
[ -f "$main" ] && [ ! -L "$main" ] || hold MAIN 14
for directory in "$state_root" "$backup_root"; do
  [ ! -e "$directory" ] || { [ -d "$directory" ] && [ ! -L "$directory" ]; } || hold DIRECTORY 14
  mkdir -p "$directory"
done
[ ! -e "$state" ] || { [ -f "$state" ] && [ ! -L "$state" ]; } || hold STATE 14
chmod 0700 "$state_root" "$backup_root"
exec 9>"$lock"
flock -n 9 || hold LOCK 15

validate(){
  candidate=$1
  ruby -e 'require "yaml"; v=YAML.safe_load(File.binread(ARGV[0]), permitted_classes:[], aliases:false); abort unless v.is_a?(Hash) && v["rules"].is_a?(Array) && v["dns"].is_a?(Hash) && v["dns"]["fake-ip-filter"].is_a?(Array)' "$candidate" >/dev/null 2>&1 || return 1
  pid=$(pidof clash_meta 2>/dev/null || true)
  case "$pid" in ''|*' '*) return 1;; esac
  core=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
  [ -f "$core" ] || return 1
  "$core" -t -d /etc/openclash -f "$candidate" >/dev/null 2>&1
}

timestamp(){ date -u +%Y%m%dT%H%M%SZ; }

arm_guard(){
  activation_backup=$1
  guard_kind=$2
  case "$guard_kind" in runtime|static) ;; *) hold GUARD_MODE 25;; esac
  arm=$state_root/guard.$$.armed
  printf '%s\n' "$activation_backup" >"$arm"
  chmod 0600 "$arm"
  # guard 与其 sleep 子进程不得继承事务锁；否则事务完成后只读动作仍会
  # 被短暂误判为 LOCK。
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
  attempt=0
  while [ "$attempt" -lt 180 ]; do
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
    [ -f "$arm" ] && [ ! -L "$arm" ] || hold GUARD_DISARMED 26
    [ "$(sha256sum "$main" | awk '{print $1}')" = "$expected_config_sha" ] || continue
    [ "$(sha256sum "$state" | awk '{print $1}')" = "$expected_state_sha" ] || continue
    [ -f "$runtime" ] && [ ! -L "$runtime" ] || continue
    ruby "$customizer" verify-runtime "$main" "$runtime" "$state" >/dev/null 2>&1 || continue
    activation_verified=true
    return 0
  done
  "$guard" "$target" "$activation_backup" "$arm" restore-runtime >/dev/null 2>&1 || true
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
  committed_partial=$backup/COMMITTED.partial
  printf '%s\n' 'STATUS=COMMITTED' "ACTION=$label" >"$committed_partial"
  chmod 0600 "$committed_partial"
  main_partial=$main.custom.partial
  state_partial=$state.partial
  rm -f "$main_partial" "$state_partial"
  cp "$output" "$main_partial"
  cp "$output_state" "$state_partial"
  chmod 0600 "$main_partial" "$state_partial"
  rollback(){
    cp -p "$backup/main.yaml" "$main" 2>/dev/null || true
    if [ -f "$backup/customizations.state" ]; then cp -p "$backup/customizations.state" "$state" 2>/dev/null || true; else rm -f "$state" || true; fi
    rm -f "$main_partial" "$state_partial" || true
    rm -f "$backup/COMMITTED" "$committed_partial" || true
    # 若运行内核可能已读取新配置，也同步恢复运行态；中途断线时仍由
    # 独立 guard 完成同一恢复动作。
    if [ -n "$arm" ] && [ -f "$arm" ]; then
      "$guard" "$target" "$backup" "$arm" "restore-$guard_kind" >/dev/null 2>&1 || true
      [ -z "$guard_pid" ] || kill "$guard_pid" 2>/dev/null || true
      [ -z "$guard_pid" ] || wait "$guard_pid" 2>/dev/null || true
    elif [ "$activation_verified" = true ]; then
      /etc/init.d/openclash restart >/dev/null 2>&1 || true
    fi
  }
  trap rollback EXIT HUP INT TERM
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
  printf '%s\n' "CONFIG_SHA256=$config_sha" "STATE_SHA256=$state_sha" >>"$committed_partial"
  rm -rf "$tx"
  restart_performed=false
  if [ "$activate_after" = true ] && [ "$config_sha" != "$previous_config_sha" ]; then
    activate "$backup" "$config_sha" "$state_sha"
    restart_performed=true
  fi
  mv "$committed_partial" "$backup/COMMITTED"
  if [ -n "$arm" ]; then
    rm -f "$arm"
    kill "$guard_pid" 2>/dev/null || true
    wait "$guard_pid" 2>/dev/null || true
  fi
  trap - EXIT HUP INT TERM
  printf '%s\n' 'CUSTOM_TRANSACTION=PASS' "RULE_COUNT=$rule_count" "FAKE_FILTER_COUNT=$filter_count" "CONFIG_SHA256=$config_sha" "STATE_SHA256=$state_sha" "BACKUP=$backup" 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' "SERVICE_RESTARTED=$restart_performed"
}

case "$action" in
  apply)
    [ "$#" -eq 4 ] || hold ARGS 11
    request=$3
    expected=$4
    case "$expected" in *[!0-9a-f]*|'') hold EXPECTED_SHA 32;; esac
    [ "${#expected}" -eq 64 ] || hold EXPECTED_SHA 32
    if [ -f "$state" ]; then current_state_sha=$(sha256sum "$state" | awk '{print $1}'); else current_state_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; fi
    [ "$current_state_sha" = "$expected" ] || hold CONCURRENT_CHANGE 33
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
    case "$label" in stage-main|manual-write|rollback) ;; *) hold LABEL 40;; esac
    if [ "$label" = manual-write ]; then
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
      commit_render "$input" "$request" "$label" false /dev/null overlay
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
    ;;
  *) hold ACTION 60;;
esac
