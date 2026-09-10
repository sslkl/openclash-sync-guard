#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

failure_reason=UNKNOWN
hold(){ failure_reason=$1; printf 'ROUTER_WEB_UPDATE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
case "$1" in router_a|router_b) target=$1;; *) hold TARGET 12;; esac

publisher_root=/etc/openclash/publisher-v4
global_rollback_marker=$publisher_root/ROLLBACK-PREPARED
root=$publisher_root/web
state_root=$publisher_root/web-state
backup_root=$publisher_root/web-backups
backup=$backup_root/web-update-backup-$(date -u +%Y%m%dT%H%M%SZ)-$$
install_lock=/etc/openclash/.publisher-v4-install.lock
pending=$state_root/web-lifecycle.PENDING
pending_partial=$state_root/.web-lifecycle.PENDING.partial
prepared=$state_root/web-lifecycle.PREPARED
prepared_partial=$state_root/.web-lifecycle.PREPARED.partial
active_state=$state_root/web-lifecycle.ACTIVE
active_partial=$state_root/.web-lifecycle.ACTIVE.partial
main=/etc/openclash/config/ProviderBase-ProviderSource.yaml
runtime=/etc/openclash/ProviderBase-ProviderSource.yaml
custom_state=$state_root/customizations.state
auth=/etc/dropbear/authorized_keys
auth_dir=/etc/dropbear
auth_lock=$auth_dir/authorized_keys.lock

agent_source=/tmp/openclash-sync-web-agent.lua
forced_source=/tmp/openclash-sync-web-forced-command.sh
customizer_source=/tmp/openclash-sync-web-customizer.rb
transaction_source=/tmp/openclash-sync-web-custom-transaction.sh
guard_source=/tmp/openclash-sync-web-custom-rollback-guard.sh
source_stage=
source_stage_ready=false
temporary=
backup_ready=false
asset_mutation_started=false
committed=false
auth_before_sha=
pending_sha=
active_receipt_before_sha=

asset_names='openclash_web_router_agent.lua openclash_web_forced_command.sh openclash_customizer.rb openclash_custom_transaction.sh openclash_custom_rollback_guard.sh'
asset_manifest='openclash_web_router_agent.lua:/tmp/openclash-sync-web-agent.lua openclash_web_forced_command.sh:/tmp/openclash-sync-web-forced-command.sh openclash_customizer.rb:/tmp/openclash-sync-web-customizer.rb openclash_custom_transaction.sh:/tmp/openclash-sync-web-custom-transaction.sh openclash_custom_rollback_guard.sh:/tmp/openclash-sync-web-custom-rollback-guard.sh'

expected_hash(){
  case "$1" in
    openclash_web_router_agent.lua) printf '%s\n' 1d2e743f9a8d8f557a8caaddcffca67c182ce7415b0a167c6bfc108c76299eab;;
    openclash_web_forced_command.sh) printf '%s\n' 55c9870ba09c2d4f1c5107c6ee241eccde26b116bafa7ecb980210b75416c5c4;;
    openclash_customizer.rb) printf '%s\n' 62ca66cfe84c7cec4338871b692014a320e2e7a94f183a120f4c35d7f59bee22;;
    openclash_custom_transaction.sh) printf '%s\n' 99fbcc8c8ffb5eb8ed1a54ed28be3ec0312c6b2069602e904fb74a6d5e14b0a2;;
    openclash_custom_rollback_guard.sh) printf '%s\n' 3a088746b462e6b1201cf0ce8f472b7d6771aa0214328500163872b5638c404a;;
    *) return 1;;
  esac
}
fsync_file(){ ruby -e 'File.open(ARGV.fetch(0), "r") { |file| file.fsync }' "$1"; }
fsync_path(){ fsync_file "$1"; }
fsync_directory(){ ruby -e 'File.open(ARGV.fetch(0), "r") { |directory| directory.fsync }' "$1"; }
sha(){
  sha_output=$(sha256sum "$1") || return 1
  sha_digest=${sha_output%% *}
  valid_digest "$sha_digest" || return 1
  printf '%s' "$sha_digest"
}
sha_text(){ ruby -rdigest -e 'print Digest::SHA256.hexdigest(ARGV.fetch(0))' "$1"; }
# Preserve metadata-read failures: ls | awk would return awk's success status.
# Ruby is already required by this installer; lstat rejects directory/symlink inputs.
inode(){ ruby -e 's = File.lstat(ARGV.fetch(0)); exit 1 unless s.file?; print s.ino' -- "$1" 2>/dev/null; }
valid_digest(){
  case "$1" in *[!0-9a-f]*|'') return 1;; esac
  [ "${#1}" -eq 64 ]
}
trusted_file(){
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(ls -ln "$1" 2>/dev/null | awk '{print $1 ":" $3 ":" $4}')" = "$2:0:0" ] || return 1
  ruby -e 'exit(File.lstat(ARGV.fetch(0)).nlink == 1 ? 0 : 1)' "$1"
}
trusted_directory(){
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(ls -ldn "$1" 2>/dev/null | awk '{print $1 ":" $3 ":" $4}')" = "$2:0:0" ]
}
journal_value(){
  journal_path=$1; journal_key=$2
  journal_result=$(awk -v key="$journal_key" 'index($0, key "=") == 1 {print substr($0, length(key) + 2)}' "$journal_path")
  [ "$(printf '%s\n' "$journal_result" | wc -l | tr -d ' ')" -eq 1 ] || return 1
  [ -n "$journal_result" ] || return 1
  printf '%s' "$journal_result"
}
journal_schema_ok(){
  journal_path=$1 marker=$2 expected_lines=$3; shift 3
  trusted_file "$journal_path" -rw------- || return 1
  [ "$(wc -l <"$journal_path" | tr -d ' ')" -eq "$expected_lines" ] || return 1
  [ "$(grep -Fxc "$marker" "$journal_path" || true)" -eq 1 ] || return 1
  [ "$(( $# + 1 ))" -eq "$expected_lines" ] || return 1
  for journal_key in "$@"; do journal_value "$journal_path" "$journal_key" >/dev/null || return 1; done
}
pending_schema_ok(){
  pending_path=$1 expected_op=$2 expected_backup=$3
  journal_schema_ok "$pending_path" PENDING 5 SCHEMA OP TARGET BACKUP_PATH || return 1
  [ "$(journal_value "$pending_path" SCHEMA)" = publisher-v4-router-web-pending-v1 ] || return 1
  [ "$(journal_value "$pending_path" OP)" = "$expected_op" ] || return 1
  [ "$(journal_value "$pending_path" TARGET)" = "$target" ] || return 1
  [ "$(journal_value "$pending_path" BACKUP_PATH)" = "$expected_backup" ]
}
prepared_update_schema_ok_v2(){
  journal_path=$1
  journal_schema_ok "$journal_path" PREPARED 41 SCHEMA OP TARGET BACKUP_PATH ROOT_PATH BACKUP_MANIFEST_SHA256 \
    PENDING_PATH PENDING_SHA256 ACTIVE_RECEIPT_BEFORE_PATH ACTIVE_RECEIPT_BEFORE_SHA256 \
    ACTIVE_BEFORE_SHA256 UCI_BEFORE_SHA256 CORE_SHA256 CORE_PID_BEFORE CORE_START_BEFORE \
    MAIN_BEFORE_SHA256 RUNTIME_BEFORE_SHA256 CUSTOM_STATE_BEFORE_SHA256 \
    OPENCLASH_WEB_ROUTER_AGENT_LUA_TARGET OPENCLASH_WEB_ROUTER_AGENT_LUA_BEFORE_SHA256 OPENCLASH_WEB_ROUTER_AGENT_LUA_AFTER_SHA256 OPENCLASH_WEB_ROUTER_AGENT_LUA_SOURCE_INODE \
    OPENCLASH_WEB_FORCED_COMMAND_SH_TARGET OPENCLASH_WEB_FORCED_COMMAND_SH_BEFORE_SHA256 OPENCLASH_WEB_FORCED_COMMAND_SH_AFTER_SHA256 OPENCLASH_WEB_FORCED_COMMAND_SH_SOURCE_INODE \
    OPENCLASH_CUSTOMIZER_RB_TARGET OPENCLASH_CUSTOMIZER_RB_BEFORE_SHA256 OPENCLASH_CUSTOMIZER_RB_AFTER_SHA256 OPENCLASH_CUSTOMIZER_RB_SOURCE_INODE \
    OPENCLASH_CUSTOM_TRANSACTION_SH_TARGET OPENCLASH_CUSTOM_TRANSACTION_SH_BEFORE_SHA256 OPENCLASH_CUSTOM_TRANSACTION_SH_AFTER_SHA256 OPENCLASH_CUSTOM_TRANSACTION_SH_SOURCE_INODE \
    OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_TARGET OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_BEFORE_SHA256 OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_AFTER_SHA256 OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_SOURCE_INODE \
    AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 || return 1
  [ "$(journal_value "$journal_path" SCHEMA)" = publisher-v4-router-web-update-prepared-v2 ] &&
  [ "$(journal_value "$journal_path" OP)" = UPDATE ] &&
  [ "$(journal_value "$journal_path" TARGET)" = "$target" ] &&
  [ "$(journal_value "$journal_path" PENDING_PATH)" = "$pending" ] &&
  [ "$(journal_value "$journal_path" ACTIVE_RECEIPT_BEFORE_PATH)" = "$active_state" ] || return 1
  for key in PENDING_SHA256 ACTIVE_RECEIPT_BEFORE_SHA256 AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256; do
    valid_digest "$(journal_value "$journal_path" "$key")" || return 1
  done
  [ "$(journal_value "$journal_path" AUTHORIZED_KEYS_BEFORE_SHA256)" = "$(journal_value "$journal_path" AUTHORIZED_KEYS_AFTER_SHA256)" ]
}
prepared_update_schema_ok(){ prepared_update_schema_ok_v2 "$1"; }
committed_common_v3(){
  receipt=$1
  [ "$(journal_value "$receipt" TARGET)" = "$target" ] &&
  [ "$(journal_value "$receipt" CONFIG_CHANGED)" = false ] &&
  [ "$(journal_value "$receipt" SERVICE_RESTARTED)" = false ] || return 1
  for digest_key in ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 \
    MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 \
    AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 PENDING_SHA256 PREPARED_SHA256; do
    digest_value=$(journal_value "$receipt" "$digest_key") || return 1
    valid_digest "$digest_value" || return 1
  done
  for receipt_name in $asset_names; do valid_digest "$(journal_value "$receipt" "${receipt_name}_AFTER_SHA256")" || return 1; done
  for numeric_key in CORE_PID_BEFORE CORE_START_BEFORE CORE_PID_AFTER CORE_START_AFTER; do
    numeric_value=$(journal_value "$receipt" "$numeric_key") || return 1
    case "$numeric_value" in ''|*[!0-9]*) return 1;; esac
  done
  [ "$(journal_value "$receipt" ACTIVE_BEFORE_SHA256)" = "$(journal_value "$receipt" ACTIVE_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" UCI_BEFORE_SHA256)" = "$(journal_value "$receipt" UCI_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" MAIN_BEFORE_SHA256)" = "$(journal_value "$receipt" MAIN_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" RUNTIME_BEFORE_SHA256)" = "$(journal_value "$receipt" RUNTIME_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" CUSTOM_STATE_BEFORE_SHA256)" = "$(journal_value "$receipt" CUSTOM_STATE_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" CORE_PID_BEFORE)" = "$(journal_value "$receipt" CORE_PID_AFTER)" ] &&
  [ "$(journal_value "$receipt" CORE_START_BEFORE)" = "$(journal_value "$receipt" CORE_START_AFTER)" ]
}
committed_install_schema_ok_legacy(){
  receipt=$1
  journal_schema_ok "$receipt" COMMITTED 27 SCHEMA TARGET ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 \
    UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 CORE_PID_BEFORE CORE_START_BEFORE CORE_PID_AFTER CORE_START_AFTER \
    MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 \
    CONFIG_CHANGED SERVICE_RESTARTED openclash_web_router_agent.lua_AFTER_SHA256 openclash_web_forced_command.sh_AFTER_SHA256 \
    openclash_customizer.rb_AFTER_SHA256 openclash_custom_transaction.sh_AFTER_SHA256 openclash_custom_rollback_guard.sh_AFTER_SHA256 \
    AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 || return 1
  [ "$(journal_value "$receipt" SCHEMA)" = publisher-v4-router-web-install-v2 ] || return 1
  [ "$(journal_value "$receipt" TARGET)" = "$target" ] && [ "$(journal_value "$receipt" CONFIG_CHANGED)" = false ] && [ "$(journal_value "$receipt" SERVICE_RESTARTED)" = false ] || return 1
  for key in ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256; do valid_digest "$(journal_value "$receipt" "$key")" || return 1; done
  for name in $asset_names; do valid_digest "$(journal_value "$receipt" "${name}_AFTER_SHA256")" || return 1; done
  for key in CORE_PID_BEFORE CORE_START_BEFORE CORE_PID_AFTER CORE_START_AFTER; do value=$(journal_value "$receipt" "$key") || return 1; case "$value" in ''|*[!0-9]*) return 1;; esac; done
  [ "$(journal_value "$receipt" ACTIVE_BEFORE_SHA256)" = "$(journal_value "$receipt" ACTIVE_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" UCI_BEFORE_SHA256)" = "$(journal_value "$receipt" UCI_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" MAIN_BEFORE_SHA256)" = "$(journal_value "$receipt" MAIN_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" RUNTIME_BEFORE_SHA256)" = "$(journal_value "$receipt" RUNTIME_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" CUSTOM_STATE_BEFORE_SHA256)" = "$(journal_value "$receipt" CUSTOM_STATE_AFTER_SHA256)" ] &&
  [ "$(journal_value "$receipt" CORE_PID_BEFORE)" = "$(journal_value "$receipt" CORE_PID_AFTER)" ] &&
  [ "$(journal_value "$receipt" CORE_START_BEFORE)" = "$(journal_value "$receipt" CORE_START_AFTER)" ]
}
committed_install_schema_ok_v3(){
  receipt=$1
  journal_schema_ok "$receipt" COMMITTED 29 SCHEMA TARGET ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 \
    UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 CORE_PID_BEFORE CORE_START_BEFORE CORE_PID_AFTER CORE_START_AFTER \
    MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 \
    CONFIG_CHANGED SERVICE_RESTARTED openclash_web_router_agent.lua_AFTER_SHA256 openclash_web_forced_command.sh_AFTER_SHA256 \
    openclash_customizer.rb_AFTER_SHA256 openclash_custom_transaction.sh_AFTER_SHA256 openclash_custom_rollback_guard.sh_AFTER_SHA256 \
    AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 PENDING_SHA256 PREPARED_SHA256 || return 1
  [ "$(journal_value "$receipt" SCHEMA)" = publisher-v4-router-web-install-v3 ] || return 1
  committed_common_v3 "$receipt"
}
committed_update_schema_ok_v3(){
  receipt=$1
  journal_schema_ok "$receipt" COMMITTED 31 SCHEMA TARGET ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 \
    UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 CORE_PID_BEFORE CORE_START_BEFORE CORE_PID_AFTER CORE_START_AFTER \
    MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 \
    CONFIG_CHANGED SERVICE_RESTARTED openclash_web_router_agent.lua_AFTER_SHA256 openclash_web_forced_command.sh_AFTER_SHA256 \
    openclash_customizer.rb_AFTER_SHA256 openclash_custom_transaction.sh_AFTER_SHA256 openclash_custom_rollback_guard.sh_AFTER_SHA256 \
    AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 PENDING_SHA256 PREPARED_SHA256 \
    ACTIVE_RECEIPT_BEFORE_PATH ACTIVE_RECEIPT_BEFORE_SHA256 || return 1
  [ "$(journal_value "$receipt" SCHEMA)" = publisher-v4-router-web-update-v3 ] || return 1
  [ "$(journal_value "$receipt" ACTIVE_RECEIPT_BEFORE_PATH)" = "$active_state" ] || return 1
  valid_digest "$(journal_value "$receipt" ACTIVE_RECEIPT_BEFORE_SHA256)" || return 1
  [ "$(journal_value "$receipt" AUTHORIZED_KEYS_BEFORE_SHA256)" = "$(journal_value "$receipt" AUTHORIZED_KEYS_AFTER_SHA256)" ] || return 1
  committed_common_v3 "$receipt"
}
committed_install_schema_ok(){
  case "$(journal_value "$1" SCHEMA 2>/dev/null || true)" in
    publisher-v4-router-web-install-v2) committed_install_schema_ok_legacy "$1";;
    publisher-v4-router-web-install-v3) committed_install_schema_ok_v3 "$1";;
    *) return 1;;
  esac
}
committed_update_schema_ok(){ committed_update_schema_ok_v3 "$1"; }
active_schema_ok(){
  active_path=$1 expected_op=$2 expected_backup=$3
  active_schema=$(journal_value "$active_path" SCHEMA) || return 1
  case "$active_schema" in
    publisher-v4-router-web-active-v1)
      journal_schema_ok "$active_path" ACTIVE 6 SCHEMA OP TARGET BACKUP_PATH COMMITTED_SHA256 || return 1
      [ "$expected_op" = INSTALL ] || return 1;;
    publisher-v4-router-web-active-v2)
      journal_schema_ok "$active_path" ACTIVE 8 SCHEMA OP TARGET BACKUP_PATH COMMITTED_SHA256 PENDING_SHA256 PREPARED_SHA256 || return 1
      valid_digest "$(journal_value "$active_path" PENDING_SHA256)" || return 1
      valid_digest "$(journal_value "$active_path" PREPARED_SHA256)" || return 1;;
    *) return 1;;
  esac
  [ "$(journal_value "$active_path" OP)" = "$expected_op" ] && [ "$(journal_value "$active_path" TARGET)" = "$target" ] &&
    [ "$(journal_value "$active_path" BACKUP_PATH)" = "$expected_backup" ] || return 1
  active_committed_sha=$(journal_value "$active_path" COMMITTED_SHA256) || return 1
  valid_digest "$active_committed_sha" || return 1
  [ "$active_committed_sha" = "$(sha "$expected_backup/COMMITTED")" ] || return 1
  if [ "$active_schema" = publisher-v4-router-web-active-v2 ]; then
    [ "$(journal_value "$active_path" PENDING_SHA256)" = "$(journal_value "$expected_backup/COMMITTED" PENDING_SHA256)" ] || return 1
    [ "$(journal_value "$active_path" PREPARED_SHA256)" = "$(journal_value "$expected_backup/COMMITTED" PREPARED_SHA256)" ] || return 1
  fi
}
file_state(){
  state_path=$1
  expected_mode=${2:--r-x------}
  if [ ! -e "$state_path" ] && [ ! -L "$state_path" ]; then
    printf '%s' MISSING
  elif trusted_file "$state_path" "$expected_mode"; then
    sha "$state_path"
  else
    printf '%s' INVALID
  fi
}
valid_backup_path(){
  candidate=$1
  prefix=$2
  [ "${candidate%/*}" = "$backup_root" ] || return 1
  printf '%s\n' "${candidate##*/}" | grep -Eq "^${prefix}[0-9]{8}T[0-9]{6}Z-[0-9]+$"
}
receipt_runtime_stable_matches(){
  runtime_receipt=$1
  /etc/init.d/openclash running >/dev/null 2>&1 &&
  [ "$(journal_value "$runtime_receipt" ACTIVE_AFTER_SHA256)" = "$(sha_text "$active_before")" ] &&
  [ "$(journal_value "$runtime_receipt" UCI_AFTER_SHA256)" = "$uci_before_sha" ] &&
  [ "$(journal_value "$runtime_receipt" CORE_SHA256)" = "$core_sha_before" ] &&
  [ "$(journal_value "$runtime_receipt" MAIN_AFTER_SHA256)" = "$main_before_sha" ] &&
  [ "$(journal_value "$runtime_receipt" RUNTIME_AFTER_SHA256)" = "$runtime_before_sha" ] &&
  [ "$(journal_value "$runtime_receipt" CUSTOM_STATE_AFTER_SHA256)" = "$state_before_sha" ] &&
  [ "$(journal_value "$runtime_receipt" CONFIG_CHANGED)" = false ] &&
    [ "$(journal_value "$runtime_receipt" SERVICE_RESTARTED)" = false ]
}
prepared_runtime_stable_matches(){
  runtime_journal=$1
  /etc/init.d/openclash running >/dev/null 2>&1 &&
  [ "$(journal_value "$runtime_journal" ACTIVE_BEFORE_SHA256)" = "$(sha_text "$active_before")" ] &&
  [ "$(journal_value "$runtime_journal" UCI_BEFORE_SHA256)" = "$uci_before_sha" ] &&
  [ "$(journal_value "$runtime_journal" CORE_SHA256)" = "$core_sha_before" ] &&
  [ "$(journal_value "$runtime_journal" MAIN_BEFORE_SHA256)" = "$main_before_sha" ] &&
  [ "$(journal_value "$runtime_journal" RUNTIME_BEFORE_SHA256)" = "$runtime_before_sha" ] &&
  [ "$(journal_value "$runtime_journal" CUSTOM_STATE_BEFORE_SHA256)" = "$state_before_sha" ]
}
receipt_auth_stable_matches(){
  auth_receipt=$1
  expected_auth=$(journal_value "$auth_receipt" AUTHORIZED_KEYS_AFTER_SHA256) || return 1
  valid_digest "$expected_auth" || return 1
  [ "$(file_state "$auth" -rw-------)" = "$expected_auth" ]
}
committed_history_matches_prepared(){
  history_prepared=$1 history_receipt=$2 history_op=$3
  prepared_digest=$(sha "$history_prepared") || return 1
  [ "$(journal_value "$history_receipt" PREPARED_SHA256)" = "$prepared_digest" ] || return 1
  [ "$(journal_value "$history_receipt" PENDING_SHA256)" = "$(journal_value "$history_prepared" PENDING_SHA256)" ] || return 1
  for history_key in ACTIVE_BEFORE_SHA256 UCI_BEFORE_SHA256 CORE_SHA256 CORE_PID_BEFORE CORE_START_BEFORE \
    MAIN_BEFORE_SHA256 RUNTIME_BEFORE_SHA256 CUSTOM_STATE_BEFORE_SHA256 AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256; do
    [ "$(journal_value "$history_receipt" "$history_key")" = "$(journal_value "$history_prepared" "$history_key")" ] || return 1
  done
  for history_name in $asset_names; do
    history_key=$(printf '%s' "$history_name" | tr 'a-z.-' 'A-Z__')
    [ "$(journal_value "$history_receipt" "${history_name}_AFTER_SHA256")" = "$(journal_value "$history_prepared" "${history_key}_AFTER_SHA256")" ] || return 1
  done
  if [ "$history_op" = UPDATE ]; then
    [ "$(journal_value "$history_receipt" ACTIVE_RECEIPT_BEFORE_PATH)" = "$(journal_value "$history_prepared" ACTIVE_RECEIPT_BEFORE_PATH)" ] || return 1
    [ "$(journal_value "$history_receipt" ACTIVE_RECEIPT_BEFORE_SHA256)" = "$(journal_value "$history_prepared" ACTIVE_RECEIPT_BEFORE_SHA256)" ] || return 1
  fi
}
lock_binding(){
  ruby -e 'path,fd=ARGV; a=File.stat(path); b=File.stat("/proc/self/fd/#{fd}"); raise unless a.dev==b.dev && a.ino==b.ino && a.uid==0 && a.gid==0 && a.nlink==1 && b.nlink==1 && (a.mode & 0o7777)==0o600' "$1" "$2"
}
ensure_lock_file(){
  lock_path=$1; lock_parent=$2
  if [ ! -e "$lock_path" ] && [ ! -L "$lock_path" ]; then
    ruby -e 'path=ARGV.fetch(0); flags=File::RDWR|File::CREAT|File::EXCL; flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW); begin; file=File.open(path,flags,0600); file.chmod(0600); file.fsync; file.close; rescue Errno::EEXIST; end' "$lock_path" || return 1
  fi
  trusted_file "$lock_path" -rw------- || return 1
  fsync_directory "$lock_parent"
}
source_bundle_ok(){
  bundle_path=$1
  bundle_kind=$2
  bundle_complete=$3
  trusted_directory "$bundle_path" drwx------ || return 1
  ruby -e '
    path,kind,complete=ARGV
    assets=%w[openclash_web_router_agent.lua openclash_web_forced_command.sh openclash_customizer.rb openclash_custom_transaction.sh openclash_custom_rollback_guard.sh]
    expected=assets + (kind=="INSTALL" ? ["public_key"] : [])
    raise unless %w[INSTALL UPDATE].include?(kind)
    actual=Dir.children(path)
    raise unless complete=="true" ? actual.sort==expected.sort : (actual-expected).empty?
    actual.each do |name|
      entry=File.lstat(File.join(path,name))
      raise unless entry.file? && !entry.symlink? && entry.uid==0 && entry.gid==0 &&
        (entry.mode & 0o7777)==0o600 && entry.nlink==1
    end
  ' "$bundle_path" "$bundle_kind" "$bundle_complete"
}
web_access_disabled_digest(){
  disabled_source=$1
  ruby -rdigest -e '
    source,needle,marker=ARGV
    data=File.binread(source)
    marker_re=/(?:\A|[ \t])#{Regexp.escape(marker)}(?:\r?\n)?\z/
    filtered=data.lines.reject { |line| line.include?(needle) || line.match?(marker_re) }.join
    print Digest::SHA256.hexdigest(filtered)
  ' "$disabled_source" "command=\"$root/openclash_web_forced_command.sh $target\"" "openclash-web-$target"
}
atomic_restore_authorized_keys(){
  restore_source=$1
  restore_current_sha=$2
  restore_target_sha=$3
  trusted_file "$restore_source" -rw------- || return 1
  trusted_file "$auth" -rw------- || return 1
  [ "$(sha "$restore_source")" = "$restore_target_sha" ] || return 1
  [ "$(sha "$auth")" = "$restore_current_sha" ] || return 1
  restore_auth_temporary=$(mktemp "$auth_dir/authorized_keys.new.XXXXXX") || return 1
  cp "$restore_source" "$restore_auth_temporary" || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  chown 0:0 "$restore_auth_temporary" || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  chmod 0600 "$restore_auth_temporary" || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  trusted_file "$restore_auth_temporary" -rw------- || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  cmp -s "$restore_source" "$restore_auth_temporary" || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  fsync_path "$restore_auth_temporary" || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  [ "$(sha "$auth")" = "$restore_current_sha" ] || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  mv -f "$restore_auth_temporary" "$auth" || { rm -f "$restore_auth_temporary" 2>/dev/null || true; return 1; }
  fsync_path "$auth" || return 1
  fsync_directory "$auth_dir" || return 1
  [ "$(file_state "$auth" -rw-------)" = "$restore_target_sha" ]
}
stop_web_access_for_recovery(){
  trusted_file "$auth" -rw------- || return 1
  fail_closed_before_inode=$(inode "$auth") || return 1
  fail_closed_before_sha=$(sha "$auth") || return 1
  fail_closed_temporary=$(mktemp "$auth_dir/authorized_keys.web-disable.XXXXXX") || return 1
  if ! ruby -e '
    source,target,needle,marker=ARGV
    data=File.binread(source)
    marker_re=/(?:\A|[ \t])#{Regexp.escape(marker)}(?:\r?\n)?\z/
    filtered=data.lines.reject { |line| line.include?(needle) || line.match?(marker_re) }.join
    File.binwrite(target,filtered)
  ' "$auth" "$fail_closed_temporary" \
    "command=\"$root/openclash_web_forced_command.sh $target\"" "openclash-web-$target"; then
    rm -f "$fail_closed_temporary" 2>/dev/null || true
    return 1
  fi
  chown 0:0 "$fail_closed_temporary" || { rm -f "$fail_closed_temporary" 2>/dev/null || true; return 1; }
  chmod 0600 "$fail_closed_temporary" || { rm -f "$fail_closed_temporary" 2>/dev/null || true; return 1; }
  trusted_file "$fail_closed_temporary" -rw------- || { rm -f "$fail_closed_temporary" 2>/dev/null || true; return 1; }
  fsync_path "$fail_closed_temporary" || { rm -f "$fail_closed_temporary" 2>/dev/null || true; return 1; }
  [ "$(inode "$auth")" = "$fail_closed_before_inode" ] && [ "$(sha "$auth")" = "$fail_closed_before_sha" ] || {
    rm -f "$fail_closed_temporary" 2>/dev/null || true
    return 1
  }
  mv -f "$fail_closed_temporary" "$auth" || { rm -f "$fail_closed_temporary" 2>/dev/null || true; return 1; }
  fsync_path "$auth" || return 1
  fsync_directory "$auth_dir" || return 1
  ! grep -Fq "command=\"$root/openclash_web_forced_command.sh $target\"" "$auth" || return 1
  ! grep -Fq "openclash-web-$target" "$auth"
}
recovery_hold(){
  recovery_reason=$1
  recovery_code=$2
  if stop_web_access_for_recovery; then
    printf '%s\n' 'WEB_ACCESS_DISABLED=true'
    hold "$recovery_reason" "$recovery_code"
  fi
  printf '%s\n' 'WEB_ACCESS_DISABLED=false'
  hold "${recovery_reason}_WEB_ACCESS_STOP_FAILED" "$recovery_code"
}
atomic_publish_stream(){
  target_path=$1; partial_path=$2
  ruby -e '
    target,partial=ARGV; directory=File.dirname(target)
    raise unless File.dirname(partial)==directory
    raise if File.exist?(target) || File.symlink?(target) || File.exist?(partial) || File.symlink?(partial)
    flags=File::WRONLY|File::CREAT|File::EXCL; flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
    file=File.open(partial,flags,0600)
    begin
      while chunk=STDIN.read(65536)
        break if chunk.empty?
        file.write(chunk)
      end
      file.flush; file.fsync
    ensure
      file.close
    end
    File.rename(partial,target); File.open(directory,"r") { |entry| entry.fsync }
  ' "$target_path" "$partial_path"
}
atomic_replace_stream(){
  target_path=$1; partial_path=$2
  ruby -e '
    target,partial=ARGV; directory=File.dirname(target)
    raise unless File.dirname(partial)==directory
    raise if File.exist?(partial) || File.symlink?(partial)
    raise if File.symlink?(target)
    flags=File::WRONLY|File::CREAT|File::EXCL; flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
    file=File.open(partial,flags,0600)
    begin
      while chunk=STDIN.read(65536)
        break if chunk.empty?
        file.write(chunk)
      end
      file.flush; file.fsync
    ensure
      file.close
    end
    File.rename(partial,target); File.open(directory,"r") { |entry| entry.fsync }
  ' "$target_path" "$partial_path"
}
publish_pending(){
  pending_op=$1 pending_backup=$2
  [ ! -e "$pending" ] && [ ! -L "$pending" ] && [ ! -e "$pending_partial" ] && [ ! -L "$pending_partial" ] || return 1
  printf '%s\n' PENDING 'SCHEMA=publisher-v4-router-web-pending-v1' "OP=$pending_op" "TARGET=$target" \
    "BACKUP_PATH=$pending_backup" | atomic_publish_stream "$pending" "$pending_partial" || return 1
  pending_schema_ok "$pending" "$pending_op" "$pending_backup" || return 1
}
normalize_pending_partial(){
  [ -e "$pending_partial" ] || [ -L "$pending_partial" ] || return 0
  [ ! -e "$pending" ] && [ ! -L "$pending" ] || return 2
  trusted_file "$pending_partial" -rw------- || return 2
  partial_op=$(journal_value "$pending_partial" OP 2>/dev/null || true)
  partial_backup=$(journal_value "$pending_partial" BACKUP_PATH 2>/dev/null || true)
  case "$partial_op" in INSTALL) partial_prefix=web-install-backup-;; UPDATE) partial_prefix=web-update-backup-;; *) partial_prefix=;; esac
  if [ -z "$partial_prefix" ] || ! valid_backup_path "$partial_backup" "$partial_prefix" ||
    ! pending_schema_ok "$pending_partial" "$partial_op" "$partial_backup"; then
    rm -f "$pending_partial" || return 2
    fsync_directory "$state_root" || return 2
    return 0
  fi
  mv "$pending_partial" "$pending" || return 2
  fsync_directory "$state_root" || return 2
}
cleanup_pending_backup(){
  orphan_backup=$1 orphan_op=$2
  [ ! -e "$orphan_backup" ] && [ ! -L "$orphan_backup" ] && return 0
  trusted_directory "$orphan_backup" drwx------ || return 1
  ruby -e '
    backup,backup_root,op=ARGV
    assets=%w[openclash_web_router_agent.lua openclash_web_forced_command.sh openclash_customizer.rb openclash_custom_transaction.sh openclash_custom_rollback_guard.sh]
    source_allowed=assets + (op=="INSTALL" ? ["public_key"] : [])
    top_allowed=["SHA256SUMS.before","PREPARED.payload"]
    if op=="INSTALL"
      top_allowed += assets.map { |name| "#{name}.absent" }; top_allowed += %w[authorized_keys.before authorized_keys.after]
    elsif op=="UPDATE"
      top_allowed += assets.flat_map { |name| ["#{name}.before","#{name}.absent"] }
      top_allowed << "authorized_keys.before"
    else
      raise
    end
    root=File.lstat(backup); raise unless root.directory? && !root.symlink? && root.uid==0 && root.gid==0 && (root.mode & 0o7777)==0o700
    source=File.join(backup,"source"); top_files=[]; source_files=[]
    Dir.children(backup).each do |name|
      path=File.join(backup,name); st=File.lstat(path)
      if name=="source"
        raise unless st.directory? && !st.symlink? && st.uid==0 && st.gid==0 && (st.mode & 0o7777)==0o700
        Dir.children(path).each do |child|
          raise unless source_allowed.include?(child)
          child_path=File.join(path,child); child_st=File.lstat(child_path)
          raise unless child_st.file? && !child_st.symlink? && child_st.uid==0 && child_st.gid==0 && (child_st.mode & 0o7777)==0o600 && child_st.nlink==1
          source_files << child_path
        end
      else
        raise unless top_allowed.include?(name)
        raise unless st.file? && !st.symlink? && st.uid==0 && st.gid==0 && (st.mode & 0o7777)==0o600 && st.nlink==1
        top_files << path
      end
    end
    source_files.each { |path| File.unlink(path) }
    if File.directory?(source) && !File.symlink?(source); File.open(source,"r") { |directory| directory.fsync }; Dir.rmdir(source); end
    top_files.each { |path| File.unlink(path) }
    File.open(backup,"r") { |directory| directory.fsync }; Dir.rmdir(backup)
    File.open(backup_root,"r") { |directory| directory.fsync }
  ' "$orphan_backup" "$backup_root" "$orphan_op"
}
recover_pending_without_prepared(){
  [ ! -e "$prepared" ] && [ ! -L "$prepared" ] || return 2
  [ -e "$pending" ] || [ -L "$pending" ] || return 0
  trusted_file "$pending" -rw------- || return 2
  orphan_op=$(journal_value "$pending" OP) || return 2
  orphan_backup=$(journal_value "$pending" BACKUP_PATH) || return 2
  case "$orphan_op" in INSTALL) valid_backup_path "$orphan_backup" web-install-backup- || return 2;; UPDATE) valid_backup_path "$orphan_backup" web-update-backup- || return 2;; *) return 2;; esac
  pending_schema_ok "$pending" "$orphan_op" "$orphan_backup" || return 2
  orphan_pending_sha=$(sha "$pending") || return 2
  if [ -e "$active_state" ] || [ -L "$active_state" ]; then
    active_backup_for_pending=$(journal_value "$active_state" BACKUP_PATH) || return 2
    if [ "$active_backup_for_pending" = "$orphan_backup" ]; then
      [ "$(journal_value "$active_state" SCHEMA)" = publisher-v4-router-web-active-v2 ] || return 2
      active_schema_ok "$active_state" "$orphan_op" "$orphan_backup" || return 2
      [ "$(journal_value "$active_state" PENDING_SHA256)" = "$orphan_pending_sha" ] || return 2
      rm -f "$pending" || return 3
      fsync_directory "$state_root" || return 3
      return 0
    fi
  fi
  if [ -e "$orphan_backup/ROLLED_BACK" ] || [ -L "$orphan_backup/ROLLED_BACK" ]; then
    trusted_directory "$orphan_backup" drwx------ || return 2
    status_schema_ok "$orphan_backup/ROLLED_BACK" ROLLED_BACK || return 2
    [ "$(journal_value "$orphan_backup/ROLLED_BACK" REASON)" = RECOVERED_TO_BEFORE ] || return 2
    [ "$(journal_value "$orphan_backup/ROLLED_BACK" PENDING_SHA256)" = "$orphan_pending_sha" ] || return 2
    [ ! -e "$orphan_backup/COMMITTED" ] && [ ! -L "$orphan_backup/COMMITTED" ] || return 2
    rm -f "$pending" || return 3
    fsync_directory "$state_root" || return 3
    return 0
  fi
  cleanup_pending_backup "$orphan_backup" "$orphan_op" || return 3
  rm -f "$pending" || return 3
  fsync_directory "$state_root"
}
complete_lifecycle_journals(){
  expected_pending_sha=$1
  pending_op=$(journal_value "$pending" OP) || return 1
  pending_backup=$(journal_value "$pending" BACKUP_PATH) || return 1
  pending_schema_ok "$pending" "$pending_op" "$pending_backup" || return 1
  [ "$(sha "$pending")" = "$expected_pending_sha" ] || return 1
  rm -f "$prepared" || return 1
  fsync_directory "$state_root" || return 1
  rm -f "$pending" || return 1
  fsync_directory "$state_root" || return 1
}
pending_exit(){
  exit_code=$?
  printf '%s\n' 'ROUTER_WEB_UPDATE=RECOVERY_REQUIRED' "TARGET=$target" "BACKUP=$backup" 'PHASE=PENDING'
  exit "$exit_code"
}
source_metadata(){
  source=$1
  [ -f "$source" ] && [ ! -L "$source" ] || hold SOURCE_ASSET 14
  [ "$(ls -ln "$source" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold SOURCE_METADATA 14
  ruby -e 'exit(File.lstat(ARGV.fetch(0)).nlink == 1 ? 0 : 1)' "$source" || hold SOURCE_HARDLINK 14
}
installed_metadata(){
  [ -f "$1" ] && [ ! -L "$1" ] &&
    [ "$(ls -ln "$1" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] &&
    ruby -e 'exit(File.lstat(ARGV.fetch(0)).nlink == 1 ? 0 : 1)' "$1"
}
process_starttime(){
  ruby -e 'text=File.binread("/proc/#{ARGV.fetch(0)}/stat",4096).chomp; match=text.match(/\A[0-9]+ \(.+\) [A-Z] (.+)\z/); value=match && match[1].split[18]; abort unless value&.match?(/\A[0-9]+\z/); puts value' "$1"
}
uci_digest(){
  uci_text=$(uci -q show openclash) || return 1
  [ -n "$uci_text" ] || return 1
  printf '%s\n' "$uci_text" | ruby -rdigest -e 'print Digest::SHA256.hexdigest(STDIN.read)'
}
cleanup_temporary(){
  [ -z "${temporary:-}" ] || rm -f "$temporary" 2>/dev/null || true
  temporary=
}
cleanup_sources(){
  [ -n "${source_stage:-}" ] || return 0
  [ "$source_stage" = "$backup/source" ] || return 1
  if [ "$source_stage_ready" != true ] && [ ! -e "$source_stage" ] && [ ! -L "$source_stage" ]; then
    return 0
  fi
  for pair in \
    "$agent_source:$source_stage/openclash_web_router_agent.lua:${agent_source_inode:-}" \
    "$forced_source:$source_stage/openclash_web_forced_command.sh:${forced_source_inode:-}" \
    "$customizer_source:$source_stage/openclash_customizer.rb:${customizer_source_inode:-}" \
    "$transaction_source:$source_stage/openclash_custom_transaction.sh:${transaction_source_inode:-}" \
    "$guard_source:$source_stage/openclash_custom_rollback_guard.sh:${guard_source_inode:-}"; do
    source=${pair%%:*}
    rest=${pair#*:}
    staged=${rest%%:*}
    expected_inode=${rest##*:}
    case "$expected_inode" in ''|*[!0-9]*) return 1;; esac
    if [ -e "$source" ] || [ -L "$source" ]; then
      current_source_inode=$(inode "$source") || return 1
      if [ "$current_source_inode" = "$expected_inode" ]; then
        trusted_file "$source" -rw------- || return 1
        trusted_file "$staged" -rw------- || return 1
        cmp -s "$staged" "$source" || return 1
        rm -f "$source" || return 1
      fi
    fi
    if [ -e "$source" ] || [ -L "$source" ]; then
      [ "$(inode "$source")" != "$expected_inode" ] || return 1
    fi
    if [ -e "$staged" ] || [ -L "$staged" ]; then
      trusted_file "$staged" -rw------- || return 1
      rm -f "$staged" || return 1
    fi
    [ ! -e "$staged" ] && [ ! -L "$staged" ] || return 1
  done
  fsync_directory /tmp || return 1
  if [ -e "$source_stage" ] || [ -L "$source_stage" ]; then
    trusted_directory "$source_stage" drwx------ || return 1
    find "$source_stage" -mindepth 1 -maxdepth 1 | grep -q . && return 1
    fsync_directory "$source_stage" || return 1
    rmdir "$source_stage" || return 1
    fsync_directory "$backup" || return 1
  fi
  source_stage_ready=false
}
cleanup_recovery_sources(){
  recovery_source=$1; recovery_backup=$2
  if [ -e "$recovery_source" ] || [ -L "$recovery_source" ]; then trusted_directory "$recovery_source" drwx------ || return 1; fi
  for recovery_pair in \
    "$agent_source:$recovery_source/openclash_web_router_agent.lua:OPENCLASH_WEB_ROUTER_AGENT_LUA" \
    "$forced_source:$recovery_source/openclash_web_forced_command.sh:OPENCLASH_WEB_FORCED_COMMAND_SH" \
    "$customizer_source:$recovery_source/openclash_customizer.rb:OPENCLASH_CUSTOMIZER_RB" \
    "$transaction_source:$recovery_source/openclash_custom_transaction.sh:OPENCLASH_CUSTOM_TRANSACTION_SH" \
    "$guard_source:$recovery_source/openclash_custom_rollback_guard.sh:OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH"; do
    recovery_original=${recovery_pair%%:*}; recovery_rest=${recovery_pair#*:}
    recovery_staged=${recovery_rest%%:*}; recovery_key=${recovery_rest##*:}
    recovery_inode=$(journal_value "$prepared" "${recovery_key}_SOURCE_INODE") || return 1
    recovery_expected=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 1
    case "$recovery_inode" in ''|*[!0-9]*) return 1;; esac
    valid_digest "$recovery_expected" || return 1
    if [ -e "$recovery_original" ] || [ -L "$recovery_original" ]; then
      trusted_file "$recovery_original" -rw------- || return 1
      if [ "$(inode "$recovery_original")" = "$recovery_inode" ]; then
        [ "$(sha "$recovery_original")" = "$recovery_expected" ] || return 1
        rm -f "$recovery_original" || return 1
      fi
    fi
    if [ -e "$recovery_original" ] || [ -L "$recovery_original" ]; then
      [ "$(inode "$recovery_original")" != "$recovery_inode" ] || return 1
    fi
    if [ -e "$recovery_staged" ] || [ -L "$recovery_staged" ]; then
      trusted_file "$recovery_staged" -rw------- || return 1
      [ "$(sha "$recovery_staged")" = "$recovery_expected" ] || return 1
      rm -f "$recovery_staged" || return 1
    fi
    [ ! -e "$recovery_staged" ] && [ ! -L "$recovery_staged" ] || return 1
  done
  fsync_directory /tmp || return 1
  if [ -d "$recovery_source" ] && [ ! -L "$recovery_source" ]; then
    find "$recovery_source" -mindepth 1 -maxdepth 1 | grep -q . && return 1
    fsync_directory "$recovery_source" || return 1
    rmdir "$recovery_source" || return 1
  fi
  fsync_directory "$recovery_backup"
}
cleanup_recovery_temporaries(){
  recovery_root=$1
  [ -e "$recovery_root" ] || [ -L "$recovery_root" ] || return 0
  trusted_directory "$recovery_root" drwx------ || return 1
  ruby -e '
    root=ARGV.fetch(0)
    candidates=Dir.children(root).select { |name| name.match?(/\A\.openclash-sync-web-new\.[A-Za-z0-9]{6}\z/) }
    candidates.each do |name|
      path=File.join(root,name); entry=File.lstat(path); mode=entry.mode & 0o7777
      raise unless entry.file? && !entry.symlink? && entry.uid==0 && entry.gid==0 &&
        entry.nlink==1 && [0o600,0o500].include?(mode)
    end
    candidates.each { |name| File.unlink(File.join(root,name)) }
    File.open(root,"r") { |directory| directory.fsync } unless candidates.empty?
  ' "$recovery_root"
}
cleanup_recovery_auth_temporaries(){
  trusted_directory "$auth_dir" drwx------ || return 1
  ruby -e '
    root=ARGV.fetch(0)
    pattern=/\Aauthorized_keys\.(?:new|web-disable)\.[A-Za-z0-9]{6}\z/
    candidates=Dir.children(root).select { |name| name.match?(pattern) }
    candidates.each do |name|
      path=File.join(root,name); entry=File.lstat(path)
      raise unless entry.file? && !entry.symlink? && entry.uid==0 && entry.gid==0 &&
        entry.nlink==1 && (entry.mode & 0o7777)==0o600
    end
    candidates.each { |name| File.unlink(File.join(root,name)) }
    File.open(root,"r") { |directory| directory.fsync } unless candidates.empty?
  ' "$auth_dir"
}
cleanup_status_partials(){
  status_partials_removed=false
  for status_partial in "$backup/.ROLLED_BACK.partial" "$backup/.ROLLBACK_FAILED.partial"; do
    [ -e "$status_partial" ] || [ -L "$status_partial" ] || continue
    trusted_file "$status_partial" -rw------- || return 1
    rm -f "$status_partial" || return 1
    status_partials_removed=true
  done
  [ "$status_partials_removed" = false ] || fsync_directory "$backup"
}
write_status(){
  status=$1
  status_partial=$backup/.${status}.partial
  case "$status" in ROLLED_BACK|ROLLBACK_FAILED) ;; *) return 1;; esac
  case "$failure_reason" in ''|*[!A-Z0-9_]*) return 1;; esac
  trusted_directory "$backup" drwx------ || return 1
  if [ -e "$backup/$status" ] || [ -L "$backup/$status" ]; then
    status_schema_ok "$backup/$status" "$status"
    return
  fi
  if [ -e "$status_partial" ] || [ -L "$status_partial" ]; then
    trusted_file "$status_partial" -rw------- || return 1
    rm -f "$status_partial" || return 1
    fsync_directory "$backup" || return 1
  fi
  valid_digest "${pending_sha:-}" && valid_digest "${prepared_sha:-}" || return 1
  printf '%s\n' "STATUS=$status" "TARGET=$target" "REASON=$failure_reason" \
    "PENDING_SHA256=$pending_sha" "PREPARED_SHA256=$prepared_sha" | \
    atomic_publish_stream "$backup/$status" "$status_partial" || return 1
  status_schema_ok "$backup/$status" "$status"
}
status_schema_ok(){
  status_path=$1
  expected_status=$2
  trusted_file "$status_path" -rw------- || return 1
  [ "$(wc -l <"$status_path" | tr -d ' ')" -eq 5 ] || return 1
  [ "$(grep -Fxc "STATUS=$expected_status" "$status_path" || true)" -eq 1 ] || return 1
  [ "$(journal_value "$status_path" TARGET)" = "$target" ] || return 1
  status_reason=$(journal_value "$status_path" REASON) || return 1
  case "$status_reason" in ''|*[!A-Z0-9_]*) return 1;; esac
  valid_digest "$(journal_value "$status_path" PENDING_SHA256)" || return 1
  valid_digest "$(journal_value "$status_path" PREPARED_SHA256)"
}

capture_runtime_baseline(){
  active_before=$(uci -q get openclash.config.config_path) || return 1
  [ "$active_before" = "$main" ] || return 1
  uci_before_sha=$(uci_digest) || return 1
  /etc/init.d/openclash running >/dev/null 2>&1 || return 1
  service_before=running
  core_pid_before=$(pidof clash_meta 2>/dev/null || true)
  case "$core_pid_before" in ''|*' '*) return 1;; esac
  core_start_before=$(process_starttime "$core_pid_before") || return 1
  core_path_before=$(readlink "/proc/$core_pid_before/exe" 2>/dev/null || true)
  [ -f "$core_path_before" ] && [ ! -L "$core_path_before" ] || return 1
  core_sha_before=$(sha "$core_path_before") || return 1
  for file in "$main" "$runtime" "$custom_state"; do [ -f "$file" ] && [ ! -L "$file" ] || return 1; done
  main_before_sha=$(sha "$main") || return 1
  runtime_before_sha=$(sha "$runtime") || return 1
  state_before_sha=$(sha "$custom_state") || return 1
}
runtime_unchanged(){
  [ "$(uci -q get openclash.config.config_path 2>/dev/null || true)" = "$active_before" ] || return 1
  [ "$(uci_digest 2>/dev/null || true)" = "$uci_before_sha" ] || return 1
  /etc/init.d/openclash running >/dev/null 2>&1 || return 1
  current_pid=$(pidof clash_meta 2>/dev/null || true)
  [ "$current_pid" = "$core_pid_before" ] || return 1
  [ "$(process_starttime "$current_pid" 2>/dev/null || true)" = "$core_start_before" ] || return 1
  current_core=$(readlink "/proc/$current_pid/exe" 2>/dev/null || true)
  [ -f "$current_core" ] && [ "$(sha "$current_core")" = "$core_sha_before" ] || return 1
  [ "$(sha "$main" 2>/dev/null || true)" = "$main_before_sha" ] || return 1
  [ "$(sha "$runtime" 2>/dev/null || true)" = "$runtime_before_sha" ] || return 1
  [ "$(sha "$custom_state" 2>/dev/null || true)" = "$state_before_sha" ] || return 1
}
atomic_restore(){
  source_file=$1 target_file=$2 mode=$3 expected_current=$4
  trusted_file "$source_file" -rw------- || return 31
  valid_digest "$expected_current" || return 31
  installed_metadata "$target_file" && [ "$(sha "$target_file" 2>/dev/null || true)" = "$expected_current" ] || return 31
  target_inode=$(inode "$target_file") || return 31
  temporary=$(mktemp "$root/.openclash-sync-web-new.XXXXXX") || return 31
  cp "$source_file" "$temporary" || { rm -f "$temporary"; return 31; }
  chown 0:0 "$temporary" || { rm -f "$temporary"; return 31; }
  chmod "$mode" "$temporary" || { rm -f "$temporary"; return 31; }
  cmp -s "$source_file" "$temporary" || { rm -f "$temporary"; return 32; }
  fsync_path "$temporary" || { rm -f "$temporary"; return 33; }
  installed_metadata "$target_file" &&
    [ "$(inode "$target_file")" = "$target_inode" ] &&
    [ "$(sha "$target_file" 2>/dev/null || true)" = "$expected_current" ] || {
      rm -f "$temporary"; return 34;
    }
  mv -f "$temporary" "$target_file" || { rm -f "$temporary"; return 34; }
  temporary=
  fsync_path "$target_file" || return 35
  trusted_file "$target_file" -r-x------ || return 35
  fsync_directory "$root" || return 36
}
atomic_remove(){
  target_file=$1
  expected_digest=$2
  valid_digest "$expected_digest" || return 31
  ruby -rdigest -e '
    path,expected=ARGV
    flags=File::RDONLY
    flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
    File.open(path,flags) do |file|
      opened=file.stat
      named=File.lstat(path)
      raise unless opened.file? && !named.symlink? && opened.dev==named.dev && opened.ino==named.ino
      raise unless opened.uid==0 && opened.gid==0 && opened.nlink==1 && (opened.mode & 0o7777)==0o500
      digest=Digest::SHA256.new
      digest.update(chunk) while chunk=file.read(65_536)
      raise unless digest.hexdigest==expected
      rebound=File.lstat(path)
      raise unless rebound.dev==opened.dev && rebound.ino==opened.ino && rebound.nlink==1
      File.unlink(path)
    end
  ' "$target_file" "$expected_digest" || return 31
  fsync_directory "$root" || return 32
}
current_matches_backup(){
  name=$1
  target_file=$root/$1
  if trusted_file "$backup/$name.before" -rw-------; then
    installed_metadata "$target_file" && cmp -s "$backup/$name.before" "$target_file"
  else
    trusted_file "$backup/$name.absent" -rw------- &&
      [ ! -e "$target_file" ] && [ ! -L "$target_file" ]
  fi
}
publish_active_update(){
  recovery_backup=$1
  if [ -e "$active_partial" ] || [ -L "$active_partial" ]; then
    trusted_file "$active_partial" -rw------- || return 1
    rm -f "$active_partial" || return 1
    fsync_directory "$state_root" || return 1
  fi
  if [ -e "$active_state" ] || [ -L "$active_state" ]; then
    if active_schema_ok "$active_state" UPDATE "$recovery_backup"; then return 0; fi
  fi
  trusted_file "$active_state" -rw------- || return 1
  expected_active_before_sha=$(journal_value "$recovery_backup/COMMITTED" ACTIVE_RECEIPT_BEFORE_SHA256) || return 1
  valid_digest "$expected_active_before_sha" || return 1
  [ "$(sha "$active_state")" = "$expected_active_before_sha" ] || return 1
  committed_digest=$(sha "$recovery_backup/COMMITTED") || return 1
  active_pending_sha=$(journal_value "$recovery_backup/COMMITTED" PENDING_SHA256) || return 1
  active_prepared_sha=$(journal_value "$recovery_backup/COMMITTED" PREPARED_SHA256) || return 1
  valid_digest "$committed_digest" && valid_digest "$active_pending_sha" && valid_digest "$active_prepared_sha" || return 1
  printf '%s\n' ACTIVE 'SCHEMA=publisher-v4-router-web-active-v2' 'OP=UPDATE' "TARGET=$target" \
    "BACKUP_PATH=$recovery_backup" "COMMITTED_SHA256=$committed_digest" \
    "PENDING_SHA256=$active_pending_sha" "PREPARED_SHA256=$active_prepared_sha" | \
    atomic_replace_stream "$active_state" "$active_partial" || return 1
  active_schema_ok "$active_state" UPDATE "$recovery_backup"
}
verify_active_update(){
  trusted_file "$active_state" -rw------- || return 2
  active_op=$(journal_value "$active_state" OP) || return 2
  case "$active_op" in INSTALL|UPDATE) ;; *) return 2;; esac
  active_backup=$(journal_value "$active_state" BACKUP_PATH) || return 2
  case "$active_op" in
    INSTALL) valid_backup_path "$active_backup" web-install-backup- || return 2;;
    UPDATE) valid_backup_path "$active_backup" web-update-backup- || return 2;;
  esac
  trusted_directory "$active_backup" drwx------ || return 2
  trusted_file "$active_backup/COMMITTED" -rw------- || return 2
  active_schema_ok "$active_state" "$active_op" "$active_backup" || return 2
  if [ "$active_op" = INSTALL ]; then committed_install_schema_ok "$active_backup/COMMITTED" || return 2; else committed_update_schema_ok "$active_backup/COMMITTED" || return 2; fi
  for active_name in $asset_names; do
    active_after=$(journal_value "$active_backup/COMMITTED" "${active_name}_AFTER_SHA256") || return 2
    valid_digest "$active_after" || return 2
    [ "$(file_state "$root/$active_name")" = "$active_after" ] || return 3
  done
  receipt_auth_stable_matches "$active_backup/COMMITTED" || return 3
  # ACTIVE is an asset/auth history receipt. Main, runtime and custom state are
  # intentionally mutable after deployment; the fresh baseline still proves
  # that none of them drifts during this updater transaction.
  runtime_unchanged || return 3
}
recover_prepared_update(){
  [ -e "$prepared" ] || return 0
  trusted_file "$prepared" -rw------- || return 2
  prepared_update_schema_ok "$prepared" || return 2
  [ "$(journal_value "$prepared" OP)" = UPDATE ] || return 2
  [ "$(journal_value "$prepared" TARGET)" = "$target" ] || return 2
  recovery_backup=$(journal_value "$prepared" BACKUP_PATH) || return 2
  valid_backup_path "$recovery_backup" web-update-backup- || return 2
  recovery_pending_sha=$(journal_value "$prepared" PENDING_SHA256) || return 2
  recovery_active_before_sha=$(journal_value "$prepared" ACTIVE_RECEIPT_BEFORE_SHA256) || return 2
  valid_digest "$recovery_pending_sha" && valid_digest "$recovery_active_before_sha" || return 2
  trusted_file "$pending" -rw------- || return 2
  pending_schema_ok "$pending" UPDATE "$recovery_backup" || return 2
  [ "$(sha "$pending")" = "$recovery_pending_sha" ] || return 2
  trusted_file "$active_state" -rw------- || return 2
  trusted_directory "$recovery_backup" drwx------ || return 2
  recovery_source=$recovery_backup/source
  recovery_committed=false
  if [ -e "$recovery_backup/COMMITTED" ] || [ -L "$recovery_backup/COMMITTED" ]; then recovery_committed=true; fi
  recovery_rolled_back=false
  if [ -e "$recovery_backup/ROLLED_BACK" ] || [ -L "$recovery_backup/ROLLED_BACK" ]; then
    status_schema_ok "$recovery_backup/ROLLED_BACK" ROLLED_BACK || return 2
    [ "$(journal_value "$recovery_backup/ROLLED_BACK" REASON)" = RECOVERED_TO_BEFORE ] || return 2
    [ "$(journal_value "$recovery_backup/ROLLED_BACK" PENDING_SHA256)" = "$recovery_pending_sha" ] || return 2
    [ "$(journal_value "$recovery_backup/ROLLED_BACK" PREPARED_SHA256)" = "$(sha "$prepared")" ] || return 2
    recovery_rolled_back=true
  fi
  [ "$recovery_committed" = false ] || [ "$recovery_rolled_back" = false ] || return 2
  [ ! -e "$recovery_backup/ROLLBACK_FAILED" ] && [ ! -L "$recovery_backup/ROLLBACK_FAILED" ] || return 2
  if [ -e "$recovery_source" ] || [ -L "$recovery_source" ]; then
    trusted_directory "$recovery_source" drwx------ || return 2
    source_bundle_complete=true
    if [ "$recovery_committed" = true ] || [ "$recovery_rolled_back" = true ]; then source_bundle_complete=false; fi
    source_bundle_ok "$recovery_source" UPDATE "$source_bundle_complete" || return 2
  else
    [ "$recovery_committed" = true ] || [ "$recovery_rolled_back" = true ] || return 2
  fi
  [ "$(journal_value "$prepared" ROOT_PATH)" = "$root" ] || return 2
  recovery_manifest=$(journal_value "$prepared" BACKUP_MANIFEST_SHA256) || return 2
  valid_digest "$recovery_manifest" || return 2
  [ "$(sha "$recovery_backup/SHA256SUMS.before")" = "$recovery_manifest" ] || return 2
  recovery_auth_before=$(journal_value "$prepared" AUTHORIZED_KEYS_BEFORE_SHA256) || return 2
  recovery_auth_after=$(journal_value "$prepared" AUTHORIZED_KEYS_AFTER_SHA256) || return 2
  valid_digest "$recovery_auth_before" && [ "$recovery_auth_before" = "$recovery_auth_after" ] || return 2
  trusted_file "$recovery_backup/authorized_keys.before" -rw------- || return 2
  [ "$(sha "$recovery_backup/authorized_keys.before")" = "$recovery_auth_before" ] || return 2
  recovery_auth_disabled=$(web_access_disabled_digest "$recovery_backup/authorized_keys.before") || return 2
  valid_digest "$recovery_auth_disabled" || return 2
  recovery_auth_current=$(file_state "$auth" -rw-------)
  [ "$recovery_auth_current" = "$recovery_auth_before" ] || [ "$recovery_auth_current" = "$recovery_auth_disabled" ] || return 3
  prepared_runtime_stable_matches "$prepared" && runtime_unchanged || return 6
  (cd "$recovery_backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1) || return 2

  recovery_all_after=true
  for recovery_name in $asset_names; do
    recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
    [ "$(journal_value "$prepared" "${recovery_key}_TARGET")" = "$root/$recovery_name" ] || return 2
    recovery_before=$(journal_value "$prepared" "${recovery_key}_BEFORE_SHA256") || return 2
    recovery_after=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 2
    valid_digest "$recovery_after" || return 2
    if [ -f "$recovery_backup/$recovery_name.before" ]; then
      trusted_file "$recovery_backup/$recovery_name.before" -rw------- || return 2
      valid_digest "$recovery_before" || return 2
      [ "$(sha "$recovery_backup/$recovery_name.before")" = "$recovery_before" ] || return 2
    else
      [ "$recovery_before" = MISSING ] || return 2
      trusted_file "$recovery_backup/$recovery_name.absent" -rw------- || return 2
    fi
    if [ -e "$recovery_source/$recovery_name" ] || [ -L "$recovery_source/$recovery_name" ]; then
      trusted_file "$recovery_source/$recovery_name" -rw------- || return 2
      [ "$(sha "$recovery_source/$recovery_name")" = "$recovery_after" ] || return 2
    else
      [ "$recovery_committed" = true ] || [ "$recovery_rolled_back" = true ] || return 2
    fi
    recovery_current=$(file_state "$root/$recovery_name")
    [ "$recovery_current" = "$recovery_before" ] || [ "$recovery_current" = "$recovery_after" ] || return 3
    [ "$recovery_current" = "$recovery_after" ] || recovery_all_after=false
  done

  if [ -e "$recovery_backup/COMMITTED" ] || [ -L "$recovery_backup/COMMITTED" ]; then
    trusted_file "$recovery_backup/COMMITTED" -rw------- || return 2
    [ "$(journal_value "$recovery_backup/COMMITTED" SCHEMA)" = publisher-v4-router-web-update-v3 ] || return 2
    committed_update_schema_ok "$recovery_backup/COMMITTED" || return 2
    committed_history_matches_prepared "$prepared" "$recovery_backup/COMMITTED" UPDATE || return 2
    [ "$recovery_all_after" = true ] || return 4
    grep -qx COMMITTED "$recovery_backup/COMMITTED" || return 2
    grep -qx "TARGET=$target" "$recovery_backup/COMMITTED" || return 2
    for recovery_name in $asset_names; do
      recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
      recovery_after=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 2
      [ "$(journal_value "$recovery_backup/COMMITTED" "${recovery_name}_AFTER_SHA256")" = "$recovery_after" ] || return 4
    done
    receipt_runtime_stable_matches "$recovery_backup/COMMITTED" && runtime_unchanged || return 4
    cleanup_recovery_temporaries "$root" || return 5
    cleanup_recovery_auth_temporaries || return 5
    if [ "$recovery_auth_current" = "$recovery_auth_disabled" ] && [ "$recovery_auth_disabled" != "$recovery_auth_before" ]; then
      atomic_restore_authorized_keys "$recovery_backup/authorized_keys.before" "$recovery_auth_disabled" "$recovery_auth_before" || return 5
      recovery_auth_current=$recovery_auth_before
    fi
    [ "$(file_state "$auth" -rw-------)" = "$recovery_auth_before" ] || return 4
    receipt_auth_stable_matches "$recovery_backup/COMMITTED" || return 4
    publish_active_update "$recovery_backup" || return 5
    cleanup_recovery_sources "$recovery_source" "$recovery_backup" || return 5
    complete_lifecycle_journals "$recovery_pending_sha" || return 5
    printf '%s\n' 'ROUTER_WEB_UPDATE=PASS' "TARGET=$target" "BACKUP=$recovery_backup" 'RECOVERED_COMMITTED=true'
    exit 0
  fi

  [ ! -L "$recovery_backup/COMMITTED" ] || return 2
  [ "$(sha "$active_state")" = "$recovery_active_before_sha" ] || return 3
  cleanup_recovery_temporaries "$root" || return 5
  cleanup_recovery_auth_temporaries || return 5
  # All assets are classified before this first recovery write.
  for recovery_name in $asset_names; do
    recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
    recovery_before=$(journal_value "$prepared" "${recovery_key}_BEFORE_SHA256") || return 2
    recovery_after=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 2
    [ "$(file_state "$root/$recovery_name")" = "$recovery_after" ] || continue
    if [ "$recovery_before" = MISSING ]; then
      atomic_remove "$root/$recovery_name" "$recovery_after" || return 5
    else
      atomic_restore "$recovery_backup/$recovery_name.before" "$root/$recovery_name" 0500 "$recovery_after" || return 5
    fi
  done
  for recovery_name in $asset_names; do
    recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
    recovery_before=$(journal_value "$prepared" "${recovery_key}_BEFORE_SHA256") || return 2
    [ "$(file_state "$root/$recovery_name")" = "$recovery_before" ] || return 5
  done
  if [ -e "$recovery_backup/COMMITTED.partial" ] || [ -L "$recovery_backup/COMMITTED.partial" ]; then
    trusted_file "$recovery_backup/COMMITTED.partial" -rw------- || return 5
    rm -f "$recovery_backup/COMMITTED.partial" || return 5
    fsync_directory "$recovery_backup" || return 5
  fi
  runtime_unchanged || return 5
  if [ "$recovery_auth_current" = "$recovery_auth_disabled" ] && [ "$recovery_auth_disabled" != "$recovery_auth_before" ]; then
    atomic_restore_authorized_keys "$recovery_backup/authorized_keys.before" "$recovery_auth_disabled" "$recovery_auth_before" || return 5
  fi
  [ "$(file_state "$auth" -rw-------)" = "$recovery_auth_before" ] || return 5
  backup=$recovery_backup
  failure_reason=RECOVERED_TO_BEFORE
  pending_sha=$recovery_pending_sha
  prepared_sha=$(sha "$prepared") || return 5
  [ "$recovery_rolled_back" = true ] || write_status ROLLED_BACK || return 5
  cleanup_recovery_sources "$recovery_source" "$recovery_backup" || return 5
  complete_lifecycle_journals "$recovery_pending_sha" || return 5
  printf '%s\n' 'ROUTER_WEB_UPDATE=RECOVERED_TO_BEFORE' "TARGET=$target" "BACKUP=$recovery_backup"
  exit 0
}
rollback(){
  set +e
  rollback_ok=true
  if stop_web_access_for_recovery; then
    web_access_disabled=true
  else
    web_access_disabled=false
    failure_reason=WEB_ACCESS_STOP_FAILED
    if write_status ROLLBACK_FAILED; then receipt_unavailable=false; else receipt_unavailable=true; fi
    printf '%s\n' 'ROUTER_WEB_UPDATE=ROLLBACK_FAILED' "TARGET=$target" "BACKUP=$backup" \
      "RECEIPT_UNAVAILABLE=$receipt_unavailable" 'WEB_ACCESS_DISABLED=false'
    return
  fi
  cleanup_temporary
  [ ! -e "$backup/COMMITTED" ] && [ ! -L "$backup/COMMITTED" ] || rollback_ok=false
  if [ -e "$backup/COMMITTED.partial" ] || [ -L "$backup/COMMITTED.partial" ]; then
    trusted_file "$backup/COMMITTED.partial" -rw------- || rollback_ok=false
    if [ "$rollback_ok" = true ]; then rm -f "$backup/COMMITTED.partial" || rollback_ok=false; fi
  fi
  fsync_directory "$backup" || rollback_ok=false
  if [ "$backup_ready" = true ] && (cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1); then
    for name in $asset_names; do
      target_file=$root/$name
      if [ -f "$backup/$name.publish-intent" ] && [ ! -L "$backup/$name.publish-intent" ]; then
        intended=$(sed -n '1p' "$backup/$name.publish-intent")
        case "$intended" in ''|*[!0-9a-f]*) rollback_ok=false; continue;; esac
        [ "${#intended}" -eq 64 ] || { rollback_ok=false; continue; }
        if current_matches_backup "$name"; then
          :
        elif installed_metadata "$target_file" && [ "$(sha "$target_file" 2>/dev/null || true)" = "$intended" ]; then
          if [ -f "$backup/$name.before" ] && [ ! -L "$backup/$name.before" ]; then
            atomic_restore "$backup/$name.before" "$target_file" 0500 "$intended" || rollback_ok=false
          elif [ -f "$backup/$name.absent" ] && [ ! -L "$backup/$name.absent" ]; then
            atomic_remove "$target_file" "$intended" || rollback_ok=false
          else
            rollback_ok=false
          fi
        else
          rollback_ok=false
        fi
      else
        current_matches_backup "$name" || rollback_ok=false
      fi
    done
  elif [ "$asset_mutation_started" = true ]; then
    rollback_ok=false
  fi
  cleanup_temporary
  rollback_auth_current=$(file_state "$auth" -rw-------)
  if [ "$rollback_auth_current" != "$auth_before_sha" ] && [ "$rollback_ok" = true ]; then
    atomic_restore_authorized_keys "$backup/authorized_keys.before" "$rollback_auth_current" "$auth_before_sha" || rollback_ok=false
  fi
  [ "$(file_state "$auth" -rw-------)" = "$auth_before_sha" ] || rollback_ok=false
  runtime_unchanged || rollback_ok=false
  cleanup_sources || rollback_ok=false
  cleanup_status_partials || rollback_ok=false
  if [ "$rollback_ok" = true ]; then write_status ROLLED_BACK || rollback_ok=false; fi
  if [ "$rollback_ok" != true ]; then
    rm -f "$backup/ROLLED_BACK" || true
    fsync_directory "$backup" || true
    if write_status ROLLBACK_FAILED; then receipt_unavailable=false; else receipt_unavailable=true; fi
    printf '%s\n' 'ROUTER_WEB_UPDATE=ROLLBACK_FAILED' "TARGET=$target" "BACKUP=$backup" \
      "RECEIPT_UNAVAILABLE=$receipt_unavailable" "WEB_ACCESS_DISABLED=$web_access_disabled"
  else
    printf '%s\n' 'ROUTER_WEB_UPDATE=ROLLED_BACK' "TARGET=$target" "BACKUP=$backup" 'RECEIPT_UNAVAILABLE=false'
  fi
}
finish(){
  exit_code=$?
  if [ "$committed" != true ]; then
    if [ -e "$prepared" ] || [ -L "$prepared" ]; then
      if stop_web_access_for_recovery; then web_access_disabled=true; else web_access_disabled=false; fi
      printf '%s\n' "WEB_ACCESS_DISABLED=$web_access_disabled"
      printf '%s\n' 'ROUTER_WEB_UPDATE=RECOVERY_REQUIRED' "TARGET=$target" "BACKUP=$backup"
    else
      rollback
    fi
  fi
  exit "$exit_code"
}

trap cleanup_sources EXIT
trap 'exit 128' HUP INT TERM
[ -d "$publisher_root" ] && [ ! -L "$publisher_root" ] || hold PUBLISHER_ROOT 13
[ "$(ls -ldn "$publisher_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold PUBLISHER_ROOT_MODE 13
[ -d "$state_root" ] && [ ! -L "$state_root" ] || hold INSTALLED_ROOT 13
[ "$(ls -ldn "$state_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold INSTALLED_ROOT_MODE 13
[ -d "$auth_dir" ] && [ ! -L "$auth_dir" ] || hold AUTHORIZED_KEYS_DIR 14
[ "$(ls -ldn "$auth_dir" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold AUTHORIZED_KEYS_DIR_MODE 14
for command in flock cmp sha256sum mktemp ruby lua uci pidof readlink; do command -v "$command" >/dev/null 2>&1 || hold TOOL 19; done
ensure_lock_file "$install_lock" /etc/openclash || hold INSTALL_LOCK_CREATE 20
exec 5<>"$install_lock"
flock -n 5 || hold INSTALL_LOCK 20
lock_binding "$install_lock" 5 || hold INSTALL_LOCK_BINDING 20
ensure_lock_file "$state_root/activation.lock" "$state_root" || hold ACTIVATION_LOCK_CREATE 20
exec 8<>"$state_root/activation.lock"
flock -n 8 || hold ACTIVATION_LOCK 20
lock_binding "$state_root/activation.lock" 8 || hold ACTIVATION_LOCK_BINDING 20
ensure_lock_file "$publisher_root/stage.lock" "$publisher_root" || hold STAGE_LOCK_CREATE 20
exec 9<>"$publisher_root/stage.lock"
flock -n 9 || hold STAGE_LOCK 20
lock_binding "$publisher_root/stage.lock" 9 || hold STAGE_LOCK_BINDING 20
ensure_lock_file "$state_root/customizations.lock" "$state_root" || hold WEB_LOCK_CREATE 20
exec 7<>"$state_root/customizations.lock"
flock -n 7 || hold WEB_LOCK 20
lock_binding "$state_root/customizations.lock" 7 || hold WEB_LOCK_BINDING 20
ensure_lock_file "$auth_lock" "$auth_dir" || hold AUTHORIZED_KEYS_LOCK_CREATE 20
exec 6<>"$auth_lock"
flock -n 6 || hold AUTHORIZED_KEYS_LOCK 20
lock_binding "$auth_lock" 6 || hold AUTHORIZED_KEYS_LOCK_BINDING 20
if [ -e "$global_rollback_marker" ] || [ -L "$global_rollback_marker" ]; then
  [ -f "$global_rollback_marker" ] && [ ! -L "$global_rollback_marker" ] && \
    [ "$(ls -ln "$global_rollback_marker" 2>/dev/null | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || \
    hold ROLLBACK_PREPARED_INVALID 20
  hold ROLLBACK_PREPARED 20
fi
[ -f "$auth" ] && [ ! -L "$auth" ] || hold AUTHORIZED_KEYS 14
trusted_file "$auth" -rw------- || hold AUTHORIZED_KEYS_MODE 14
capture_runtime_baseline || hold RUNTIME_BASELINE 20
normalize_pending_partial || recovery_hold PENDING_PARTIAL_INVALID 20
if [ -e "$prepared_partial" ] || [ -L "$prepared_partial" ]; then
  [ ! -e "$prepared" ] && [ ! -L "$prepared" ] || recovery_hold PREPARED_PARTIAL_CONFLICT 20
  trusted_file "$prepared_partial" -rw------- || recovery_hold PREPARED_PARTIAL_INVALID 20
  rm -f "$prepared_partial" || recovery_hold PREPARED_PARTIAL_CLEANUP 20
  fsync_directory "$state_root" || recovery_hold PREPARED_PARTIAL_CLEANUP 20
fi
recover_prepared_update || case "$?" in
  2) recovery_hold PREPARED_INVALID 20;;
  3) recovery_hold PREPARED_THIRD_HASH 20;;
  4) recovery_hold COMMITTED_MIXED_STATE 20;;
  6) recovery_hold PREPARED_RUNTIME_DRIFT 20;;
  *) recovery_hold PREPARED_RECOVERY_FAILED 20;;
esac
if [ -e "$active_state" ] || [ -L "$active_state" ]; then
  verify_active_update || case "$?" in
    2) recovery_hold ACTIVE_INVALID 20;;
    *) recovery_hold ACTIVE_STATE_DRIFT 20;;
  esac
fi
[ -e "$active_state" ] || [ -L "$active_state" ] || recovery_hold ACTIVE_MISSING 20
if [ -e "$active_partial" ] || [ -L "$active_partial" ]; then recovery_hold ACTIVE_PARTIAL_ORPHAN 20; fi
recover_pending_without_prepared || case "$?" in 2) recovery_hold PENDING_INVALID 20;; *) recovery_hold PENDING_RECOVERY_FAILED 20;; esac
cleanup_recovery_temporaries "$root" || recovery_hold TEMPORARY_INVALID 20
cleanup_recovery_auth_temporaries || recovery_hold AUTHORIZED_KEYS_TEMPORARY_INVALID 20
active_receipt_before_sha=$(sha "$active_state") || hold ACTIVE_DIGEST 20
auth_before_inode=$(inode "$auth") || hold AUTHORIZED_KEYS_DIGEST 20
auth_before_sha=$(sha "$auth") || hold AUTHORIZED_KEYS_DIGEST 20
valid_digest "$active_receipt_before_sha" && valid_digest "$auth_before_sha" || hold BASELINE_DIGEST 20
[ -d "$root" ] && [ ! -L "$root" ] || hold INSTALLED_ROOT 13
[ "$(ls -ldn "$root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold INSTALLED_ROOT_MODE 13
for name in $asset_names; do
  if [ -e "$root/$name" ] || [ -L "$root/$name" ]; then installed_metadata "$root/$name" || hold INSTALLED_ASSET 18; fi
done
find "$root" -xdev -type l | grep -q . && hold WEB_SYMLINK 18 || true
for file in "$agent_source" "$forced_source" "$customizer_source" "$transaction_source" "$guard_source"; do source_metadata "$file"; done
if [ ! -e "$backup_root" ] && [ ! -L "$backup_root" ]; then
  mkdir "$backup_root" || hold BACKUP_ROOT_CREATE 21
  chmod 0700 "$backup_root" || hold BACKUP_ROOT_MODE 21
  fsync_directory "$publisher_root" || hold BACKUP_ROOT_FSYNC 21
fi
[ -d "$backup_root" ] && [ ! -L "$backup_root" ] || hold BACKUP_ROOT 21
[ "$(ls -ldn "$backup_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold BACKUP_ROOT_MODE 21
[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 21
publish_pending UPDATE "$backup" || hold PENDING_PUBLISH 21
pending_sha=$(sha "$pending") || hold PENDING_DIGEST 21
valid_digest "$pending_sha" || hold PENDING_DIGEST 21
trap pending_exit EXIT
trap 'exit 128' HUP INT TERM
mkdir "$backup" || hold BACKUP_CREATE 21
chmod 0700 "$backup" || hold BACKUP_MODE 21
fsync_directory "$backup_root" || hold BACKUP_ROOT_FSYNC 21

for name in $asset_names; do
  target_file=$root/$name
  if [ -e "$target_file" ] || [ -L "$target_file" ]; then
    installed_metadata "$target_file" || hold INSTALLED_ASSET 22
    before_inode=$(inode "$target_file")
    before_sha=$(sha "$target_file")
    cp "$target_file" "$backup/$name.before" || hold BACKUP_COPY 22
    chmod 0600 "$backup/$name.before" || hold BACKUP_MODE 22
    installed_metadata "$target_file" || hold INSTALLED_DRIFT 22
    [ "$(inode "$target_file")" = "$before_inode" ] && [ "$(sha "$target_file")" = "$before_sha" ] || hold INSTALLED_DRIFT 22
    [ "$(sha "$backup/$name.before")" = "$before_sha" ] || hold BACKUP_HASH 22
  else
    : >"$backup/$name.absent" || hold BACKUP_COPY 22
    chmod 0600 "$backup/$name.absent" || hold BACKUP_MODE 22
  fi
done
installed_auth_inode=$(inode "$auth") || hold AUTHORIZED_KEYS_DRIFT 22
[ "$installed_auth_inode" = "$auth_before_inode" ] && [ "$(sha "$auth")" = "$auth_before_sha" ] || hold AUTHORIZED_KEYS_DRIFT 22
cp "$auth" "$backup/authorized_keys.before" || hold BACKUP_COPY 22
chown 0:0 "$backup/authorized_keys.before" || hold BACKUP_MODE 22
chmod 0600 "$backup/authorized_keys.before" || hold BACKUP_MODE 22
[ "$(inode "$auth")" = "$auth_before_inode" ] && [ "$(sha "$auth")" = "$auth_before_sha" ] || hold AUTHORIZED_KEYS_DRIFT 22
[ "$(sha "$backup/authorized_keys.before")" = "$auth_before_sha" ] || hold BACKUP_HASH 22
: >"$backup/SHA256SUMS.before" || hold BACKUP_HASH 22
for name in $asset_names; do
  if [ -f "$backup/$name.before" ]; then file=$name.before; else file=$name.absent; fi
  (cd "$backup" && sha256sum "$file" >>SHA256SUMS.before) || hold BACKUP_HASH 22
  fsync_file "$backup/$file" || hold BACKUP_FSYNC 22
done
(cd "$backup" && sha256sum authorized_keys.before >>SHA256SUMS.before) || hold BACKUP_HASH 22
fsync_file "$backup/authorized_keys.before" || hold BACKUP_FSYNC 22
chmod 0600 "$backup/SHA256SUMS.before" || hold BACKUP_MODE 22
fsync_path "$backup/SHA256SUMS.before" || hold BACKUP_FSYNC 22
fsync_directory "$backup" || hold BACKUP_FSYNC 22
backup_ready=true

source_stage=$backup/source
mkdir "$source_stage" || hold SOURCE_STAGE 23
chmod 0700 "$source_stage" || hold SOURCE_STAGE 23
source_stage_ready=true
for pair in $asset_manifest; do
  name=${pair%%:*}
  source_file=${pair#*:}
  source_metadata "$source_file"
  before_inode=$(inode "$source_file")
  before_sha=$(sha "$source_file")
  [ "$before_sha" = "$(expected_hash "$name")" ] || hold SOURCE_TRUST 23
  cp "$source_file" "$source_stage/$name" || hold SOURCE_COPY 23
  chown 0:0 "$source_stage/$name" || hold SOURCE_STAGE 23
  chmod 0600 "$source_stage/$name" || hold SOURCE_STAGE 23
  source_metadata "$source_file"
  [ "$(inode "$source_file")" = "$before_inode" ] && [ "$(sha "$source_file")" = "$before_sha" ] || hold SOURCE_DRIFT 23
  [ "$(sha "$source_stage/$name")" = "$before_sha" ] || hold SOURCE_HASH 23
  case "$name" in
    openclash_web_router_agent.lua) agent_source_inode=$before_inode;;
    openclash_web_forced_command.sh) forced_source_inode=$before_inode;;
    openclash_customizer.rb) customizer_source_inode=$before_inode;;
    openclash_custom_transaction.sh) transaction_source_inode=$before_inode;;
    openclash_custom_rollback_guard.sh) guard_source_inode=$before_inode;;
  esac
  fsync_file "$source_stage/$name" || hold SOURCE_FSYNC 23
done
fsync_directory "$source_stage" || hold SOURCE_FSYNC 23
fsync_directory "$backup" || hold SOURCE_FSYNC 23
source_bundle_ok "$source_stage" UPDATE true || hold SOURCE_BUNDLE 23
asset_manifest='openclash_web_router_agent.lua:'"$source_stage"'/openclash_web_router_agent.lua openclash_web_forced_command.sh:'"$source_stage"'/openclash_web_forced_command.sh openclash_customizer.rb:'"$source_stage"'/openclash_customizer.rb openclash_custom_transaction.sh:'"$source_stage"'/openclash_custom_transaction.sh openclash_custom_rollback_guard.sh:'"$source_stage"'/openclash_custom_rollback_guard.sh'

OPENCLASH_LUA_SOURCE="$source_stage/openclash_web_router_agent.lua" \
  lua -e 'local path=os.getenv("OPENCLASH_LUA_SOURCE"); assert(path and path~=""); assert(loadfile(path))' || hold LUA_SYNTAX 24
/bin/sh -n "$source_stage/openclash_web_forced_command.sh" || hold FORCED_COMMAND_SYNTAX 24
ruby -c "$source_stage/openclash_customizer.rb" >/dev/null 2>&1 || hold RUBY_SYNTAX 24
/bin/sh -n "$source_stage/openclash_custom_transaction.sh" || hold SHELL_SYNTAX 24
/bin/sh -n "$source_stage/openclash_custom_rollback_guard.sh" || hold GUARD_SYNTAX 24
runtime_unchanged || hold RUNTIME_DRIFT 25

active_before_digest=$(sha_text "$active_before") || hold PREPARED_DIGEST 25
backup_manifest_sha=$(sha "$backup/SHA256SUMS.before") || hold PREPARED_DIGEST 25
valid_digest "$active_before_digest" && valid_digest "$backup_manifest_sha" || hold PREPARED_DIGEST 25
prepared_payload=$backup/PREPARED.payload
: >"$prepared_payload" || hold PREPARED_BUILD 25
chmod 0600 "$prepared_payload" || hold PREPARED_BUILD 25
printf '%s\n' PREPARED 'SCHEMA=publisher-v4-router-web-update-prepared-v2' 'OP=UPDATE' "TARGET=$target" \
  "BACKUP_PATH=$backup" "ROOT_PATH=$root" "BACKUP_MANIFEST_SHA256=$backup_manifest_sha" \
  "PENDING_PATH=$pending" "PENDING_SHA256=$pending_sha" \
  "ACTIVE_RECEIPT_BEFORE_PATH=$active_state" "ACTIVE_RECEIPT_BEFORE_SHA256=$active_receipt_before_sha" \
  "ACTIVE_BEFORE_SHA256=$active_before_digest" "UCI_BEFORE_SHA256=$uci_before_sha" "CORE_SHA256=$core_sha_before" \
  "CORE_PID_BEFORE=$core_pid_before" "CORE_START_BEFORE=$core_start_before" "MAIN_BEFORE_SHA256=$main_before_sha" \
  "RUNTIME_BEFORE_SHA256=$runtime_before_sha" "CUSTOM_STATE_BEFORE_SHA256=$state_before_sha" \
  >"$prepared_payload" || hold PREPARED_BUILD 25
for name in $asset_names; do
  journal_key=$(printf '%s' "$name" | tr 'a-z.-' 'A-Z__') || hold PREPARED_BUILD 25
  if [ -f "$backup/$name.before" ]; then journal_before=$(sha "$backup/$name.before") || hold PREPARED_DIGEST 25; else journal_before=MISSING; fi
  journal_after=$(sha "$source_stage/$name") || hold PREPARED_DIGEST 25
  { [ "$journal_before" = MISSING ] || valid_digest "$journal_before"; } && valid_digest "$journal_after" || hold PREPARED_DIGEST 25
  case "$name" in
    openclash_web_router_agent.lua) journal_source_inode=$agent_source_inode;;
    openclash_web_forced_command.sh) journal_source_inode=$forced_source_inode;;
    openclash_customizer.rb) journal_source_inode=$customizer_source_inode;;
    openclash_custom_transaction.sh) journal_source_inode=$transaction_source_inode;;
    openclash_custom_rollback_guard.sh) journal_source_inode=$guard_source_inode;;
    *) hold PREPARED_BUILD 25;;
  esac
  case "$journal_source_inode" in ''|*[!0-9]*) hold PREPARED_DIGEST 25;; esac
  printf '%s\n' "${journal_key}_TARGET=$root/$name" "${journal_key}_BEFORE_SHA256=$journal_before" \
    "${journal_key}_AFTER_SHA256=$journal_after" "${journal_key}_SOURCE_INODE=$journal_source_inode" \
    >>"$prepared_payload" || hold PREPARED_BUILD 25
done
printf '%s\n' "AUTHORIZED_KEYS_BEFORE_SHA256=$auth_before_sha" "AUTHORIZED_KEYS_AFTER_SHA256=$auth_before_sha" \
  >>"$prepared_payload" || hold PREPARED_BUILD 25
fsync_path "$prepared_payload" || hold PREPARED_FSYNC 25
prepared_update_schema_ok "$prepared_payload" || hold PREPARED_SCHEMA 25
atomic_publish_stream "$prepared" "$prepared_partial" <"$prepared_payload" || hold PREPARED_FSYNC 25
prepared_update_schema_ok "$prepared" || hold PREPARED_SCHEMA 25
prepared_sha=$(sha "$prepared") || hold PREPARED_DIGEST 25
valid_digest "$prepared_sha" || hold PREPARED_DIGEST 25
rm -f "$prepared_payload" || hold PREPARED_CLEANUP 25
fsync_directory "$backup" || hold PREPARED_CLEANUP 25
trap finish EXIT
trap 'exit 128' HUP INT TERM

write_intent(){
  name=$1
  intended=$2
  partial=$backup/.$name.publish-intent.partial
  printf '%s\n' "$intended" >"$partial" || return 1
  chmod 0600 "$partial" || return 1
  fsync_file "$partial" || return 1
  mv -f "$partial" "$backup/$name.publish-intent" || return 1
  fsync_directory "$backup" || return 1
}
atomic_publish(){
  source_file=$1
  target_file=$2
  [ -f "$source_file" ] && [ ! -L "$source_file" ] || return 30
  source_sha=$(sha "$source_file") || return 30
  temporary=$(mktemp "$root/.openclash-sync-web-new.XXXXXX") || return 31
  cp "$source_file" "$temporary" || return 31
  chown 0:0 "$temporary" || return 31
  chmod 0500 "$temporary" || return 31
  cmp -s "$source_file" "$temporary" || return 32
  fsync_path "$temporary" || return 33
  [ "$(sha "$source_file")" = "$source_sha" ] || return 37
  mv -f "$temporary" "$target_file" || return 34
  temporary=
  fsync_path "$target_file" || return 35
  fsync_directory "$root" || return 36
}
for pair in $asset_manifest; do
  name=${pair%%:*}
  source_file=${pair#*:}
  intended=$(sha "$source_file")
  write_intent "$name" "$intended" || hold PUBLISH_INTENT 26
  asset_mutation_started=true
  atomic_publish "$source_file" "$root/$name" || hold ATOMIC_PUBLISH 26
done
for pair in $asset_manifest; do
  name=${pair%%:*}
  source_file=${pair#*:}
  installed_metadata "$root/$name" || hold INSTALLED_MODE 27
  cmp -s "$source_file" "$root/$name" || hold INSTALLED_HASH 27
done
/bin/sh -n "$root/openclash_web_forced_command.sh" || hold INSTALLED_SYNTAX 27
/bin/sh -n "$root/openclash_custom_transaction.sh" || hold INSTALLED_SYNTAX 27
/bin/sh -n "$root/openclash_custom_rollback_guard.sh" || hold INSTALLED_SYNTAX 27
ruby -c "$root/openclash_customizer.rb" >/dev/null 2>&1 || hold INSTALLED_SYNTAX 27
OPENCLASH_LUA_SOURCE="$root/openclash_web_router_agent.lua" \
  lua -e 'local path=os.getenv("OPENCLASH_LUA_SOURCE"); assert(path and path~=""); assert(loadfile(path))' || hold INSTALLED_SYNTAX 27
runtime_unchanged || hold RUNTIME_DRIFT 28
ruby "$root/openclash_customizer.rb" inspect "$main" "$custom_state" >/dev/null 2>&1 || hold INSPECT 28
runtime_unchanged || hold RUNTIME_DRIFT 28

active_after=$(uci -q get openclash.config.config_path) || hold RUNTIME_DRIFT 28
uci_after_sha=$(uci_digest) || hold RUNTIME_DRIFT 28
core_pid_after=$(pidof clash_meta 2>/dev/null || true)
core_start_after=$(process_starttime "$core_pid_after" 2>/dev/null || true)
config_changed=true
[ "$(sha "$main")" = "$main_before_sha" ] && [ "$(sha "$runtime")" = "$runtime_before_sha" ] &&
[ "$(sha "$custom_state")" = "$state_before_sha" ] && [ "$uci_after_sha" = "$uci_before_sha" ] && config_changed=false
service_restarted=true
[ "$service_before" = running ] && [ "$core_pid_after" = "$core_pid_before" ] &&
[ "$core_start_after" = "$core_start_before" ] && service_restarted=false
[ "$active_after" = "$active_before" ] && [ "$config_changed" = false ] &&
[ "$service_restarted" = false ] || hold RUNTIME_DRIFT 28
auth_after_sha=$(sha "$auth") || hold AUTHORIZED_KEYS_DIGEST 28
[ "$auth_after_sha" = "$auth_before_sha" ] || recovery_hold AUTHORIZED_KEYS_DRIFT 28

active_after_digest=$(sha_text "$active_after") || hold RECEIPT_DIGEST 29
main_after_sha=$(sha "$main") || hold RECEIPT_DIGEST 29
runtime_after_sha=$(sha "$runtime") || hold RECEIPT_DIGEST 29
state_after_sha=$(sha "$custom_state") || hold RECEIPT_DIGEST 29
valid_digest "$active_after_digest" && valid_digest "$main_after_sha" && valid_digest "$runtime_after_sha" &&
  valid_digest "$state_after_sha" || hold RECEIPT_DIGEST 29
: >"$backup/COMMITTED.partial" || hold RECEIPT 29
chmod 0600 "$backup/COMMITTED.partial" || hold RECEIPT 29
printf '%s\n' COMMITTED 'SCHEMA=publisher-v4-router-web-update-v3' "TARGET=$target" \
  "ACTIVE_BEFORE_SHA256=$active_before_digest" "ACTIVE_AFTER_SHA256=$active_after_digest" \
  "UCI_BEFORE_SHA256=$uci_before_sha" "UCI_AFTER_SHA256=$uci_after_sha" \
  "CORE_SHA256=$core_sha_before" "CORE_PID_BEFORE=$core_pid_before" "CORE_START_BEFORE=$core_start_before" \
  "CORE_PID_AFTER=$core_pid_after" "CORE_START_AFTER=$core_start_after" \
  "MAIN_BEFORE_SHA256=$main_before_sha" "MAIN_AFTER_SHA256=$main_after_sha" \
  "RUNTIME_BEFORE_SHA256=$runtime_before_sha" "RUNTIME_AFTER_SHA256=$runtime_after_sha" \
  "CUSTOM_STATE_BEFORE_SHA256=$state_before_sha" "CUSTOM_STATE_AFTER_SHA256=$state_after_sha" \
  "CONFIG_CHANGED=$config_changed" "SERVICE_RESTARTED=$service_restarted" \
  >"$backup/COMMITTED.partial" || hold RECEIPT 29
for name in $asset_names; do
  asset_after_sha=$(sha "$root/$name") || hold RECEIPT_DIGEST 29
  valid_digest "$asset_after_sha" || hold RECEIPT_DIGEST 29
  printf '%s_AFTER_SHA256=%s\n' "$name" "$asset_after_sha" >>"$backup/COMMITTED.partial" || hold RECEIPT 29
done
printf '%s\n' "AUTHORIZED_KEYS_BEFORE_SHA256=$auth_before_sha" "AUTHORIZED_KEYS_AFTER_SHA256=$auth_after_sha" \
  "PENDING_SHA256=$pending_sha" "PREPARED_SHA256=$prepared_sha" \
  "ACTIVE_RECEIPT_BEFORE_PATH=$active_state" "ACTIVE_RECEIPT_BEFORE_SHA256=$active_receipt_before_sha" \
  >>"$backup/COMMITTED.partial" || hold RECEIPT 29
committed_update_schema_ok "$backup/COMMITTED.partial" || hold RECEIPT_SCHEMA 29
committed_history_matches_prepared "$prepared" "$backup/COMMITTED.partial" UPDATE || hold RECEIPT_HISTORY 29
fsync_file "$backup/COMMITTED.partial" || hold RECEIPT_FSYNC 29
mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED" || hold RECEIPT 29
fsync_directory "$backup" || hold RECEIPT_FSYNC 29
committed_update_schema_ok "$backup/COMMITTED" || hold RECEIPT_SCHEMA 29
committed_history_matches_prepared "$prepared" "$backup/COMMITTED" UPDATE || hold RECEIPT_HISTORY 29
committed=true
publish_active_update "$backup" || recovery_hold ACTIVE_FSYNC 29
cleanup_sources || recovery_hold SOURCE_CLEANUP 29
[ "$source_stage_ready" = false ] && [ ! -e "$source_stage" ] || recovery_hold SOURCE_CLEANUP 29
complete_lifecycle_journals "$pending_sha" || recovery_hold LIFECYCLE_CLEANUP 29
trap - EXIT HUP INT TERM
printf '%s\n' 'ROUTER_WEB_UPDATE=PASS' "TARGET=$target" "BACKUP=$backup" "CONFIG_CHANGED=$config_changed" "SERVICE_RESTARTED=$service_restarted"
