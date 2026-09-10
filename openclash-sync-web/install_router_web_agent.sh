#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ failure_reason=$1; printf 'ROUTER_WEB_INSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
case "$1" in router_a|router_b) target=$1;; *) hold TARGET 12;; esac

publisher_root=/etc/openclash/publisher-v4
global_rollback_marker=$publisher_root/ROLLBACK-PREPARED
root=$publisher_root/web
state_root=$publisher_root/web-state
backup_root=$publisher_root/web-backups
backup=$backup_root/web-install-backup-$(date -u +%Y%m%dT%H%M%SZ)-$$
install_lock=/etc/openclash/.publisher-v4-install.lock
pending=$state_root/web-lifecycle.PENDING
pending_partial=$state_root/.web-lifecycle.PENDING.partial
prepared=$state_root/web-lifecycle.PREPARED
prepared_partial=$state_root/.web-lifecycle.PREPARED.partial
active_state=$state_root/web-lifecycle.ACTIVE
active_partial=$state_root/.web-lifecycle.ACTIVE.partial
auth=/etc/dropbear/authorized_keys
auth_dir=/etc/dropbear
pub_file=/tmp/openclash-sync-web.pub
main=/etc/openclash/config/ProviderBase-ProviderSource.yaml
runtime=/etc/openclash/ProviderBase-ProviderSource.yaml
custom_state=$state_root/customizations.state

agent_source=/tmp/openclash-sync-web-agent.lua
forced_source=/tmp/openclash-sync-web-forced-command.sh
customizer_source=/tmp/openclash-sync-web-customizer.rb
transaction_source=/tmp/openclash-sync-web-custom-transaction.sh
guard_source=/tmp/openclash-sync-web-custom-rollback-guard.sh
source_stage=
source_stage_ready=false
temporary=
auth_before_inode=
auth_before_sha=
auth_after_sha=
auth_published=false
auth_lock=/etc/dropbear/authorized_keys.lock
failure_reason=UNKNOWN

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

fsync_path(){
  ruby -e 'path=ARGV.fetch(0); File.open(path, "r") { |file| file.fsync }; File.open(File.dirname(path), "r") { |directory| directory.fsync }' "$1"
}
fsync_directory(){
  ruby -e 'File.open(ARGV.fetch(0), "r") { |directory| directory.fsync }' "$1"
}
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
  journal_path=$1
  journal_key=$2
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
# v3 lifecycle evidence is intentionally defined after the legacy readers.  A
# router may still have an old INSTALL receipt, but every newly written receipt
# must bind the PENDING and PREPARED journals and the authorized_keys digest.
pending_schema_ok(){
  pending_path=$1 expected_op=$2 expected_backup=$3
  journal_schema_ok "$pending_path" PENDING 5 SCHEMA OP TARGET BACKUP_PATH || return 1
  [ "$(journal_value "$pending_path" SCHEMA)" = publisher-v4-router-web-pending-v1 ] || return 1
  [ "$(journal_value "$pending_path" OP)" = "$expected_op" ] || return 1
  [ "$(journal_value "$pending_path" TARGET)" = "$target" ] || return 1
  [ "$(journal_value "$pending_path" BACKUP_PATH)" = "$expected_backup" ]
}
prepared_install_schema_ok_v2(){
  journal_path=$1
  journal_schema_ok "$journal_path" PREPARED 41 SCHEMA OP TARGET BACKUP_PATH ROOT_PATH BACKUP_MANIFEST_SHA256 \
    PENDING_PATH PENDING_SHA256 ACTIVE_BEFORE_SHA256 UCI_BEFORE_SHA256 CORE_SHA256 CORE_PID_BEFORE CORE_START_BEFORE \
    MAIN_BEFORE_SHA256 RUNTIME_BEFORE_SHA256 CUSTOM_STATE_BEFORE_SHA256 \
    OPENCLASH_WEB_ROUTER_AGENT_LUA_TARGET OPENCLASH_WEB_ROUTER_AGENT_LUA_BEFORE_SHA256 OPENCLASH_WEB_ROUTER_AGENT_LUA_AFTER_SHA256 OPENCLASH_WEB_ROUTER_AGENT_LUA_SOURCE_INODE \
    OPENCLASH_WEB_FORCED_COMMAND_SH_TARGET OPENCLASH_WEB_FORCED_COMMAND_SH_BEFORE_SHA256 OPENCLASH_WEB_FORCED_COMMAND_SH_AFTER_SHA256 OPENCLASH_WEB_FORCED_COMMAND_SH_SOURCE_INODE \
    OPENCLASH_CUSTOMIZER_RB_TARGET OPENCLASH_CUSTOMIZER_RB_BEFORE_SHA256 OPENCLASH_CUSTOMIZER_RB_AFTER_SHA256 OPENCLASH_CUSTOMIZER_RB_SOURCE_INODE \
    OPENCLASH_CUSTOM_TRANSACTION_SH_TARGET OPENCLASH_CUSTOM_TRANSACTION_SH_BEFORE_SHA256 OPENCLASH_CUSTOM_TRANSACTION_SH_AFTER_SHA256 OPENCLASH_CUSTOM_TRANSACTION_SH_SOURCE_INODE \
    OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_TARGET OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_BEFORE_SHA256 OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_AFTER_SHA256 OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH_SOURCE_INODE \
    AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 PUBLIC_KEY_SOURCE_INODE PUBLIC_KEY_SOURCE_SHA256 || return 1
  [ "$(journal_value "$journal_path" SCHEMA)" = publisher-v4-router-web-install-prepared-v2 ] &&
  [ "$(journal_value "$journal_path" OP)" = INSTALL ] &&
  [ "$(journal_value "$journal_path" TARGET)" = "$target" ] &&
  [ "$(journal_value "$journal_path" PENDING_PATH)" = "$pending" ] || return 1
  pending_hash=$(journal_value "$journal_path" PENDING_SHA256) || return 1
  valid_digest "$pending_hash"
}
prepared_install_schema_ok(){ prepared_install_schema_ok_v2 "$1"; }
committed_common_v3(){
  receipt=$1
  [ "$(journal_value "$receipt" TARGET)" = "$target" ] &&
  [ "$(journal_value "$receipt" CONFIG_CHANGED)" = false ] &&
  [ "$(journal_value "$receipt" SERVICE_RESTARTED)" = false ] || return 1
  for digest_key in ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 \
    MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 \
    CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 \
    PENDING_SHA256 PREPARED_SHA256; do
    digest_value=$(journal_value "$receipt" "$digest_key") || return 1
    valid_digest "$digest_value" || return 1
  done
  for receipt_name in $asset_names; do
    digest_value=$(journal_value "$receipt" "${receipt_name}_AFTER_SHA256") || return 1
    valid_digest "$digest_value" || return 1
  done
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
    MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 \
    CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256 CONFIG_CHANGED SERVICE_RESTARTED \
    openclash_web_router_agent.lua_AFTER_SHA256 openclash_web_forced_command.sh_AFTER_SHA256 \
    openclash_customizer.rb_AFTER_SHA256 openclash_custom_transaction.sh_AFTER_SHA256 \
    openclash_custom_rollback_guard.sh_AFTER_SHA256 AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256 || return 1
  [ "$(journal_value "$receipt" SCHEMA)" = publisher-v4-router-web-install-v2 ] || return 1
  for key in AUTHORIZED_KEYS_BEFORE_SHA256 AUTHORIZED_KEYS_AFTER_SHA256; do valid_digest "$(journal_value "$receipt" "$key")" || return 1; done
  # Reuse the legacy function's strict runtime equality checks without leaving
  # the old function name as the active reader.
  [ "$(journal_value "$receipt" TARGET)" = "$target" ] &&
  [ "$(journal_value "$receipt" CONFIG_CHANGED)" = false ] &&
  [ "$(journal_value "$receipt" SERVICE_RESTARTED)" = false ] || return 1
  for key in ACTIVE_BEFORE_SHA256 ACTIVE_AFTER_SHA256 UCI_BEFORE_SHA256 UCI_AFTER_SHA256 CORE_SHA256 MAIN_BEFORE_SHA256 MAIN_AFTER_SHA256 RUNTIME_BEFORE_SHA256 RUNTIME_AFTER_SHA256 CUSTOM_STATE_BEFORE_SHA256 CUSTOM_STATE_AFTER_SHA256; do valid_digest "$(journal_value "$receipt" "$key")" || return 1; done
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
  [ "$(journal_value "$active_path" OP)" = "$expected_op" ] &&
  [ "$(journal_value "$active_path" TARGET)" = "$target" ] &&
  [ "$(journal_value "$active_path" BACKUP_PATH)" = "$expected_backup" ] || return 1
  active_committed_sha=$(journal_value "$active_path" COMMITTED_SHA256) || return 1
  valid_digest "$active_committed_sha" || return 1
  current_committed_sha=$(sha "$expected_backup/COMMITTED") || return 1
  [ "$active_committed_sha" = "$current_committed_sha" ] || return 1
  if [ "$active_schema" = publisher-v4-router-web-active-v2 ]; then
    [ "$(journal_value "$active_path" PENDING_SHA256)" = "$(journal_value "$expected_backup/COMMITTED" PENDING_SHA256)" ] || return 1
    [ "$(journal_value "$active_path" PREPARED_SHA256)" = "$(journal_value "$expected_backup/COMMITTED" PREPARED_SHA256)" ] || return 1
  fi
}
file_state(){
  state_path=$1
  expected_mode=$2
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
  lock_path=$1
  lock_parent=$2
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
  target_path=$1
  partial_path=$2
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
  case "$partial_op" in
    INSTALL) partial_prefix=web-install-backup-;;
    UPDATE) partial_prefix=web-update-backup-;;
    *) partial_prefix=;;
  esac
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
      top_allowed += assets.map { |name| "#{name}.absent" }
      top_allowed += %w[authorized_keys.before authorized_keys.after]
    elsif op=="UPDATE"
      top_allowed += assets.flat_map { |name| ["#{name}.before","#{name}.absent"] }
      top_allowed << "authorized_keys.before"
    else
      raise
    end
    root=File.lstat(backup); raise unless root.directory? && !root.symlink? && root.uid==0 && root.gid==0 && (root.mode & 0o7777)==0o700
    source=File.join(backup,"source")
    top_files=[]; source_files=[]
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
    if File.directory?(source) && !File.symlink?(source)
      File.open(source,"r") { |directory| directory.fsync }; Dir.rmdir(source)
    end
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
  case "$orphan_op" in
    INSTALL) valid_backup_path "$orphan_backup" web-install-backup- || return 2;;
    UPDATE) valid_backup_path "$orphan_backup" web-update-backup- || return 2;;
    *) return 2;;
  esac
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
  printf '%s\n' 'ROUTER_WEB_INSTALL=RECOVERY_REQUIRED' "TARGET=$target" "BACKUP=$backup" 'PHASE=PENDING'
  exit "$exit_code"
}
process_starttime(){
  ruby -e 'text=File.binread("/proc/#{ARGV.fetch(0)}/stat",4096).chomp; match=text.match(/\A[0-9]+ \(.+\) [A-Z] (.+)\z/); value=match && match[1].split[18]; abort unless value&.match?(/\A[0-9]+\z/); puts value' "$1"
}
uci_digest(){
  uci_text=$(uci -q show openclash) || return 1
  [ -n "$uci_text" ] || return 1
  printf '%s\n' "$uci_text" | ruby -rdigest -e 'print Digest::SHA256.hexdigest(STDIN.read)'
}
capture_runtime_baseline(){
  active_before=$(uci -q get openclash.config.config_path) || return 1
  [ "$active_before" = "$main" ] || return 1
  uci_before_sha=$(uci_digest) || return 1
  /etc/init.d/openclash running >/dev/null 2>&1 || return 1
  core_pid_before=$(pidof clash_meta 2>/dev/null || true)
  case "$core_pid_before" in ''|*' '*) return 1;; esac
  core_start_before=$(process_starttime "$core_pid_before") || return 1
  core_path_before=$(readlink "/proc/$core_pid_before/exe" 2>/dev/null || true)
  [ -f "$core_path_before" ] || return 1
  core_sha_before=$(sha "$core_path_before") || return 1
  for file in "$main" "$runtime" "$custom_state"; do
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
  done
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
source_metadata(){
  source=$1
  [ -f "$source" ] && [ ! -L "$source" ] || hold SOURCE_ASSET 14
  metadata=$(ls -ln "$source" | awk '{print $1 ":" $3 ":" $4}')
  [ "$metadata" = '-rw-------:0:0' ] || hold SOURCE_METADATA 14
  ruby -e 'exit(File.lstat(ARGV.fetch(0)).nlink == 1 ? 0 : 1)' "$source" || hold SOURCE_HARDLINK 14
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
cleanup_temporaries(){
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
    "$guard_source:$source_stage/openclash_custom_rollback_guard.sh:${guard_source_inode:-}" \
    "$pub_file:$source_stage/public_key:${pub_file_inode:-}"; do
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
cleanup_recovery_source(){
  recovery_source=$1
  recovery_backup=$2
  if [ -e "$recovery_source" ] || [ -L "$recovery_source" ]; then trusted_directory "$recovery_source" drwx------ || return 1; fi
  for recovery_pair in \
    "$agent_source:$recovery_source/openclash_web_router_agent.lua:OPENCLASH_WEB_ROUTER_AGENT_LUA" \
    "$forced_source:$recovery_source/openclash_web_forced_command.sh:OPENCLASH_WEB_FORCED_COMMAND_SH" \
    "$customizer_source:$recovery_source/openclash_customizer.rb:OPENCLASH_CUSTOMIZER_RB" \
    "$transaction_source:$recovery_source/openclash_custom_transaction.sh:OPENCLASH_CUSTOM_TRANSACTION_SH" \
    "$guard_source:$recovery_source/openclash_custom_rollback_guard.sh:OPENCLASH_CUSTOM_ROLLBACK_GUARD_SH" \
    "$pub_file:$recovery_source/public_key:PUBLIC_KEY"; do
    recovery_original=${recovery_pair%%:*}; recovery_rest=${recovery_pair#*:}
    recovery_staged=${recovery_rest%%:*}; recovery_key=${recovery_rest##*:}
    recovery_inode=$(journal_value "$prepared" "${recovery_key}_SOURCE_INODE") || return 1
    case "$recovery_inode" in ''|*[!0-9]*) return 1;; esac
    if [ "$recovery_key" = PUBLIC_KEY ]; then
      recovery_expected=$(journal_value "$prepared" PUBLIC_KEY_SOURCE_SHA256) || return 1
    else
      recovery_expected=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 1
    fi
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
publish_active_install(){
  recovery_backup=$1
  if [ -e "$active_partial" ] || [ -L "$active_partial" ]; then
    trusted_file "$active_partial" -rw------- || return 1
    rm -f "$active_partial" || return 1
    fsync_directory "$state_root" || return 1
  fi
  if [ -e "$active_state" ] || [ -L "$active_state" ]; then
    active_schema_ok "$active_state" INSTALL "$recovery_backup"
    return
  fi
  committed_digest=$(sha "$recovery_backup/COMMITTED") || return 1
  active_pending_sha=$(journal_value "$recovery_backup/COMMITTED" PENDING_SHA256) || return 1
  active_prepared_sha=$(journal_value "$recovery_backup/COMMITTED" PREPARED_SHA256) || return 1
  valid_digest "$committed_digest" || return 1
  valid_digest "$active_pending_sha" && valid_digest "$active_prepared_sha" || return 1
  printf '%s\n' ACTIVE 'SCHEMA=publisher-v4-router-web-active-v2' 'OP=INSTALL' "TARGET=$target" \
    "BACKUP_PATH=$recovery_backup" "COMMITTED_SHA256=$committed_digest" \
    "PENDING_SHA256=$active_pending_sha" "PREPARED_SHA256=$active_prepared_sha" | \
    atomic_publish_stream "$active_state" "$active_partial" || return 1
  active_schema_ok "$active_state" INSTALL "$recovery_backup"
}
verify_active_install(){
  [ -e "$active_state" ] || return 1
  trusted_file "$active_state" -rw------- || return 2
  active_op=$(journal_value "$active_state" OP) || return 2
  case "$active_op" in INSTALL|UPDATE) ;; *) return 2;; esac
  active_backup=$(journal_value "$active_state" BACKUP_PATH) || return 2
  case "$active_op" in INSTALL) valid_backup_path "$active_backup" web-install-backup- || return 2;; UPDATE) valid_backup_path "$active_backup" web-update-backup- || return 2;; esac
  trusted_directory "$active_backup" drwx------ || return 2
  trusted_file "$active_backup/COMMITTED" -rw------- || return 2
  active_schema_ok "$active_state" "$active_op" "$active_backup" || return 2
  if [ "$active_op" = INSTALL ]; then committed_install_schema_ok "$active_backup/COMMITTED" || return 2; else committed_update_schema_ok "$active_backup/COMMITTED" || return 2; fi
  for active_name in $asset_names; do
    active_after=$(journal_value "$active_backup/COMMITTED" "${active_name}_AFTER_SHA256") || return 2
    valid_digest "$active_after" || return 2
    [ "$(file_state "$root/$active_name" -r-x------)" = "$active_after" ] || return 3
  done
  receipt_auth_stable_matches "$active_backup/COMMITTED" || return 3
  # ACTIVE is an asset/auth history receipt. Main, runtime and custom state are
  # intentionally mutable after deployment; the fresh baseline still proves
  # that none of them drifts during this installer transaction.
  runtime_unchanged || return 3
  return 0
}
recover_prepared_install(){
  [ -e "$prepared" ] || return 0
  trusted_file "$prepared" -rw------- || return 2
  prepared_install_schema_ok "$prepared" || return 2
  [ "$(journal_value "$prepared" OP)" = INSTALL ] || return 2
  [ "$(journal_value "$prepared" TARGET)" = "$target" ] || return 2
  recovery_backup=$(journal_value "$prepared" BACKUP_PATH) || return 2
  valid_backup_path "$recovery_backup" web-install-backup- || return 2
  recovery_pending_sha=$(journal_value "$prepared" PENDING_SHA256) || return 2
  valid_digest "$recovery_pending_sha" || return 2
  trusted_file "$pending" -rw------- || return 2
  pending_schema_ok "$pending" INSTALL "$recovery_backup" || return 2
  [ "$(sha "$pending")" = "$recovery_pending_sha" ] || return 2
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
    source_bundle_ok "$recovery_source" INSTALL "$source_bundle_complete" || return 2
  else
    [ "$recovery_committed" = true ] || [ "$recovery_rolled_back" = true ] || return 2
  fi
  [ "$(journal_value "$prepared" ROOT_PATH)" = "$root" ] || return 2
  recovery_manifest=$(journal_value "$prepared" BACKUP_MANIFEST_SHA256) || return 2
  valid_digest "$recovery_manifest" || return 2
  [ "$(sha "$recovery_backup/SHA256SUMS.before")" = "$recovery_manifest" ] || return 2
  prepared_runtime_stable_matches "$prepared" && runtime_unchanged || return 6
  (cd "$recovery_backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1) || return 2

  recovery_all_after=true
  for recovery_name in $asset_names; do
    recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
    [ "$(journal_value "$prepared" "${recovery_key}_TARGET")" = "$root/$recovery_name" ] || return 2
    recovery_before=$(journal_value "$prepared" "${recovery_key}_BEFORE_SHA256") || return 2
    recovery_after=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 2
    [ "$recovery_before" = MISSING ] && valid_digest "$recovery_after" || return 2
    if [ -e "$recovery_source/$recovery_name" ] || [ -L "$recovery_source/$recovery_name" ]; then
      trusted_file "$recovery_source/$recovery_name" -rw------- || return 2
      [ "$(sha "$recovery_source/$recovery_name")" = "$recovery_after" ] || return 2
    else
      [ "$recovery_committed" = true ] || [ "$recovery_rolled_back" = true ] || return 2
    fi
    recovery_current=$(file_state "$root/$recovery_name" -r-x------)
    [ "$recovery_current" = "$recovery_before" ] || [ "$recovery_current" = "$recovery_after" ] || return 3
    [ "$recovery_current" = "$recovery_after" ] || recovery_all_after=false
  done
  recovery_auth_before=$(journal_value "$prepared" AUTHORIZED_KEYS_BEFORE_SHA256) || return 2
  recovery_auth_after=$(journal_value "$prepared" AUTHORIZED_KEYS_AFTER_SHA256) || return 2
  valid_digest "$recovery_auth_before" && valid_digest "$recovery_auth_after" || return 2
  trusted_file "$recovery_backup/authorized_keys.before" -rw------- || return 2
  trusted_file "$recovery_backup/authorized_keys.after" -rw------- || return 2
  [ "$(sha "$recovery_backup/authorized_keys.before")" = "$recovery_auth_before" ] || return 2
  [ "$(sha "$recovery_backup/authorized_keys.after")" = "$recovery_auth_after" ] || return 2
  recovery_auth_current=$(file_state "$auth" -rw-------)
  [ "$recovery_auth_current" = "$recovery_auth_before" ] || [ "$recovery_auth_current" = "$recovery_auth_after" ] || return 3

  if [ -e "$recovery_backup/COMMITTED" ] || [ -L "$recovery_backup/COMMITTED" ]; then
    trusted_file "$recovery_backup/COMMITTED" -rw------- || return 2
    [ "$(journal_value "$recovery_backup/COMMITTED" SCHEMA)" = publisher-v4-router-web-install-v3 ] || return 2
    committed_install_schema_ok "$recovery_backup/COMMITTED" || return 2
    committed_history_matches_prepared "$prepared" "$recovery_backup/COMMITTED" INSTALL || return 2
    [ "$recovery_all_after" = true ] || return 4
    grep -qx COMMITTED "$recovery_backup/COMMITTED" || return 2
    grep -qx "TARGET=$target" "$recovery_backup/COMMITTED" || return 2
    for recovery_name in $asset_names; do
      recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
      recovery_after=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 2
      [ "$(journal_value "$recovery_backup/COMMITTED" "${recovery_name}_AFTER_SHA256")" = "$recovery_after" ] || return 4
    done
    grep -qx "AUTHORIZED_KEYS_AFTER_SHA256=$recovery_auth_after" "$recovery_backup/COMMITTED" || return 4
    receipt_runtime_stable_matches "$recovery_backup/COMMITTED" && runtime_unchanged || return 4
    cleanup_recovery_temporaries "$root" || return 5
    cleanup_recovery_auth_temporaries || return 5
    if [ "$recovery_auth_current" = "$recovery_auth_before" ]; then
      atomic_restore_authorized_keys "$recovery_backup/authorized_keys.after" "$recovery_auth_before" "$recovery_auth_after" || return 5
      recovery_auth_current=$recovery_auth_after
    fi
    [ "$recovery_auth_current" = "$recovery_auth_after" ] || return 4
    receipt_auth_stable_matches "$recovery_backup/COMMITTED" || return 4
    publish_active_install "$recovery_backup" || return 5
    cleanup_recovery_source "$recovery_source" "$recovery_backup" || return 5
    complete_lifecycle_journals "$recovery_pending_sha" || return 5
    printf '%s\n' 'ROUTER_WEB_INSTALL=PASS' "TARGET=$target" "BACKUP=$recovery_backup" 'RECOVERED_COMMITTED=true'
    exit 0
  fi

  [ ! -L "$recovery_backup/COMMITTED" ] || return 2
  cleanup_recovery_temporaries "$root" || return 5
  cleanup_recovery_auth_temporaries || return 5
  # Classification above completes before this first recovery write.
  if [ "$recovery_auth_current" = "$recovery_auth_after" ]; then
    temporary=$(mktemp "$auth_dir/authorized_keys.new.XXXXXX") || return 5
    cp "$recovery_backup/authorized_keys.before" "$temporary" || return 5
    chown 0:0 "$temporary" || return 5
    chmod 0600 "$temporary" || return 5
    fsync_path "$temporary" || return 5
    [ "$(file_state "$auth" -rw-------)" = "$recovery_auth_after" ] || return 3
    mv -f "$temporary" "$auth" || return 5
    temporary=
    fsync_directory "$auth_dir" || return 5
  fi
  for recovery_name in $asset_names; do
    recovery_key=$(printf '%s' "$recovery_name" | tr 'a-z.-' 'A-Z__')
    recovery_after=$(journal_value "$prepared" "${recovery_key}_AFTER_SHA256") || return 2
    [ "$(file_state "$root/$recovery_name" -r-x------)" = "$recovery_after" ] || continue
    rm -f "$root/$recovery_name" || return 5
    fsync_directory "$root" || return 5
  done
  if [ -d "$root" ] && [ ! -L "$root" ]; then
    find "$root" -mindepth 1 -maxdepth 1 | grep -q . && return 5
    rmdir "$root" || return 5
    fsync_directory "$publisher_root" || return 5
  fi
  [ "$(file_state "$auth" -rw-------)" = "$recovery_auth_before" ] || return 5
  if [ -e "$recovery_backup/COMMITTED.partial" ] || [ -L "$recovery_backup/COMMITTED.partial" ]; then
    trusted_file "$recovery_backup/COMMITTED.partial" -rw------- || return 5
    rm -f "$recovery_backup/COMMITTED.partial" || return 5
    fsync_directory "$recovery_backup" || return 5
  fi
  backup=$recovery_backup
  failure_reason=RECOVERED_TO_BEFORE
  pending_sha=$recovery_pending_sha
  prepared_sha=$(sha "$prepared") || return 5
  [ "$recovery_rolled_back" = true ] || write_status ROLLED_BACK || return 5
  cleanup_recovery_source "$recovery_source" "$recovery_backup" || return 5
  complete_lifecycle_journals "$recovery_pending_sha" || return 5
  printf '%s\n' 'ROUTER_WEB_INSTALL=RECOVERED_TO_BEFORE' "TARGET=$target" "BACKUP=$recovery_backup"
  exit 0
}
prepared_exit(){
  exit_code=$?
  if stop_web_access_for_recovery; then web_access_disabled=true; else web_access_disabled=false; fi
  printf '%s\n' "WEB_ACCESS_DISABLED=$web_access_disabled"
  printf '%s\n' 'ROUTER_WEB_INSTALL=RECOVERY_REQUIRED' "TARGET=$target" "BACKUP=$backup"
  exit "$exit_code"
}
trap cleanup_sources EXIT
trap 'exit 128' HUP INT TERM

[ -d "$publisher_root" ] && [ ! -L "$publisher_root" ] || hold PUBLISHER_ROOT 13
[ "$(ls -ldn "$publisher_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold PUBLISHER_ROOT_MODE 13
[ -d "$state_root" ] && [ ! -L "$state_root" ] || hold STATE_ROOT 13
[ "$(ls -ldn "$state_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold STATE_ROOT_MODE 13
[ -d "$auth_dir" ] && [ ! -L "$auth_dir" ] || hold AUTHORIZED_KEYS_DIR 14
[ "$(ls -ldn "$auth_dir" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold AUTHORIZED_KEYS_DIR_MODE 14
for command in flock cmp sha256sum mktemp ruby lua uci pidof readlink; do command -v "$command" >/dev/null 2>&1 || hold TOOL 23; done

ensure_lock_file "$install_lock" /etc/openclash || hold INSTALL_LOCK_CREATE 24
exec 5<>"$install_lock"
flock -n 5 || hold INSTALL_LOCK 24
lock_binding "$install_lock" 5 || hold INSTALL_LOCK_BINDING 24
ensure_lock_file "$state_root/activation.lock" "$state_root" || hold ACTIVATION_LOCK_CREATE 24
exec 8<>"$state_root/activation.lock"
flock -n 8 || hold ACTIVATION_LOCK 24
lock_binding "$state_root/activation.lock" 8 || hold ACTIVATION_LOCK_BINDING 24
ensure_lock_file "$publisher_root/stage.lock" "$publisher_root" || hold STAGE_LOCK_CREATE 24
exec 9<>"$publisher_root/stage.lock"
flock -n 9 || hold STAGE_LOCK 24
lock_binding "$publisher_root/stage.lock" 9 || hold STAGE_LOCK_BINDING 24
ensure_lock_file "$state_root/customizations.lock" "$state_root" || hold WEB_LOCK_CREATE 24
exec 7<>"$state_root/customizations.lock"
flock -n 7 || hold WEB_LOCK 24
lock_binding "$state_root/customizations.lock" 7 || hold WEB_LOCK_BINDING 24
ensure_lock_file "$auth_lock" "$auth_dir" || hold AUTHORIZED_KEYS_LOCK_CREATE 24
exec 6<>"$auth_lock"
flock -n 6 || hold AUTHORIZED_KEYS_LOCK 24
lock_binding "$auth_lock" 6 || hold AUTHORIZED_KEYS_LOCK_BINDING 24
if [ -e "$global_rollback_marker" ] || [ -L "$global_rollback_marker" ]; then
  [ -f "$global_rollback_marker" ] && [ ! -L "$global_rollback_marker" ] && \
    [ "$(ls -ln "$global_rollback_marker" 2>/dev/null | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || \
    hold ROLLBACK_PREPARED_INVALID 24
  hold ROLLBACK_PREPARED 24
fi

[ -f "$auth" ] && [ ! -L "$auth" ] || hold AUTHORIZED_KEYS 14
trusted_file "$auth" -rw------- || hold AUTHORIZED_KEYS_MODE 14

capture_runtime_baseline || hold RUNTIME_BASELINE 25
normalize_pending_partial || recovery_hold PENDING_PARTIAL_INVALID 25
if [ -e "$prepared_partial" ] || [ -L "$prepared_partial" ]; then
  [ ! -e "$prepared" ] && [ ! -L "$prepared" ] || recovery_hold PREPARED_PARTIAL_CONFLICT 25
  trusted_file "$prepared_partial" -rw------- || recovery_hold PREPARED_PARTIAL_INVALID 25
  rm -f "$prepared_partial" || recovery_hold PREPARED_PARTIAL_CLEANUP 25
  fsync_directory "$state_root" || recovery_hold PREPARED_PARTIAL_CLEANUP 25
fi
recover_prepared_install || case "$?" in
  2) recovery_hold PREPARED_INVALID 25;;
  3) recovery_hold PREPARED_THIRD_HASH 25;;
  4) recovery_hold COMMITTED_MIXED_STATE 25;;
  6) recovery_hold PREPARED_RUNTIME_DRIFT 25;;
  *) recovery_hold PREPARED_RECOVERY_FAILED 25;;
esac
if [ -e "$active_state" ] || [ -L "$active_state" ]; then
  verify_active_install || case "$?" in
    2) recovery_hold ACTIVE_INVALID 25;;
    *) recovery_hold ACTIVE_STATE_DRIFT 25;;
  esac
fi
if [ -e "$active_partial" ] || [ -L "$active_partial" ]; then recovery_hold ACTIVE_PARTIAL_ORPHAN 25; fi
recover_pending_without_prepared || case "$?" in 2) recovery_hold PENDING_INVALID 25;; *) recovery_hold PENDING_RECOVERY_FAILED 25;; esac
if [ -e "$active_state" ] || [ -L "$active_state" ]; then
  cleanup_recovery_temporaries "$root" || recovery_hold TEMPORARY_INVALID 25
fi
cleanup_recovery_auth_temporaries || recovery_hold AUTHORIZED_KEYS_TEMPORARY_INVALID 25
if [ -e "$active_state" ] || [ -L "$active_state" ]; then
  printf '%s\n' 'ROUTER_WEB_INSTALL=PASS' "TARGET=$target" 'RECOVERED_ACTIVE=true'
  exit 0
fi
[ -f "$pub_file" ] && [ ! -L "$pub_file" ] || hold PUBLIC_KEY 13
source_metadata "$pub_file"
pub_file_inode=$(inode "$pub_file")
pub_file_sha=$(sha "$pub_file")
pub=$(sed -n '1p' "$pub_file")
case "$pub" in ssh-ed25519\ *) ;; *) hold PUBLIC_KEY 13;; esac
[ "$(wc -l <"$pub_file" | tr -d ' ')" -eq 1 ] || hold PUBLIC_KEY 13
[ "$(printf '%s' "$pub" | wc -c | tr -d ' ')" -le 512 ] || hold PUBLIC_KEY 13
key_type=$(printf '%s\n' "$pub" | awk '{print $1}')
key_data=$(printf '%s\n' "$pub" | awk '{print $2}')
case "$key_data" in ''|*[!A-Za-z0-9+/=]*) hold PUBLIC_KEY 13;; esac
pub="$key_type $key_data"
for file in "$agent_source" "$forced_source" "$customizer_source" "$transaction_source" "$guard_source"; do source_metadata "$file"; done
[ ! -e "$root" ] && [ ! -L "$root" ] || hold WEB_ROOT_EXISTS 22
if grep -q 'openclash-web-router_' "$auth"; then hold EXISTING_KEY 17; fi

if [ ! -e "$backup_root" ] && [ ! -L "$backup_root" ]; then
  mkdir "$backup_root" || hold BACKUP_ROOT_CREATE 25
  chmod 0700 "$backup_root" || hold BACKUP_ROOT_MODE 25
  fsync_directory "$publisher_root" || hold BACKUP_ROOT_FSYNC 25
fi
[ -d "$backup_root" ] && [ ! -L "$backup_root" ] || hold BACKUP_ROOT 25
[ "$(ls -ldn "$backup_root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold BACKUP_ROOT_MODE 25
[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 25
publish_pending INSTALL "$backup" || hold PENDING_PUBLISH 25
pending_sha=$(sha "$pending") || hold PENDING_DIGEST 25
valid_digest "$pending_sha" || hold PENDING_DIGEST 25
trap pending_exit EXIT
trap 'exit 128' HUP INT TERM
mkdir "$backup"
chmod 0700 "$backup"
fsync_directory "$backup_root"
source_stage=$backup/source
mkdir "$source_stage"
chmod 0700 "$source_stage"
source_stage_ready=true
for pair in $asset_manifest; do
  name=${pair%%:*}
  source_file=${pair#*:}
  source_metadata "$source_file"
  before_inode=$(inode "$source_file")
  before_sha=$(sha "$source_file")
  [ "$before_sha" = "$(expected_hash "$name")" ] || hold SOURCE_TRUST 26
  cp "$source_file" "$source_stage/$name"
  chown 0:0 "$source_stage/$name"
  chmod 0600 "$source_stage/$name"
  source_metadata "$source_file"
  [ "$(inode "$source_file")" = "$before_inode" ] || hold SOURCE_DRIFT 26
  [ "$(sha "$source_file")" = "$before_sha" ] || hold SOURCE_DRIFT 26
  [ "$(sha "$source_stage/$name")" = "$before_sha" ] || hold SOURCE_HASH 26
  case "$name" in
    openclash_web_router_agent.lua) agent_source_inode=$before_inode;;
    openclash_web_forced_command.sh) forced_source_inode=$before_inode;;
    openclash_customizer.rb) customizer_source_inode=$before_inode;;
    openclash_custom_transaction.sh) transaction_source_inode=$before_inode;;
    openclash_custom_rollback_guard.sh) guard_source_inode=$before_inode;;
  esac
  fsync_path "$source_stage/$name"
done
before_inode=$(inode "$pub_file")
before_sha=$(sha "$pub_file")
cp "$pub_file" "$source_stage/public_key"
chown 0:0 "$source_stage/public_key"
chmod 0600 "$source_stage/public_key"
[ "$(inode "$pub_file")" = "$before_inode" ] && [ "$(sha "$pub_file")" = "$before_sha" ] || hold SOURCE_DRIFT 26
[ "$(sha "$source_stage/public_key")" = "$before_sha" ] || hold SOURCE_HASH 26
pub_file_inode=$before_inode
fsync_path "$source_stage/public_key"
fsync_directory "$source_stage"
fsync_directory "$backup"
source_bundle_ok "$source_stage" INSTALL true || hold SOURCE_BUNDLE 26
asset_manifest='openclash_web_router_agent.lua:'"$source_stage"'/openclash_web_router_agent.lua openclash_web_forced_command.sh:'"$source_stage"'/openclash_web_forced_command.sh openclash_customizer.rb:'"$source_stage"'/openclash_customizer.rb openclash_custom_transaction.sh:'"$source_stage"'/openclash_custom_transaction.sh openclash_custom_rollback_guard.sh:'"$source_stage"'/openclash_custom_rollback_guard.sh'

OPENCLASH_LUA_SOURCE="$source_stage/openclash_web_router_agent.lua" \
  lua -e 'local path=os.getenv("OPENCLASH_LUA_SOURCE"); assert(path and path~=""); assert(loadfile(path))' || hold LUA_SYNTAX 15
/bin/sh -n "$source_stage/openclash_web_forced_command.sh" || hold SHELL_SYNTAX 16
ruby -c "$source_stage/openclash_customizer.rb" >/dev/null 2>&1 || hold RUBY_SYNTAX 19
/bin/sh -n "$source_stage/openclash_custom_transaction.sh" || hold TRANSACTION_SYNTAX 20
/bin/sh -n "$source_stage/openclash_custom_rollback_guard.sh" || hold GUARD_SYNTAX 21

pub=$(sed -n '1p' "$source_stage/public_key")
[ "$(wc -l <"$source_stage/public_key" | tr -d ' ')" -eq 1 ] || hold PUBLIC_KEY 13
[ "$(inode "$pub_file")" = "$pub_file_inode" ] && [ "$(sha "$pub_file")" = "$pub_file_sha" ] || hold PUBLIC_KEY_DRIFT 13
entry="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,command=\"$root/openclash_web_forced_command.sh $target\" $pub openclash-web-$target"

for name in $asset_names; do
  : >"$backup/$name.absent"
  chmod 0600 "$backup/$name.absent"
done
auth_before_inode=$(inode "$auth")
auth_before_sha=$(sha "$auth")
cp "$auth" "$backup/authorized_keys.before"
chmod 0600 "$backup/authorized_keys.before"
[ "$(inode "$auth")" = "$auth_before_inode" ] && [ "$(sha "$auth")" = "$auth_before_sha" ] || hold AUTHORIZED_KEYS_DRIFT 27
: >"$backup/SHA256SUMS.before" || hold BACKUP_HASH 26
(cd "$backup" && sha256sum authorized_keys.before >>SHA256SUMS.before) || hold BACKUP_HASH 26
for name in $asset_names; do
  (cd "$backup" && sha256sum "$name.absent" >>SHA256SUMS.before) || hold BACKUP_HASH 26
done
chmod 0600 "$backup/SHA256SUMS.before"
fsync_path "$backup/authorized_keys.before" || hold BACKUP_FSYNC 26
fsync_path "$backup/SHA256SUMS.before" || hold BACKUP_FSYNC 26
for name in $asset_names; do
  fsync_path "$backup/$name.absent" || hold BACKUP_FSYNC 26
done
fsync_directory "$backup" || hold BACKUP_FSYNC 26

# Durable install intent is published before the first web or authorized_keys mutation.
cp "$auth" "$backup/authorized_keys.after" || hold BACKUP_COPY 27
printf '%s\n' "$entry" >>"$backup/authorized_keys.after" || hold BACKUP_COPY 27
chown 0:0 "$backup/authorized_keys.after" || hold BACKUP_MODE 27
chmod 0600 "$backup/authorized_keys.after" || hold BACKUP_MODE 27
grep -Fxc "$entry" "$backup/authorized_keys.after" | grep -qx 1 || hold AUTHORIZED_KEYS_AFTER 27
fsync_path "$backup/authorized_keys.after" || hold BACKUP_FSYNC 27
auth_after_sha=$(sha "$backup/authorized_keys.after") || hold PREPARED_DIGEST 27
active_before_digest=$(sha_text "$active_before") || hold PREPARED_DIGEST 27
backup_manifest_sha=$(sha "$backup/SHA256SUMS.before") || hold PREPARED_DIGEST 27
valid_digest "$auth_before_sha" && valid_digest "$auth_after_sha" && valid_digest "$active_before_digest" &&
  valid_digest "$backup_manifest_sha" || hold PREPARED_DIGEST 27
prepared_payload=$backup/PREPARED.payload
: >"$prepared_payload" || hold PREPARED_BUILD 27
chmod 0600 "$prepared_payload" || hold PREPARED_BUILD 27
printf '%s\n' PREPARED 'SCHEMA=publisher-v4-router-web-install-prepared-v2' 'OP=INSTALL' "TARGET=$target" \
  "BACKUP_PATH=$backup" "ROOT_PATH=$root" "BACKUP_MANIFEST_SHA256=$backup_manifest_sha" \
  "PENDING_PATH=$pending" "PENDING_SHA256=$pending_sha" \
  "ACTIVE_BEFORE_SHA256=$active_before_digest" "UCI_BEFORE_SHA256=$uci_before_sha" "CORE_SHA256=$core_sha_before" \
  "CORE_PID_BEFORE=$core_pid_before" "CORE_START_BEFORE=$core_start_before" "MAIN_BEFORE_SHA256=$main_before_sha" \
  "RUNTIME_BEFORE_SHA256=$runtime_before_sha" "CUSTOM_STATE_BEFORE_SHA256=$state_before_sha" \
  >"$prepared_payload" || hold PREPARED_BUILD 27
for name in $asset_names; do
  journal_key=$(printf '%s' "$name" | tr 'a-z.-' 'A-Z__') || hold PREPARED_BUILD 27
  journal_after=$(sha "$source_stage/$name") || hold PREPARED_DIGEST 27
  valid_digest "$journal_after" || hold PREPARED_DIGEST 27
  case "$name" in
    openclash_web_router_agent.lua) journal_source_inode=$agent_source_inode;;
    openclash_web_forced_command.sh) journal_source_inode=$forced_source_inode;;
    openclash_customizer.rb) journal_source_inode=$customizer_source_inode;;
    openclash_custom_transaction.sh) journal_source_inode=$transaction_source_inode;;
    openclash_custom_rollback_guard.sh) journal_source_inode=$guard_source_inode;;
    *) hold PREPARED_BUILD 27;;
  esac
  case "$journal_source_inode" in ''|*[!0-9]*) hold PREPARED_DIGEST 27;; esac
  printf '%s\n' "${journal_key}_TARGET=$root/$name" "${journal_key}_BEFORE_SHA256=MISSING" \
    "${journal_key}_AFTER_SHA256=$journal_after" "${journal_key}_SOURCE_INODE=$journal_source_inode" \
    >>"$prepared_payload" || hold PREPARED_BUILD 27
done
printf '%s\n' "AUTHORIZED_KEYS_BEFORE_SHA256=$auth_before_sha" "AUTHORIZED_KEYS_AFTER_SHA256=$auth_after_sha" \
  "PUBLIC_KEY_SOURCE_INODE=$pub_file_inode" "PUBLIC_KEY_SOURCE_SHA256=$pub_file_sha" \
  >>"$prepared_payload" || hold PREPARED_BUILD 27
fsync_path "$prepared_payload" || hold PREPARED_FSYNC 27
prepared_install_schema_ok "$prepared_payload" || hold PREPARED_SCHEMA 27
atomic_publish_stream "$prepared" "$prepared_partial" <"$prepared_payload" || hold PREPARED_FSYNC 27
prepared_install_schema_ok "$prepared" || hold PREPARED_SCHEMA 27
prepared_sha=$(sha "$prepared") || hold PREPARED_DIGEST 27
valid_digest "$prepared_sha" || hold PREPARED_DIGEST 27
rm -f "$prepared_payload" || hold PREPARED_CLEANUP 27
fsync_directory "$backup" || hold PREPARED_CLEANUP 27
trap prepared_exit EXIT

rollback_ok=true
committed=false
atomic_restore(){
  source_file=$1
  target_file=$2
  mode=$3
  temporary=''
  temporary=$(mktemp "$root/.openclash-sync-web-new.XXXXXX") || return 31
  if ! cp "$source_file" "$temporary"; then rm -f "$temporary"; return 31; fi
  if ! chown 0:0 "$temporary"; then rm -f "$temporary"; return 31; fi
  if ! chmod "$mode" "$temporary"; then rm -f "$temporary"; return 31; fi
  if ! cmp -s "$source_file" "$temporary"; then rm -f "$temporary"; return 32; fi
  if ! fsync_path "$temporary"; then rm -f "$temporary"; return 33; fi
  if ! mv -f "$temporary" "$target_file"; then rm -f "$temporary"; return 34; fi
  fsync_path "$target_file" || return 35
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
rollback(){
  set +e
  rollback_ok=true
  if stop_web_access_for_recovery; then
    web_access_disabled=true
  else
    web_access_disabled=false
    failure_reason=WEB_ACCESS_STOP_FAILED
    if write_status ROLLBACK_FAILED; then receipt_unavailable=false; else receipt_unavailable=true; fi
    printf 'ROUTER_WEB_INSTALL=ROLLBACK_FAILED\nTARGET=%s\nBACKUP=%s\nRECEIPT_UNAVAILABLE=%s\nWEB_ACCESS_DISABLED=false\n' "$target" "$backup" "$receipt_unavailable"
    return
  fi
  cleanup_temporaries
  [ ! -e "$backup/COMMITTED" ] && [ ! -L "$backup/COMMITTED" ] || rollback_ok=false
  if [ -e "$backup/COMMITTED.partial" ] || [ -L "$backup/COMMITTED.partial" ]; then
    trusted_file "$backup/COMMITTED.partial" -rw------- || rollback_ok=false
    if [ "$rollback_ok" = true ]; then rm -f "$backup/COMMITTED.partial" || rollback_ok=false; fi
  fi
  fsync_directory "$backup" || rollback_ok=false
  if (cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1); then
    if [ -d "$root" ] && [ ! -L "$root" ]; then
      for name in $asset_names; do
        intended=$(expected_hash "$name" 2>/dev/null || true)
        atomic_remove "$root/$name" "$intended" || rollback_ok=false
      done
      [ ! -e "$root" ] || [ ! -L "$root" ] || rollback_ok=false
      rmdir "$root" || rollback_ok=false
      fsync_directory "$publisher_root" || rollback_ok=false
    else
      [ ! -e "$root" ] && [ ! -L "$root" ] || rollback_ok=false
    fi
    if [ "$auth_published" = true ]; then
      [ "$(sha "$auth" 2>/dev/null || true)" = "$auth_after_sha" ] || rollback_ok=false
      temporary=$(mktemp "$auth_dir/authorized_keys.new.XXXXXX") || rollback_ok=false
      if [ -n "${temporary:-}" ] && [ -e "$temporary" ]; then
        cp "$backup/authorized_keys.before" "$temporary" || rollback_ok=false
        chown 0:0 "$temporary" || rollback_ok=false
        chmod 0600 "$temporary" || rollback_ok=false
        cmp -s "$backup/authorized_keys.before" "$temporary" || rollback_ok=false
        fsync_path "$temporary" || rollback_ok=false
        mv -f "$temporary" "$auth" || rollback_ok=false
        temporary=
        fsync_path "$auth" || rollback_ok=false
        fsync_directory "$auth_dir" || rollback_ok=false
      fi
    else
      [ "$(sha "$auth" 2>/dev/null || true)" = "$auth_before_sha" ] || rollback_ok=false
    fi
  else
    rollback_ok=false
  fi
  cleanup_temporaries
  cleanup_status_partials || rollback_ok=false
  [ ! -L "$auth" ] || rollback_ok=false
  if [ "$auth_published" = true ]; then
    cmp -s "$backup/authorized_keys.before" "$auth" || rollback_ok=false
    [ "$(ls -ln "$auth" 2>/dev/null | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || rollback_ok=false
  fi
  [ ! -e "$root" ] && [ ! -L "$root" ] || rollback_ok=false
  cleanup_sources || rollback_ok=false
  if [ "$rollback_ok" = true ]; then
    write_status ROLLED_BACK || rollback_ok=false
  fi
  if [ "$rollback_ok" != true ]; then
    rm -f "$backup/ROLLED_BACK" || true
    fsync_directory "$backup" || true
    if write_status ROLLBACK_FAILED; then receipt_unavailable=false; else receipt_unavailable=true; fi
    printf 'ROUTER_WEB_INSTALL=ROLLBACK_FAILED\nTARGET=%s\nBACKUP=%s\nRECEIPT_UNAVAILABLE=%s\nWEB_ACCESS_DISABLED=%s\n' "$target" "$backup" "$receipt_unavailable" "$web_access_disabled"
  else
    printf 'ROUTER_WEB_INSTALL=ROLLED_BACK\nTARGET=%s\nBACKUP=%s\nRECEIPT_UNAVAILABLE=false\n' "$target" "$backup"
  fi
}
finish(){
  exit_code=$?
  if [ "$committed" != true ]; then
    if [ -e "$prepared" ] || [ -L "$prepared" ]; then
      if stop_web_access_for_recovery; then web_access_disabled=true; else web_access_disabled=false; fi
      printf '%s\n' "WEB_ACCESS_DISABLED=$web_access_disabled"
      printf '%s\n' 'ROUTER_WEB_INSTALL=RECOVERY_REQUIRED' "TARGET=$target" "BACKUP=$backup"
    else
      rollback
    fi
  fi
  exit "$exit_code"
}
trap finish EXIT
trap 'exit 128' HUP INT TERM

runtime_unchanged || hold RUNTIME_DRIFT 30
mkdir "$root" || hold WEB_ROOT_CREATE 30
chmod 0700 "$root" || hold WEB_ROOT_MODE 30
fsync_directory "$root" || hold WEB_ROOT_FSYNC 30
fsync_directory "$publisher_root" || hold WEB_ROOT_FSYNC 30

atomic_publish(){
  source_file=$1
  target_file=$2
  mode=$3
  source_metadata "$source_file"
  source_before_inode=$(inode "$source_file")
  source_before_sha=$(sha "$source_file")
  temporary=$(mktemp "$root/.openclash-sync-web-new.XXXXXX") || return 31
  cp "$source_file" "$temporary" || { rm -f "$temporary"; return 31; }
  source_metadata "$source_file"
  [ "$(inode "$source_file")" = "$source_before_inode" ] || { rm -f "$temporary"; return 37; }
  [ "$(sha "$source_file")" = "$source_before_sha" ] || { rm -f "$temporary"; return 37; }
  chown 0:0 "$temporary" || { rm -f "$temporary"; return 31; }
  chmod "$mode" "$temporary" || { rm -f "$temporary"; return 31; }
  cmp -s "$source_file" "$temporary" || { rm -f "$temporary"; return 32; }
  fsync_path "$temporary" || { rm -f "$temporary"; return 33; }
  mv -f "$temporary" "$target_file" || { rm -f "$temporary"; return 34; }
  temporary=
  fsync_path "$target_file" || return 35
  fsync_directory "$root" || return 36
}

for pair in $asset_manifest; do
  name=${pair%%:*}
  source_file=${pair#*:}
  atomic_publish "$source_file" "$root/$name" 0500 || hold ATOMIC_PUBLISH 31
done

atomic_authorized_keys(){
  [ -f "$auth" ] && [ ! -L "$auth" ] || return 40
  [ "$(inode "$auth")" = "$auth_before_inode" ] && [ "$(sha "$auth")" = "$auth_before_sha" ] || return 50
  temporary=$(mktemp "$auth_dir/authorized_keys.new.XXXXXX") || return 41
  cp "$auth" "$temporary" || { rm -f "$temporary"; return 41; }
  [ "$(inode "$auth")" = "$auth_before_inode" ] && [ "$(sha "$auth")" = "$auth_before_sha" ] || return 50
  printf '%s\n' "$entry" >>"$temporary" || { rm -f "$temporary"; return 42; }
  chown 0:0 "$temporary" || { rm -f "$temporary"; return 43; }
  chmod 0600 "$temporary" || { rm -f "$temporary"; return 43; }
  key_count=$(grep -Fxc "$entry" "$temporary" || true)
  [ "$key_count" -eq 1 ] || { rm -f "$temporary"; return 44; }
  cmp -s "$auth" "$temporary" && { rm -f "$temporary"; return 45; }
  fsync_path "$temporary" || { rm -f "$temporary"; return 46; }
  [ "$(inode "$auth")" = "$auth_before_inode" ] && [ "$(sha "$auth")" = "$auth_before_sha" ] || return 50
  mv -f "$temporary" "$auth" || { rm -f "$temporary"; return 47; }
  temporary=
  fsync_path "$auth" || return 48
  fsync_directory "$auth_dir" || return 49
  auth_published=true
  auth_after_sha=$(sha "$auth")
}
atomic_authorized_keys || hold AUTHORIZED_KEYS_PUBLISH 32
runtime_unchanged || hold RUNTIME_DRIFT 32

for name in $asset_names; do
  [ -f "$root/$name" ] && [ ! -L "$root/$name" ] || hold INSTALLED_ASSET 33
  [ "$(ls -ln "$root/$name" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold INSTALLED_MODE 33
done
key_count=$(grep -Fxc "$entry" "$auth" || true)
[ "$key_count" -eq 1 ] || hold KEY_COUNT 34
cmp -s "$backup/authorized_keys.before" "$auth" && hold AUTHORIZED_KEYS_UNCHANGED 34
active_after=$(uci -q get openclash.config.config_path) || hold RUNTIME_DRIFT 34
uci_after_sha=$(uci_digest) || hold RUNTIME_DRIFT 34
config_changed=false
[ "$active_after" = "$active_before" ] && [ "$uci_after_sha" = "$uci_before_sha" ] || config_changed=true
  current_pid=$(pidof clash_meta 2>/dev/null || true)
  current_start=$(process_starttime "$current_pid" 2>/dev/null || true)
  service_restarted=false
  [ "$current_pid" = "$core_pid_before" ] && [ "$current_start" = "$core_start_before" ] || service_restarted=true
  [ "$(sha "$main")" = "$main_before_sha" ] &&
  [ "$(sha "$runtime")" = "$runtime_before_sha" ] &&
  [ "$(sha "$custom_state")" = "$state_before_sha" ] || config_changed=true
  [ "$config_changed" = false ] && [ "$service_restarted" = false ] || hold RUNTIME_DRIFT 34
cleanup_temporaries

active_after_digest=$(sha_text "$active_after") || hold RECEIPT_DIGEST 35
main_after_sha=$(sha "$main") || hold RECEIPT_DIGEST 35
runtime_after_sha=$(sha "$runtime") || hold RECEIPT_DIGEST 35
state_after_sha=$(sha "$custom_state") || hold RECEIPT_DIGEST 35
valid_digest "$active_after_digest" && valid_digest "$main_after_sha" && valid_digest "$runtime_after_sha" &&
  valid_digest "$state_after_sha" || hold RECEIPT_DIGEST 35
: >"$backup/COMMITTED.partial" || hold RECEIPT 35
chmod 0600 "$backup/COMMITTED.partial" || hold RECEIPT 35
printf '%s\n' COMMITTED 'SCHEMA=publisher-v4-router-web-install-v3' "TARGET=$target" \
  "ACTIVE_BEFORE_SHA256=$active_before_digest" "ACTIVE_AFTER_SHA256=$active_after_digest" \
  "UCI_BEFORE_SHA256=$uci_before_sha" "UCI_AFTER_SHA256=$uci_after_sha" \
  "CORE_SHA256=$core_sha_before" "CORE_PID_BEFORE=$core_pid_before" "CORE_START_BEFORE=$core_start_before" \
  "CORE_PID_AFTER=$current_pid" "CORE_START_AFTER=$current_start" \
  "MAIN_BEFORE_SHA256=$main_before_sha" "MAIN_AFTER_SHA256=$main_after_sha" \
  "RUNTIME_BEFORE_SHA256=$runtime_before_sha" "RUNTIME_AFTER_SHA256=$runtime_after_sha" \
  "CUSTOM_STATE_BEFORE_SHA256=$state_before_sha" "CUSTOM_STATE_AFTER_SHA256=$state_after_sha" \
  "CONFIG_CHANGED=$config_changed" "SERVICE_RESTARTED=$service_restarted" \
  >"$backup/COMMITTED.partial" || hold RECEIPT 35
for name in $asset_names; do
  asset_after_sha=$(sha "$root/$name") || hold RECEIPT_DIGEST 35
  valid_digest "$asset_after_sha" || hold RECEIPT_DIGEST 35
  printf '%s_AFTER_SHA256=%s\n' "$name" "$asset_after_sha" >>"$backup/COMMITTED.partial" || hold RECEIPT 35
done
printf '%s\n' "AUTHORIZED_KEYS_BEFORE_SHA256=$auth_before_sha" "AUTHORIZED_KEYS_AFTER_SHA256=$auth_after_sha" \
  "PENDING_SHA256=$pending_sha" "PREPARED_SHA256=$prepared_sha" \
  >>"$backup/COMMITTED.partial" || hold RECEIPT 35
committed_install_schema_ok "$backup/COMMITTED.partial" || hold RECEIPT_SCHEMA 35
committed_history_matches_prepared "$prepared" "$backup/COMMITTED.partial" INSTALL || hold RECEIPT_HISTORY 35
fsync_path "$backup/COMMITTED.partial" || hold RECEIPT_FSYNC 35
mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED" || hold RECEIPT 35
fsync_directory "$backup" || hold RECEIPT_FSYNC 35
committed_install_schema_ok "$backup/COMMITTED" || hold RECEIPT_SCHEMA 35
committed_history_matches_prepared "$prepared" "$backup/COMMITTED" INSTALL || hold RECEIPT_HISTORY 35
committed=true
publish_active_install "$backup" || recovery_hold ACTIVE_FSYNC 35
cleanup_sources || recovery_hold SOURCE_CLEANUP 35
[ "$source_stage_ready" = false ] && [ ! -e "$source_stage" ] || recovery_hold SOURCE_CLEANUP 35
complete_lifecycle_journals "$pending_sha" || recovery_hold LIFECYCLE_CLEANUP 35
trap - EXIT HUP INT TERM
printf '%s\n' 'ROUTER_WEB_INSTALL=PASS' "TARGET=$target" "BACKUP=$backup" "CONFIG_CHANGED=$config_changed" "SERVICE_RESTARTED=$service_restarted"
