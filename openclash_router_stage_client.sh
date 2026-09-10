#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'ROUTER_STAGE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
cleanup_sensitive_file(){
  file=$1
  [ -f "$file" ] || return 0
  size=$(wc -c <"$file" | tr -d ' ')
  if [ "$size" -gt 0 ]; then
    dd if=/dev/zero of="$file" bs=4096 count=$(( (size + 4095) / 4096 )) conv=notrunc 2>/dev/null || true
  fi
  rm -f "$file"
}
cleanup_uncommitted(){
  if [ "${stage_committed:-false}" != true ]; then
    [ -n "${maying_tmp:-}" ] && cleanup_sensitive_file "$maying_tmp"
    [ -n "${maying:-}" ] && cleanup_sensitive_file "$maying"
    [ -n "${candidate:-}" ] && cleanup_sensitive_file "$candidate"
    [ -n "${builder_error:-}" ] && cleanup_sensitive_file "$builder_error"
  fi
}
interrupted(){ exit 128; }
stage_committed=false
trap cleanup_uncommitted EXIT
trap interrupted HUP INT TERM
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
target=$1
case "$target" in router_a|router_b) ;; *) hold TARGET 12;; esac

root=/etc/openclash/publisher-v4
bin=$root/bin
keys=$root/keys
stage_root=$root/stage
worker_host=192.0.2.20
worker_user=syncsvc
key=$keys/sync-worker-ed25519
builder=$bin/openclash_router_stage_builder.rb
expected_core_sha=0000000000000000000000000000000000000000000000000000000000000000

for file in "$key" "$builder" /root/.ssh/known_hosts; do [ -f "$file" ] && [ ! -L "$file" ] || hold ASSET 13; done
[ "$(ls -ln "$key" | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold KEY_MODE 14
[ "$(ls -ln /root/.ssh/known_hosts | awk '{print $1 ":" $3 ":" $4}')" = '-rw-------:0:0' ] || hold HOSTKEY_MODE 15
[ "$(ls -ln "$builder" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold BUILDER_MODE 15
find "$root" -xdev -type l | grep -q . && hold ROOT_SYMLINK 15

active=$(uci -q get openclash.config.config_path || true)
[ "$active" = /etc/openclash/config/ProviderBase-ProviderSource.yaml ] || hold ACTIVE_DRIFT 16
/etc/init.d/openclash running >/dev/null 2>&1 || hold SERVICE 17
pid=$(pidof clash_meta 2>/dev/null || true)
case "$pid" in ''|*' '*) hold CORE_CARDINALITY 18;; esac
core=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
[ -f "$core" ] && [ "$(sha256sum "$core" | awk '{print $1}')" = "$expected_core_sha" ] || hold CORE_IDENTITY 19

lock=$root/stage.lock
mkdir -p "$stage_root"
chmod 0700 "$root" "$bin" "$keys" "$stage_root"
for directory in "$root" "$bin" "$keys" "$stage_root"; do
  [ "$(ls -ldn "$directory" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold DIRECTORY_MODE 21
done
exec 9>"$lock"
flock -n 9 || hold LOCK 22
transaction=$(date -u +%Y%m%dT%H%M%SZ)-$$
case "$transaction" in *[!0-9TZ-]*) hold TRANSACTION 23;; esac
stage=$stage_root/$transaction
mkdir "$stage"
chmod 0700 "$stage"
receipt=$stage/worker-receipt.json
maying=$stage/Maying-normalized.yaml
maying_tmp=$stage/Maying-normalized.yaml.partial

if ! lua - <<'LUA' | ssh -T -q -i "$key" \
  "$worker_user@$worker_host" publisher-v4-openclash-worker-v1 \
  >"$maying_tmp" 2>"$receipt"
local json=require("luci.jsonc")
local uci=require("luci.model.uci").cursor()
local addresses={}
uci:foreach("openclash","config_subscribe",function(section)
  if section.name=="Maying" and type(section.address)=="string" then addresses[#addresses+1]=section.address end
end)
assert(#addresses==1)
local address=addresses[1]
assert(#address>0 and #address<=16384)
io.write(json.stringify({schema="publisher-v4-worker-request-v1",address=address}))
LUA
then
  [ ! -s "$maying_tmp" ] || hold WORKER_PARTIAL_OUTPUT 30
  worker_reason=$(jsonfilter -i "$receipt" -e '@.reason' 2>/dev/null || true)
  case "$worker_reason" in
    REQUEST|REQUEST_SCHEMA|SOURCE_DRIFT|CONVERTED_YAML|MAYING_DOCUMENT_SHAPE|MAYING_DNS_UNEXPECTED|MAYING_SOURCE_CONTRACT|CONVERTER_UDP_FALSE|CONVERTER_UDP_TYPE|UDP_COUNT_MISMATCH|CONTRACT|NORMALIZATION|NORMALIZATION_POLICY|NORMALIZED_YAML|NETWORK|INTERNAL) ;;
    *) worker_reason=INTERNAL ;;
  esac
  hold "WORKER_$worker_reason" 31
fi
chmod 0600 "$maying_tmp" "$receipt"
[ -s "$maying_tmp" ] && [ -s "$receipt" ] || hold WORKER_OUTPUT 32
decision=$(jsonfilter -i "$receipt" -e '@.decision' 2>/dev/null || true)
reason=$(jsonfilter -i "$receipt" -e '@.reason' 2>/dev/null || true)
count=$(jsonfilter -i "$receipt" -e '@.normalization.output_proxy_count' 2>/dev/null || true)
yaml_sha=$(jsonfilter -i "$receipt" -e '@.normalized_yaml_sha256' 2>/dev/null || true)
source_format=$(jsonfilter -i "$receipt" -e '@.normalization.source_format' 2>/dev/null || true)
udp_true_count=$(jsonfilter -i "$receipt" -e '@.normalized_udp_true_count' 2>/dev/null || true)
dns_present=$(jsonfilter -i "$receipt" -e '@.converter_dns_present' 2>/dev/null || true)
[ "$decision" = PASS ] && [ "$reason" = NONE ] || hold WORKER_DECISION 33
case "$count" in ''|*[!0-9]*) hold WORKER_COUNT 34;; esac
[ "$count" -ge 1 ] && [ "$count" -le 2048 ] || hold WORKER_COUNT 34
[ "$source_format" = BASE64_SSR_URI_LIST ] || hold WORKER_MAYING_SOURCE_CONTRACT 34
case "$udp_true_count" in ''|*[!0-9]*) hold WORKER_UDP_COUNT_MISMATCH 34;; esac
[ "$udp_true_count" -eq "$count" ] || hold WORKER_UDP_COUNT_MISMATCH 34
[ "$dns_present" = false ] || hold WORKER_MAYING_DNS_UNEXPECTED 34
[ "$(sha256sum "$maying_tmp" | awk '{print $1}')" = "$yaml_sha" ] || hold WORKER_HASH 35

mv "$maying_tmp" "$maying"
chmod 0600 "$maying"
candidate=$stage/candidate.yaml
builder_error=$stage/builder-error.partial
if ! ruby "$builder" /etc/openclash/config/ProviderBase.yaml "$maying" \
  /etc/openclash/ProviderBase-ProviderSource.yaml "$candidate" "$count" \
  >"$stage/builder-receipt.yaml" 2>"$builder_error"; then
  builder_reason=$(sed -n 's/^ROUTER_STAGE_BUILD=HOLD|REASON=\([A-Z0-9_-][A-Z0-9_-]*\)$/\1/p' "$builder_error" || true)
  builder_lines=$(wc -l <"$builder_error" | tr -d ' ')
  case "$builder_reason" in
    ARGS|EXPECTED_COUNT|INPUT_PATH|OUTPUT_PATH|OUTPUT_EXISTS|YAML_SIZE|YAML_ALIAS|YAML_CLASS|YAML_SYNTAX|YAML_PARSE|YAML_BUDGET|YAML_ROOT|BASE_ROOT|MAYING_ROOT|RUNTIME_ROOT|BASE_DNS|PROXIES_TYPE|PROXY-GROUPS_TYPE|RULES_TYPE|BASE_PROXY|BASE_GROUP|MAYING_PROXY|MAYING_GROUP|MAYING_COUNT|MAYING_TYPE|MAYING_DOCUMENT_SHAPE|MAYING_DNS_UNEXPECTED|MAYING_RULES_UNEXPECTED|NODE_COLLISION|RUNTIME_PROXY|RUNTIME_GROUP|SUPPLEMENT_COUNT|SUPPLEMENT_TYPE|RUNTIME_PROXY_ROTATION|RUNTIME_GROUP_ROTATION|RUNTIME_GROUP_MISSING|RUNTIME_GROUP_REMOVAL|RUNTIME_GROUP_ADDITION|RUNTIME_MANAGED_REGION|REGION_COLLISION|REGION_MISSING|REGION_EMPTY|REGION_MEMBER|REGION_PARTITION|REGION_GROUP_SHAPE|REGION_NAME_AMBIGUOUS|BUSINESS_GROUP|BUSINESS_DUPLICATE|DNS_POLICY_COLLISION|DNS_OWNERSHIP_DRIFT|DNS_HOSTS|CANDIDATE_PROXY|CANDIDATE_GROUP|BASE_PROXY_DRIFT|RULE_DRIFT|GROUP_REFERENCE|GROUP_CYCLE|CANDIDATE_SIZE|INTERNAL) ;;
    *) builder_reason=INTERNAL ;;
  esac
  [ "$builder_lines" -eq 1 ] || builder_reason=INTERNAL
  rm -f "$builder_error"
  printf '%s\n' 'BUILDER=HOLD' "REASON=$builder_reason" >"$stage/builder-status"
  chmod 0600 "$stage/builder-status"
  hold "BUILDER_$builder_reason" 40
fi
if [ -s "$builder_error" ]; then
  rm -f "$builder_error"
  hold BUILDER_UNEXPECTED_STDERR 40
fi
rm -f "$builder_error"
chmod 0600 "$candidate" "$stage/builder-receipt.yaml"
base_dns_sha=$(awk '$1 == "base_dns_sha256:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
candidate_dns_sha=$(awk '$1 == "candidate_dns_sha256:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
builder_udp_count=$(awk '$1 == "maying_udp_true_count:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
builder_tfo_count=$(awk '$1 == "maying_tfo_false_count:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
builder_udp_runtime=$(awk '$1 == "maying_udp_runtime_verified:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
policy_host_count=$(awk '$1 == "maying_policy_host_count:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
policy_resolver_sha=$(awk '$1 == "maying_policy_resolver_set_sha256:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
builder_candidate_sha=$(awk '$1 == "candidate_sha256:" && NF == 2 {print $2}' "$stage/builder-receipt.yaml")
for digest in "$base_dns_sha" "$candidate_dns_sha" "$policy_resolver_sha" "$builder_candidate_sha"; do
  case "$digest" in ''|*[!0-9a-f]*) hold BUILDER_DNS_OWNERSHIP_DRIFT 40;; esac
  [ "${#digest}" -eq 64 ] || hold BUILDER_DNS_OWNERSHIP_DRIFT 40
done
case "$builder_udp_count" in ''|*[!0-9]*) hold BUILDER_UDP_COUNT_MISMATCH 40;; esac
case "$builder_tfo_count" in ''|*[!0-9]*) hold BUILDER_UDP_COUNT_MISMATCH 40;; esac
case "$policy_host_count" in ''|*[!0-9]*) hold BUILDER_DNS_OWNERSHIP_DRIFT 40;; esac
[ "$builder_udp_count" -eq "$count" ] && [ "$builder_tfo_count" -eq "$count" ] || hold BUILDER_UDP_COUNT_MISMATCH 40
[ "$policy_host_count" -le "$count" ] || hold BUILDER_DNS_OWNERSHIP_DRIFT 40
[ "$builder_udp_runtime" = false ] || hold BUILDER_UDP_COUNT_MISMATCH 40
printf '%s\n' 'BUILDER=PASS' >"$stage/builder-status"
chmod 0600 "$stage/builder-status"
if ! "$core" -t -d /etc/openclash -f "$candidate" >/dev/null 2>/dev/null; then
  printf '%s\n' 'MIHOMO=HOLD' >"$stage/mihomo-status"
  hold MIHOMO 41
fi
printf '%s\n' 'MIHOMO=PASS' >"$stage/mihomo-status"
chmod 0600 "$stage/mihomo-status"
candidate_sha=$(sha256sum "$candidate" | awk '{print $1}')
[ "$candidate_sha" = "$builder_candidate_sha" ] || hold BUILDER_HASH 42
printf '%s\n' \
  'ROUTER_STAGE=PASS' "TARGET=$target" "TRANSACTION=$transaction" \
  "MAYING_SOURCE_FORMAT=$source_format" "MAYING_PROXY_COUNT=$count" "MAYING_UDP_TRUE_COUNT=$udp_true_count" \
  "MAYING_DNS_PRESENT=$dns_present" "BASE_DNS_SHA256=$base_dns_sha" "CANDIDATE_DNS_SHA256=$candidate_dns_sha" \
  "MAYING_POLICY_HOST_COUNT=$policy_host_count" "MAYING_POLICY_RESOLVER_SET_SHA256=$policy_resolver_sha" \
  "CANDIDATE_SHA256=$candidate_sha" \
  'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false' \
  >"$stage/COMMITTED"
chmod 0600 "$stage/COMMITTED"
stage_committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'ROUTER_STAGE=PASS' "TARGET=$target" "MAYING_SOURCE_FORMAT=$source_format" "MAYING_PROXY_COUNT=$count" \
  "MAYING_UDP_TRUE_COUNT=$udp_true_count" "MAYING_DNS_PRESENT=$dns_present" \
  "BASE_DNS_SHA256=$base_dns_sha" "CANDIDATE_DNS_SHA256=$candidate_dns_sha" "CANDIDATE_SHA256=$candidate_sha" \
  "MAYING_POLICY_HOST_COUNT=$policy_host_count" "MAYING_POLICY_RESOLVER_SET_SHA256=$policy_resolver_sha" \
  'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
