#!/bin/sh
set -eu

audit=PASS
root=/etc/openclash/publisher-v4
bin=$root/bin

asset_audit=PASS
for file in openclash_router_stage_builder.rb openclash_router_stage_client.sh router-openclash-sync-capability-audit.sh; do
  path=$bin/$file
  if [ ! -f "$path" ] || [ -L "$path" ] || [ "$(ls -ln "$path" | awk '{print $1 ":" $3 ":" $4}')" != '-r-x------:0:0' ]; then
    asset_audit=HOLD
  fi
done
printf 'PUBLISHER_ASSETS=%s\n' "$asset_audit"
[ "$asset_audit" = PASS ] || audit=HOLD

contract_audit=PASS
for marker in MAYING_DOCUMENT_SHAPE MAYING_DNS_UNEXPECTED MAYING_RULES_UNEXPECTED CONVERTER_UDP_FALSE CONVERTER_UDP_TYPE UDP_COUNT_MISMATCH DNS_OWNERSHIP_DRIFT DNS_POLICY_COLLISION BASE_DNS_SHA256 CANDIDATE_DNS_SHA256 BUILDER_HASH; do
  grep -Fq "$marker" "$bin/openclash_router_stage_client.sh" || contract_audit=HOLD
done
printf 'SYNC_CONTRACT_MARKERS=%s\n' "$contract_audit"
[ "$contract_audit" = PASS ] || audit=HOLD

printf 'RUBY_YAML='
if ruby -ryaml -e 'exit YAML.respond_to?(:safe_load)' >/dev/null 2>&1; then printf 'PASS\n'; else printf 'MISSING\n'; audit=HOLD; fi
printf 'RUBY_DIGEST='
if ruby -rdigest -e 'exit Digest::SHA256.hexdigest("contract").length == 64' >/dev/null 2>&1; then printf 'PASS\n'; else printf 'MISSING\n'; audit=HOLD; fi
printf '%s\n' 'RUBY_DEPENDENCY_SET=YAML_DIGEST_ONLY'

for command in curl sha256sum flock mktemp readlink jsonfilter awk sed cmp; do
  label=$(printf '%s' "$command" | tr 'a-z' 'A-Z')
  printf 'TOOL_%s=' "$label"
  if command -v "$command" >/dev/null 2>&1; then printf 'PRESENT\n'; else printf 'MISSING\n'; audit=HOLD; fi
done

pid=$(pidof clash_meta 2>/dev/null || true)
case "$pid" in
  ''|*' '*) pid=; audit=HOLD ;;
esac
executable=
[ -z "$pid" ] || executable=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
if [ -n "$executable" ] && [ -f "$executable" ] && [ -x "$executable" ]; then
  printf 'CORE_BASENAME=%s\n' "${executable##*/}"
  printf 'CORE_SHA256='
  sha256sum "$executable" | awk '{print $1}'
  printf 'CORE_SIZE='
  ls -ln "$executable" | awk '{print $5}'
else
  printf 'CORE_IDENTITY=HOLD\n'
  audit=HOLD
fi

printf 'ACTIVE_UNCHANGED='
if [ "$(uci -q get openclash.config.config_path)" = /etc/openclash/config/ProviderBase-ProviderSource.yaml ]; then printf 'true\n'; else printf 'false\n'; audit=HOLD; fi
printf 'SERVICE_RUNNING='
if /etc/init.d/openclash running >/dev/null 2>&1; then printf 'true\n'; else printf 'false\n'; audit=HOLD; fi
printf 'CAPABILITY_AUDIT=%s\n' "$audit"
[ "$audit" = PASS ]
