#!/bin/sh
set -eu

audit=PASS

printf 'RUBY_URI='
if ruby -ruri -e 'exit URI.respond_to?(:decode_www_form)' >/dev/null 2>&1; then printf 'PASS\n'; else printf 'MISSING\n'; audit=HOLD; fi
printf 'RUBY_JSON='
if ruby -rjson -e 'exit JSON.respond_to?(:generate)' >/dev/null 2>&1; then printf 'PASS\n'; else printf 'MISSING\n'; audit=HOLD; fi
printf 'RUBY_YAML='
if ruby -ryaml -e 'exit YAML.respond_to?(:safe_load)' >/dev/null 2>&1; then printf 'PASS\n'; else printf 'MISSING\n'; audit=HOLD; fi
printf 'RUBY_IPADDR='
if ruby -ripaddr -e 'exit IPAddr.new("192.0.2.1").ipv4?' >/dev/null 2>&1; then printf 'PASS\n'; else printf 'MISSING\n'; audit=HOLD; fi

for command in curl sha256sum flock mktemp readlink; do
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
