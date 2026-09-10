#!/bin/sh
set -eu

PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}
export PATH
umask 077

hold(){ printf 'MIHOMO_SYNTAX=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$#" -eq 1 ] || hold ARGS 10
mihomo=$1
[ -f "$mihomo" ] && [ -x "$mihomo" ] && [ ! -L "$mihomo" ] || hold MIHOMO 11
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/openclash-mihomo-test.XXXXXX")
cleanup(){
  find "$work" -type f -exec rm -f {} + 2>/dev/null || true
  find "$work" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
ruby "$root/tools/build_synthetic_candidate.rb" >"$work/candidate.yaml"
[ -s "$work/candidate.yaml" ] || hold CANDIDATE 12
"$mihomo" -t -d "$work" -f "$work/candidate.yaml" >/dev/null 2>&1 || hold MIHOMO_TEST 13
printf '%s\n' 'MIHOMO_SYNTAX=PASS' 'FIXTURE=SYNTHETIC' 'LIVE_CHANGES=false'
