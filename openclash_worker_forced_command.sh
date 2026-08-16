#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH
unset ENV BASH_ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME
umask 077

root=/opt/publisher-v4-openclash-worker
anchor=$root/source-host.sha256
policy_file=$root/normalization-policy
[ "${SSH_ORIGINAL_COMMAND:-}" = 'publisher-v4-openclash-worker-v1' ] || {
  printf '%s\n' '{"schema":"publisher-v4-worker-response-v1","decision":"HOLD","reason":"COMMAND","authorization_effect":"NONE"}' >&2
  exit 64
}
[ -f "$anchor" ] && [ ! -L "$anchor" ] || exit 65
anchor_size=$(wc -c <"$anchor" | tr -d ' ')
[ "$anchor_size" -eq 65 ] || exit 65
digest=$(tr -d '\n' <"$anchor")
case "$digest" in *[!0-9a-f]*|'') exit 65;; esac
[ "${#digest}" -eq 64 ] || exit 65
[ -f "$policy_file" ] && [ ! -L "$policy_file" ] || exit 66
[ "$(wc -c <"$policy_file" | tr -d ' ')" -le 64 ] || exit 66
[ "$(wc -l <"$policy_file" | tr -d ' ')" -eq 1 ] || exit 66
policy=$(tr -d '\n' <"$policy_file")
case "$policy" in strict-v1|converter-name-authority-v1) ;; *) exit 66;; esac
exec /usr/bin/python3 -E -s -B "$root/openclash_worker.py" --stream "$digest" "$policy"
