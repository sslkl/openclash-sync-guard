#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'INSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 6 ] || hold ARGS 11
source_dir=$1
public_key_file=$2
source_host_sha256=$3
key_id=$4
normalization_policy=$5
deployment_id=$6
case "$key_id" in router_a|router_b) ;; *) hold KEY_ID 11;; esac
case "$normalization_policy" in strict-v1|converter-name-authority-v1) ;; *) hold NORMALIZATION_POLICY 11;; esac
case "$deployment_id" in *[!0-9A-Z-]*|'') hold DEPLOYMENT_ID 11;; esac
[ "${#deployment_id}" -ge 8 ] && [ "${#deployment_id}" -le 48 ] || hold DEPLOYMENT_ID 11
case "$source_dir" in /*) ;; *) hold SOURCE_DIR 12;; esac
case "$source_host_sha256" in *[!0-9a-f]*|'') hold SOURCE_ANCHOR 13;; esac
[ "${#source_host_sha256}" -eq 64 ] || hold SOURCE_ANCHOR 13
[ -f "$public_key_file" ] && [ ! -L "$public_key_file" ] || hold PUBLIC_KEY 14
public_key=$(cat "$public_key_file")
case "$public_key" in ssh-ed25519\ *) ;; *) hold PUBLIC_KEY_TYPE 15;; esac
[ "$(printf '%s\n' "$public_key" | wc -l | tr -d ' ')" -eq 1 ] || hold PUBLIC_KEY_LINES 16
command -v ssh-keygen >/dev/null 2>&1 || hold SSH_KEYGEN 16
ssh-keygen -lf "$public_key_file" 2>/dev/null | grep -q ' (ED25519)$' || hold PUBLIC_KEY_FORMAT 16
for file in maying_normalizer.py maying_converter_reconciler.py openclash_worker.py openclash_worker_forced_command.sh; do
  [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ] || hold SOURCE_ASSET 17
done

root=/opt/publisher-v4-openclash-worker
auth=/home/syncsvc/.ssh/authorized_keys
backup=/home/syncsvc/.ssh/sync-backups/publisher-v4-openclash-worker-v1-$key_id-$deployment_id
service_uid=$(id -u syncsvc)
service_gid=$(id -g syncsvc)
[ -f "$auth" ] && [ ! -L "$auth" ] || hold AUTHORIZED_KEYS 18
[ "$(stat -c '%a:%u:%g' "$auth")" = "600:$service_uid:$service_gid" ] || hold AUTHORIZED_KEYS_MODE 18
[ -d /home/syncsvc/.ssh ] && [ ! -L /home/syncsvc/.ssh ] || hold SSH_DIR 18
[ "$(stat -c '%a:%u:%g' /home/syncsvc/.ssh)" = "700:$service_uid:$service_gid" ] || hold SSH_DIR_MODE 18
[ ! -L "$root" ] || hold INSTALL_ROOT_TYPE 20
[ ! -e "$root" ] || { [ -d "$root" ] && [ "$(stat -c '%a:%u:%g' "$root")" = '755:0:0' ]; } || hold INSTALL_ROOT_TYPE 20
[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 21
created_root=false
install -d -m 0700 -o syncsvc -g syncsvc /home/syncsvc/.ssh/sync-backups
[ ! -L /home/syncsvc/.ssh/sync-backups ] && [ "$(stat -c '%a:%u:%g' /home/syncsvc/.ssh/sync-backups)" = "700:$service_uid:$service_gid" ] || hold BACKUP_ROOT_MODE 21
install -d -m 0700 -o syncsvc -g syncsvc "$backup"
install -m 0600 -o syncsvc -g syncsvc "$auth" "$backup/authorized_keys.before"
sha256sum "$backup/authorized_keys.before" >"$backup/SHA256SUMS"
chown syncsvc:syncsvc "$backup/SHA256SUMS"
chmod 0600 "$backup/SHA256SUMS"

committed=false
rollback(){
  set +e
  install -m 0600 -o syncsvc -g syncsvc "$backup/authorized_keys.before" "$auth"
  [ "$created_root" = true ] && rm -rf "$root"
  rm -rf "$backup"
  printf 'INSTALL=ROLLED_BACK\n'
}
finish(){ [ "$committed" = true ] || rollback; }
interrupted(){ exit 128; }
trap finish EXIT
trap interrupted HUP INT TERM

if [ -d "$root" ]; then
  find "$root" -xdev -type l | grep -q . && hold WORKER_SYMLINK 25
  for pair in "maying_normalizer.py:maying_normalizer.py" "maying_converter_reconciler.py:maying_converter_reconciler.py" "openclash_worker.py:openclash_worker.py" "forced-command:openclash_worker_forced_command.sh"; do
    installed=${pair%%:*}; source=${pair#*:}
    [ -f "$root/$installed" ] && [ ! -L "$root/$installed" ] || hold EXISTING_ASSET 25
    [ "$(sha256sum "$root/$installed" | awk '{print $1}')" = "$(sha256sum "$source_dir/$source" | awk '{print $1}')" ] || hold EXISTING_DRIFT 26
  done
  for file in source-host.sha256 normalization-policy; do
    [ -f "$root/$file" ] && [ ! -L "$root/$file" ] || hold EXISTING_ASSET 25
  done
  [ "$(tr -d '\n' <"$root/source-host.sha256")" = "$source_host_sha256" ] || hold EXISTING_ANCHOR_DRIFT 27
  [ "$(tr -d '\n' <"$root/normalization-policy")" = "$normalization_policy" ] || hold EXISTING_POLICY_DRIFT 28
else
  install -d -m 0755 -o root -g root "$root"
  created_root=true
  install -m 0444 -o root -g root "$source_dir/maying_normalizer.py" "$root/maying_normalizer.py"
  install -m 0444 -o root -g root "$source_dir/maying_converter_reconciler.py" "$root/maying_converter_reconciler.py"
  install -m 0444 -o root -g root "$source_dir/openclash_worker.py" "$root/openclash_worker.py"
  install -m 0555 -o root -g root "$source_dir/openclash_worker_forced_command.sh" "$root/forced-command"
  printf '%s\n' "$source_host_sha256" >"$root/source-host.sha256"
  chmod 0444 "$root/source-host.sha256"
  chown root:root "$root/source-host.sha256"
  printf '%s\n' "$normalization_policy" >"$root/normalization-policy"
  chmod 0444 "$root/normalization-policy"
  chown root:root "$root/normalization-policy"
fi

for file in maying_normalizer.py maying_converter_reconciler.py openclash_worker.py source-host.sha256 normalization-policy; do
  [ "$(stat -c '%a:%u:%g' "$root/$file")" = '444:0:0' ] || hold WORKER_FILE_MODE 29
done
[ "$(stat -c '%a:%u:%g' "$root/forced-command")" = '555:0:0' ] || hold FORCED_COMMAND_MODE 29
[ "$(tr -d '\n' <"$root/normalization-policy")" = "$normalization_policy" ] || hold POLICY_BINDING 29
[ "$(wc -l <"$root/normalization-policy" | tr -d ' ')" -eq 1 ] || hold POLICY_BINDING 29
[ "$(tr -d '\n' <"$root/source-host.sha256")" = "$source_host_sha256" ] || hold SOURCE_BINDING 29
[ "$(wc -l <"$root/source-host.sha256" | tr -d ' ')" -eq 1 ] || hold SOURCE_BINDING 29
find "$root" -xdev -type l | grep -q . && hold WORKER_SYMLINK 29

key_fields=$(printf '%s\n' "$public_key" | awk '{print NF}')
[ "$key_fields" -ge 2 ] || hold PUBLIC_KEY_FIELDS 22
key_type=$(printf '%s\n' "$public_key" | awk '{print $1}')
key_data=$(printf '%s\n' "$public_key" | awk '{print $2}')
case "$key_data" in ''|*[!A-Za-z0-9+/=]*) hold PUBLIC_KEY_FORMAT 22;; esac
entry="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc,command=\"$root/forced-command\" $key_type $key_data publisher-v4-openclash-$key_id"
grep -Fq "$key_data" "$auth" && hold KEY_ALREADY_PRESENT 23
printf '%s\n' "$entry" >>"$auth"
chown syncsvc:syncsvc "$auth"
chmod 0600 "$auth"

/usr/bin/python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$root/maying_normalizer.py" "$root/maying_converter_reconciler.py" "$root/openclash_worker.py"
/bin/sh -n "$root/forced-command"
find "$root" -xdev -type d -name __pycache__ | grep -q . && hold PYTHON_CACHE 24
printf 'COMMITTED\n' >"$backup/COMMITTED"
chown syncsvc:syncsvc "$backup/COMMITTED"
chmod 0600 "$backup/COMMITTED"
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'INSTALL=PASS' "KEY_ID=$key_id" "DEPLOYMENT_ID=$deployment_id" "NORMALIZATION_POLICY=$normalization_policy" 'FORCED_COMMAND=true' 'SSH_RESTRICT=true' 'WORKER_ROOT_READ_ONLY=true' 'SOURCE_HOST_HASH_BOUND=true' 'SERVICE_INSTALLED=false'
