#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'INSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 3 ] || hold ARGS 11
target=$1
source_dir=$2
hostkey_file=$3
case "$target" in router_a|router_b) ;; *) hold TARGET 12;; esac
case "$source_dir" in /*) ;; *) hold SOURCE_DIR 13;; esac
[ -f "$hostkey_file" ] && [ ! -L "$hostkey_file" ] || hold HOSTKEY 14
[ "$(wc -l <"$hostkey_file" | tr -d ' ')" -eq 1 ] || hold HOSTKEY_COUNT 15
[ "$(awk 'NR==1 {print $1}' "$hostkey_file")" = 192.0.2.20 ] || hold HOSTKEY_TARGET 16
[ "$(awk 'NR==1 {print $2}' "$hostkey_file")" = ssh-ed25519 ] || hold HOSTKEY_TYPE 16
hostkey_data=$(awk 'NR==1 {print $3}' "$hostkey_file")
case "$hostkey_data" in ''|*[!A-Za-z0-9+/=]*) hold HOSTKEY_FORMAT 16;; esac
for file in openclash_router_stage_builder.rb openclash_router_stage_client.sh router-openclash-sync-capability-audit.sh; do
  [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ] || hold SOURCE_ASSET 18
done
command -v dropbearkey >/dev/null 2>&1 || hold DROPBEARKEY 19
command -v ruby >/dev/null 2>&1 || hold RUBY 20
command -v lua >/dev/null 2>&1 || hold LUA 21
command -v jsonfilter >/dev/null 2>&1 || hold JSONFILTER 22
command -v cmp >/dev/null 2>&1 || hold CMP 22

root=/etc/openclash/publisher-v4
ssh_dir=/root/.ssh
created_ssh=false
[ ! -e "$root" ] && [ ! -L "$root" ] || hold INSTALL_ROOT_EXISTS 23
if [ ! -e "$ssh_dir" ]; then
  mkdir "$ssh_dir"
  chmod 0700 "$ssh_dir"
  created_ssh=true
elif [ ! -d "$ssh_dir" ] || [ -L "$ssh_dir" ]; then
  hold SSH_DIR_TYPE 24
fi
[ ! -e "$ssh_dir/known_hosts" ] || hold KNOWN_HOSTS_EXISTS 25

rollback(){
  set +e
  rm -rf "$root"
  rm -f "$ssh_dir/known_hosts"
  [ "$created_ssh" = true ] && rmdir "$ssh_dir" 2>/dev/null || true
  printf 'INSTALL=ROLLED_BACK\n'
}
committed=false
finish(){ [ "$committed" = true ] || rollback; }
interrupted(){ exit 128; }
trap finish EXIT
trap interrupted HUP INT TERM

mkdir -p "$root/bin" "$root/keys" "$root/stage"
chmod 0700 "$root" "$root/bin" "$root/keys" "$root/stage"
cp "$source_dir/openclash_router_stage_builder.rb" "$root/bin/openclash_router_stage_builder.rb"
cp "$source_dir/openclash_router_stage_client.sh" "$root/bin/openclash_router_stage_client.sh"
cp "$source_dir/router-openclash-sync-capability-audit.sh" "$root/bin/router-openclash-sync-capability-audit.sh"
cp "$hostkey_file" "$ssh_dir/known_hosts"
chmod 0500 "$root/bin/openclash_router_stage_builder.rb" "$root/bin/openclash_router_stage_client.sh" "$root/bin/router-openclash-sync-capability-audit.sh"
chmod 0600 "$ssh_dir/known_hosts"
chmod 0700 "$ssh_dir"

private=$root/keys/sync-worker-ed25519
dropbearkey -t ed25519 -f "$private" >/dev/null 2>&1 || hold KEYGEN 30
chmod 0600 "$private"
dropbearkey -y -f "$private" 2>/dev/null | sed -n 's/^ssh-ed25519 /ssh-ed25519 /p' >"$root/keys/sync-worker-ed25519.pub"
chmod 0644 "$root/keys/sync-worker-ed25519.pub"
[ "$(wc -l <"$root/keys/sync-worker-ed25519.pub" | tr -d ' ')" -eq 1 ] || hold PUBLIC_KEY 31

/bin/sh -n "$root/bin/openclash_router_stage_client.sh" || hold CLIENT_SYNTAX 32
/bin/sh -n "$root/bin/router-openclash-sync-capability-audit.sh" || hold AUDIT_SYNTAX 32
ruby -c "$root/bin/openclash_router_stage_builder.rb" >/dev/null || hold BUILDER_SYNTAX 33
for file in openclash_router_stage_builder.rb openclash_router_stage_client.sh router-openclash-sync-capability-audit.sh; do
  cmp -s "$source_dir/$file" "$root/bin/$file" || hold COPIED_BYTES 33
done
for path in "$root" "$root/bin" "$root/keys" "$root/stage" "$ssh_dir"; do
  [ "$(ls -ldn "$path" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold DIRECTORY_MODE 34
done
printf '%s\n' "TARGET=$target" 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false' >"$root/INSTALL-RECEIPT"
chmod 0600 "$root/INSTALL-RECEIPT"
printf 'COMMITTED\n' >"$root/COMMITTED"
chmod 0600 "$root/COMMITTED"
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'INSTALL=PASS' "TARGET=$target" 'PRIVATE_KEY_CREATED=true' 'PUBLIC_KEY_READY=true' 'ACTIVE_CHANGED=false' 'UCI_CHANGED=false' 'SERVICE_RESTARTED=false'
