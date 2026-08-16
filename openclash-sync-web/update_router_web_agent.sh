#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
hold(){ printf 'ROUTER_WEB_UPDATE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
case "$1" in router_a|router_b) target=$1;; *) hold TARGET 12;; esac
root=/etc/openclash/publisher-v4/web
backup=/etc/openclash/publisher-v4/web-update-backup-$(date -u +%Y%m%dT%H%M%SZ)-$$
[ -d "$root" ] && [ ! -L "$root" ] || hold INSTALLED_ROOT 13
[ "$(ls -ldn "$root" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold INSTALLED_ROOT_MODE 13
mkdir "$backup"
chmod 0700 "$backup"
[ "$(ls -ldn "$backup" | awk '{print $1 ":" $3 ":" $4}')" = 'drwx------:0:0' ] || hold BACKUP_MODE 13
rollback(){
  for file in "$backup"/*; do
    name=${file##*/}
    case "$name" in
      *.absent) rm -f "$root/${name%.absent}";;
      *) cp -p "$file" "$root/$name" 2>/dev/null || true;;
    esac
  done
  rm -f "$root"/.openclash-sync-web-new.*
  rm -f /tmp/openclash-sync-web-agent.lua /tmp/openclash-sync-web-forced-command.sh /tmp/openclash-sync-web-customizer.rb /tmp/openclash-sync-web-custom-transaction.sh /tmp/openclash-sync-web-custom-rollback-guard.sh
}
trap rollback EXIT HUP INT TERM
[ -f "$root/openclash_web_router_agent.lua" ] && [ ! -L "$root/openclash_web_router_agent.lua" ] || hold INSTALLED_ASSET 13
for pair in 'openclash_web_router_agent.lua:/tmp/openclash-sync-web-agent.lua' 'openclash_web_forced_command.sh:/tmp/openclash-sync-web-forced-command.sh' 'openclash_customizer.rb:/tmp/openclash-sync-web-customizer.rb' 'openclash_custom_transaction.sh:/tmp/openclash-sync-web-custom-transaction.sh' 'openclash_custom_rollback_guard.sh:/tmp/openclash-sync-web-custom-rollback-guard.sh'; do
  name=${pair%%:*}; source=${pair#*:}
  [ -f "$source" ] && [ ! -L "$source" ] || hold SOURCE_ASSET 14
  if [ -e "$root/$name" ]; then
    [ -f "$root/$name" ] && [ ! -L "$root/$name" ] || hold INSTALLED_ASSET 13
    [ "$(ls -ln "$root/$name" | awk '{print $1 ":" $3 ":" $4}')" = '-r-x------:0:0' ] || hold INSTALLED_ASSET_MODE 13
    cp -p "$root/$name" "$backup/$name"
  else
    : >"$backup/$name.absent"
  fi
done
lua -e 'assert(loadfile("/tmp/openclash-sync-web-agent.lua"))' || hold LUA_SYNTAX 15
/bin/sh -n /tmp/openclash-sync-web-forced-command.sh || hold FORCED_COMMAND_SYNTAX 16
ruby -c /tmp/openclash-sync-web-customizer.rb >/dev/null || hold RUBY_SYNTAX 16
/bin/sh -n /tmp/openclash-sync-web-custom-transaction.sh || hold SHELL_SYNTAX 17
/bin/sh -n /tmp/openclash-sync-web-custom-rollback-guard.sh || hold GUARD_SYNTAX 17
deploy_file(){
  source_file=$1
  destination=$2
  temporary=$root/.openclash-sync-web-new.$$
  rm -f "$temporary"
  cp "$source_file" "$temporary"
  chown 0:0 "$temporary"
  chmod 0500 "$temporary"
  mv "$temporary" "$destination"
}
deploy_file /tmp/openclash-sync-web-agent.lua "$root/openclash_web_router_agent.lua"
deploy_file /tmp/openclash-sync-web-forced-command.sh "$root/openclash_web_forced_command.sh"
deploy_file /tmp/openclash-sync-web-customizer.rb "$root/openclash_customizer.rb"
deploy_file /tmp/openclash-sync-web-custom-transaction.sh "$root/openclash_custom_transaction.sh"
deploy_file /tmp/openclash-sync-web-custom-rollback-guard.sh "$root/openclash_custom_rollback_guard.sh"
for pair in 'openclash_web_router_agent.lua:/tmp/openclash-sync-web-agent.lua' 'openclash_web_forced_command.sh:/tmp/openclash-sync-web-forced-command.sh' 'openclash_customizer.rb:/tmp/openclash-sync-web-customizer.rb' 'openclash_custom_transaction.sh:/tmp/openclash-sync-web-custom-transaction.sh' 'openclash_custom_rollback_guard.sh:/tmp/openclash-sync-web-custom-rollback-guard.sh'; do
  name=${pair%%:*}; source=${pair#*:}
  cmp -s "$source" "$root/$name" || hold INSTALLED_HASH 19
done
ruby "$root/openclash_customizer.rb" inspect /etc/openclash/config/ProviderBase-ProviderSource.yaml /etc/openclash/publisher-v4/web-state/customizations.state >/dev/null 2>&1 || hold INSPECT 18
/bin/sh -n "$root/openclash_web_forced_command.sh" || hold FORCED_COMMAND_INSTALLED 19
trap - EXIT HUP INT TERM
rm -f /tmp/openclash-sync-web-agent.lua /tmp/openclash-sync-web-forced-command.sh /tmp/openclash-sync-web-customizer.rb /tmp/openclash-sync-web-custom-transaction.sh /tmp/openclash-sync-web-custom-rollback-guard.sh
printf '%s\n' 'ROUTER_WEB_UPDATE=PASS' "TARGET=$target" "BACKUP=$backup" 'CONFIG_CHANGED=false' 'SERVICE_RESTARTED=false'
