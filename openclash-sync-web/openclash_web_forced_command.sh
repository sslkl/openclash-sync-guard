#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV CDPATH GLOBIGNORE LUA_PATH LUA_CPATH LUA_INIT RUBYOPT RUBYLIB GEM_HOME GEM_PATH BUNDLE_GEMFILE BUNDLE_PATH LD_PRELOAD LD_LIBRARY_PATH
umask 077
[ "${SSH_ORIGINAL_COMMAND:-}" = openclash-web-router-v1 ] || exit 40
[ "$#" -eq 1 ] || exit 41
case "$1" in router_a|router_b) target=$1;; *) exit 42;; esac
exec /usr/bin/lua /etc/openclash/publisher-v4/web/openclash_web_router_agent.lua "$target"
