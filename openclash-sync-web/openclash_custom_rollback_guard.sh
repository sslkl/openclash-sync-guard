#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
# 无论由后台 guard 还是事务内显式恢复调用，都不得把事务锁传给
# OpenClash 或等待子进程。事务本体仍单独持有 fd 9。
exec 9>&- 2>/dev/null || true
[ "$#" -eq 4 ] || exit 10
target=$1
backup=$2
arm=$3
mode=$4
case "$target" in router_a|router_b) ;; *) exit 11;; esac
backup_root=/etc/openclash/publisher-v4/web-backups
backup_name=${backup##*/}
[ "$backup" = "$backup_root/$backup_name" ] || exit 12
case "$backup_name" in ''|*[!A-Za-z0-9_-]*) exit 12;; esac
[ -d "$backup" ] && [ ! -L "$backup" ] || exit 12
arm_root=/etc/openclash/publisher-v4/web-state
arm_name=${arm##*/}
[ "$arm" = "$arm_root/$arm_name" ] || exit 13
case "$arm_name" in guard.*.armed) ;; *) exit 13;; esac
arm_pid=${arm_name#guard.}; arm_pid=${arm_pid%.armed}
case "$arm_pid" in ''|*[!0-9]*) exit 13;; esac
case "$mode" in wait-runtime|wait-static|restore-runtime|restore-static) ;; *) exit 14;; esac
[ -f "$backup/main.yaml" ] && [ ! -L "$backup/main.yaml" ] || exit 15
[ -f "$arm" ] && [ ! -L "$arm" ] || exit 0
[ "$(cat "$arm" 2>/dev/null)" = "$backup" ] || exit 13
case "$mode" in
  wait-*)
    remaining=240
    while [ "$remaining" -gt 0 ]; do
      sleep 1
      remaining=$((remaining-1))
    done
    ;;
esac
[ -f "$arm" ] || exit 0
main=/etc/openclash/config/ProviderBase-ProviderSource.yaml
state=/etc/openclash/publisher-v4/web-state/customizations.state
[ -f "$main" ] && [ ! -L "$main" ] || exit 16
case "$mode" in wait-*) waiting=true;; *) waiting=false;; esac
if [ "$waiting" = true ] && [ -f "$backup/COMMITTED" ] && [ ! -L "$backup/COMMITTED" ]; then
  expected_config=$(sed -n 's/^CONFIG_SHA256=//p' "$backup/COMMITTED")
  expected_state=$(sed -n 's/^STATE_SHA256=//p' "$backup/COMMITTED")
  case "$expected_config:$expected_state" in
    *[!0-9a-f:]*|:*|*:) ;;
    *)
      if [ "${#expected_config}" -eq 64 ] && [ "${#expected_state}" -eq 64 ] && [ -f "$state" ] && [ ! -L "$state" ] &&
         [ "$(sha256sum "$main" | awk '{print $1}')" = "$expected_config" ] &&
         [ "$(sha256sum "$state" | awk '{print $1}')" = "$expected_state" ]; then
        rm -f "$arm"
        exit 0
      fi
      ;;
  esac
fi
cp -p "$backup/main.yaml" "$main"
chmod 0600 "$main"
if [ -f "$backup/customizations.state" ]; then
  cp -p "$backup/customizations.state" "$state"
  chmod 0600 "$state"
else
  rm -f "$state"
fi
case "$mode" in *-runtime) /etc/init.d/openclash restart >/dev/null 2>&1 || true;; esac
rm -f "$arm"
