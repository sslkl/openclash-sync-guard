#!/bin/sh
set -eu
PATH=/usr/bin:/bin
export PATH
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
user=openclash-admin
realm='OpenClash Sync'
ha1_file=$root/.auth-ha1
[ -f "$ha1_file" ] && [ ! -L "$ha1_file" ] || { printf '%s\n' '未找到当前部署的认证摘要。' >&2; exit 1; }
[ "$(stat -f '%Lp' "$ha1_file")" = 600 ] || { printf '%s\n' '本机认证摘要文件权限必须为 0600。' >&2; exit 1; }
expected=$(sed -n 's/^sha256://p' "$ha1_file")
[ -n "$expected" ] || expected=$(sed -n '1p' "$ha1_file")
case "$expected" in ''|*[!0-9a-f]* ) printf '%s\n' '本机认证摘要格式无效。' >&2; exit 1;; esac
[ "${#expected}" -eq 64 ] || { printf '%s\n' '本机认证摘要格式无效。' >&2; exit 1; }

matches_current(){
  candidate=$1
  actual=$(printf '%s:%s:%s' "$user" "$realm" "$candidate" | shasum -a 256 | awk '{print $1}')
  [ "$actual" = "$expected" ]
}

password=
secret_file=$root/.web-login-secret
if [ -f "$secret_file" ] && [ ! -L "$secret_file" ]; then
  mode=$(stat -f '%Lp' "$secret_file")
  [ "$mode" = 600 ] || { printf '%s\n' '本机 current 登录凭据文件权限必须为 0600。' >&2; exit 1; }
  candidate=$(sed -n '1p' "$secret_file")
  if [ -n "$candidate" ] && matches_current "$candidate"; then password=$candidate; fi
fi
if [ -z "$password" ]; then
  candidate=$(security find-generic-password -a "$user" -s org.example.openclash-sync-web -w 2>/dev/null || true)
  if [ -n "$candidate" ] && matches_current "$candidate"; then password=$candidate; fi
fi
unset candidate actual expected secret_file
[ -n "$password" ] || { printf '%s\n' 'current 密码槽与当前部署摘要不一致；请运行 prepare_web_auth.py --promote-candidate 恢复，拒绝借用 candidate。' >&2; exit 1; }
printf '%s' "$password" | pbcopy
unset password
printf '%s\n' '密码已复制到剪贴板。登录用户名：openclash-admin'
