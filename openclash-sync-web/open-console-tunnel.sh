#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "$#" -eq 2 ] || {
  printf '%s\n' '用法：open-console-tunnel.sh <专用私钥绝对路径> <WORKER 专用 known_hosts 绝对路径>' >&2
  exit 2
}
identity_file=$1
known_hosts_file=$2
current_uid=$(id -u)
trusted_user_file(){
  file=$1
  case "$file" in /*/../*|*/./*|*//*|*/..|*/.) return 1;; /*) ;; *) return 1;; esac
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  [ "$(stat -f '%u:%Lp' "$file" 2>/dev/null)" = "$current_uid:600" ] || return 1
  directory=${file%/*}; [ -n "$directory" ] || directory=/
  while :; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
    owner=$(ls -ldn "$directory" | awk '{print $3}')
    [ "$owner" = 0 ] || [ "$owner" = "$current_uid" ] || return 1
    find "$directory" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q . && return 1
    [ "$directory" = / ] && return 0
    parent=${directory%/*}; [ -n "$parent" ] || parent=/; directory=$parent
  done
}
trusted_user_file "$identity_file" || { printf '%s\n' '私钥必须是当前用户所有、非符号链接、0600 的普通文件。' >&2; exit 3; }
trusted_user_file "$known_hosts_file" || { printf '%s\n' 'known_hosts 必须是当前用户所有、非符号链接、0600 的普通文件。' >&2; exit 4; }
[ "$(wc -l <"$known_hosts_file" | tr -d ' ')" -eq 1 ] || { printf '%s\n' 'known_hosts 必须只包含 WORKER 的一条 Ed25519 记录。' >&2; exit 4; }
awk 'NF == 3 && $1 == "192.0.2.20" && $2 == "ssh-ed25519" && $3 ~ /^[A-Za-z0-9+\/=]+$/ {ok=1} END {exit !ok}' "$known_hosts_file" || {
  printf '%s\n' 'known_hosts 目标、算法或格式不符合 WORKER 专用 pin。' >&2
  exit 4
}
printf '%s\n' \
  'OpenClash 中文管理台隧道正在运行。' \
  '请在浏览器打开：http://127.0.0.1:18088' \
  '保持此窗口开启；按 Ctrl+C 关闭隧道。'
exec ssh -F /dev/null -N -T \
  -o BatchMode=yes \
  -o ClearAllForwardings=no \
  -o CheckHostIP=yes \
  -o ConnectionAttempts=1 \
  -o ConnectTimeout=8 \
  -o ControlMaster=no \
  -o ControlPath=none \
  -o ExitOnForwardFailure=yes \
  -o ForwardAgent=no \
  -o GlobalKnownHostsFile=/dev/null \
  -o GSSAPIAuthentication=no \
  -o HostbasedAuthentication=no \
  -o IdentitiesOnly=yes \
  -o KbdInteractiveAuthentication=no \
  -o NumberOfPasswordPrompts=0 \
  -o PasswordAuthentication=no \
  -o PermitLocalCommand=no \
  -o PreferredAuthentications=publickey \
  -o ProxyCommand=none \
  -o ProxyJump=none \
  -o PubkeyAuthentication=yes \
  -o RequestTTY=no \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=yes \
  -o UpdateHostKeys=no \
  -o UserKnownHostsFile="$known_hosts_file" \
  -i "$identity_file" \
  -L 127.0.0.1:18088:127.0.0.1:8088 \
  syncsvc@192.0.2.20
