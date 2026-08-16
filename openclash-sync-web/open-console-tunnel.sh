#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
printf '%s\n' \
  'OpenClash 中文管理台隧道正在运行。' \
  '请在浏览器打开：http://127.0.0.1:18088' \
  '保持此窗口开启；按 Ctrl+C 关闭隧道。'
exec ssh -N -T \
  -o BatchMode=yes \
  -o ClearAllForwardings=no \
  -o ControlMaster=no \
  -o ControlPath=none \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -L 127.0.0.1:18088:192.0.2.20:8088 \
  sync-worker-host
