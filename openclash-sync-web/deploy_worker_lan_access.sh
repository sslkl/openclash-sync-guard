#!/bin/sh
# Disabled legacy LAN-only migrator. It cannot install the full current release.
# Use the documented guarded updater with matching app, helper, service and runtime.
set -eu
printf '%s\n' 'HOLD=LEGACY_LAN_MIGRATOR_DISABLED' \
  'USE=update_worker_web_console.sh' 'LIVE_CHANGES=false' >&2
exit 64
