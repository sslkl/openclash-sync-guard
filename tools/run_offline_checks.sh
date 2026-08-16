#!/bin/sh
set -eu

PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}
export PATH PYTHONDONTWRITEBYTECODE=1
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

python_bin=${PYTHON:-python3}
command -v "$python_bin" >/dev/null 2>&1 || { printf '%s\n' 'OFFLINE_CHECKS=HOLD' 'REASON=PYTHON'; exit 10; }
command -v ruby >/dev/null 2>&1 || { printf '%s\n' 'OFFLINE_CHECKS=HOLD' 'REASON=RUBY'; exit 11; }
command -v node >/dev/null 2>&1 || { printf '%s\n' 'OFFLINE_CHECKS=HOLD' 'REASON=NODE'; exit 12; }

"$python_bin" -c 'import yaml; assert yaml.__version__ == "6.0.2"'
"$python_bin" test_maying_converter_reconciler.py
"$python_bin" test_openclash_worker.py
"$python_bin" -m unittest discover -v -s tests -p 'test_*.py'
"$python_bin" -m unittest discover -v -s openclash-sync-web/tests -p 'test_*.py'
ruby test_openclash_router_stage_builder.rb
ruby openclash-sync-web/tests/test_openclash_customizer.rb
find . -type f -name '*.sh' -not -path './.git/*' -exec sh -n {} +
node --check openclash-sync-web/static/app.js

printf '%s\n' 'OFFLINE_CHECKS=PASS' 'LIVE_CHANGES=false'
