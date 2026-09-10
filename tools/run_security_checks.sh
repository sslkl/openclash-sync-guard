#!/bin/sh
# Static checks never install tools. Network advisory lookup requires opt-in.
set -eu

PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}
export PATH PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
stage=SETUP
outcome=FAIL
finish() {
  code=$?
  if [ "$code" -ne 0 ]; then
    printf 'SECURITY_CHECKS=%s\nFAILED_CHECK=%s\nEXIT_CODE=%s\n' "$outcome" "$stage" "$code"
  fi
  printf '%s\n' 'LIVE_CHANGES=false'
}
trap finish 0
trap 'exit 130' INT
trap 'exit 143' TERM
hold() { outcome=HOLD; printf 'REASON=%s\n' "$1"; exit "${2:-10}"; }
run_check() {
  stage=$1
  shift
  printf 'CHECK=%s\n' "$stage"
  if "$@"; then
    printf '%s=PASS\n' "$stage"
  else
    code=$?
    printf '%s=FAIL\n' "$stage"
    exit "$code"
  fi
}

[ "$#" -eq 0 ] || hold UNEXPECTED_ARGUMENTS 2

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python_bin=${PYTHON:-python3}
command -v "$python_bin" >/dev/null 2>&1 || hold PYTHON_MISSING 10
"$python_bin" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || hold PYTHON_3_11_REQUIRED 11
[ -f "$root/vendor/pyyaml-6.0.2/yaml/__init__.py" ] || hold VENDORED_PYYAML_MISSING 12
PYTHONPATH=$root/vendor/pyyaml-6.0.2${PYTHONPATH:+:$PYTHONPATH}
export PYTHONPATH

stage=TOOL_PREFLIGHT
ruff_bin=${RUFF:-ruff}
bandit_bin=${BANDIT:-bandit}
shellcheck_bin=${SHELLCHECK:-shellcheck}
for tool in "$ruff_bin" "$bandit_bin" "$shellcheck_bin"; do
  command -v "$tool" >/dev/null 2>&1 || hold "MISSING_${tool##*/}" 13
done
case "${RUN_DEPENDENCY_AUDIT:-0}" in
  0|1) ;;
  *) hold RUN_DEPENDENCY_AUDIT_MUST_BE_0_OR_1 14 ;;
esac
if [ "${RUN_DEPENDENCY_AUDIT:-0}" -eq 1 ]; then
  "$python_bin" -c 'import importlib.util, sys; sys.exit(0 if importlib.util.find_spec("pip_audit") else 1)' || hold PIP_AUDIT_MISSING 15
fi

# Stable correctness gate; broad style suggestions are reviewed separately.
run_check RUFF_CORRECTNESS "$ruff_bin" check --isolated --no-cache --select E9,F,B023,PLW1510 \
  maying_normalizer.py maying_converter_reconciler.py openclash_worker.py \
  test_maying_converter_reconciler.py test_openclash_worker.py tools tests openclash-sync-web
run_check BANDIT_POLICY "$python_bin" tools/bandit_policy.py --bandit "$bandit_bin"
run_check SHELLCHECK "$python_bin" - "$shellcheck_bin" <<'PYSHELLCHECK'
import os
from pathlib import Path
import subprocess
import sys

root = Path.cwd()
files = list(root.glob("*.sh"))
excluded = {".git", ".venv", "venv", "__pycache__", "vendor", "node_modules",
            ".audit-tools", "build", "dist", "secrets", "deploy"}
for name in ("tools", "tests", "openclash-sync-web"):
    for directory, dirs, names in os.walk(root / name, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not d.startswith("."))
        files.extend(Path(directory) / name for name in sorted(names) if name.endswith(".sh"))
if not files:
    print("SHELLCHECK_ERROR=NO_SOURCE_FILES", flush=True)
    sys.exit(1)
for path in sorted(set(files)):
    if path.is_symlink() or not path.is_file():
        print(f"SHELLCHECK_ERROR=NON_REGULAR_SOURCE\nFAILED_FILE={path.relative_to(root)}", flush=True)
        sys.exit(1)
    result = subprocess.run([sys.argv[1], "-S", "warning", str(path)], check=False)
    if result.returncode:
        print(f"FAILED_SHELLCHECK_FILE={path.relative_to(root)}", flush=True)
        sys.exit(result.returncode if result.returncode > 0 else 128 - result.returncode)
print(f"SHELLCHECK_FILES={len(set(files))}", flush=True)
PYSHELLCHECK

printf '%s\n' 'STATIC_SECURITY_CHECKS=PASS'
if [ "${RUN_DEPENDENCY_AUDIT:-0}" -eq 1 ]; then
  # Queries public advisory metadata only; never resolves or installs packages.
  run_check DEPENDENCY_AUDIT "$python_bin" -m pip_audit --no-deps --disable-pip \
    -r openclash-sync-web/requirements.txt
  printf '%s\n' 'SECURITY_CHECKS=PASS'
else
  printf '%s\n' 'DEPENDENCY_AUDIT=SKIP' 'DEPENDENCY_AUDIT_REASON=NETWORK_AUDIT_NOT_REQUESTED' \
    'SECURITY_CHECKS=PASS_WITH_SKIPS'
fi
