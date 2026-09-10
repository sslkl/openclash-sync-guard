#!/bin/sh
# Required regressions are local/fixture-only. Real parser integrations are opt-in.
set -eu

PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}
export PATH PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONOPTIMIZE=0
stage=SETUP
outcome=FAIL
skipped=0
finish() {
  code=$?
  if [ "$code" -ne 0 ]; then
    printf 'OFFLINE_CHECKS=%s\nFAILED_CHECK=%s\nEXIT_CODE=%s\n' "$outcome" "$stage" "$code"
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
run_unittests() {
  stage=$1
  shift
  printf 'CHECK=%s\n' "$stage"
  if "$python_bin" - "$stage" "$@" <<'PYTEST'
import os
from pathlib import Path
import sys
import unittest

label, mode, *targets = sys.argv[1:]


def test_ids(node):
    if isinstance(node, unittest.TestSuite):
        for child in node:
            yield from test_ids(child)
    else:
        yield node.id()


def main():
    loader = unittest.TestLoader()
    if mode == "discover":
        directory = str(Path(targets[0]).resolve())
        suite = loader.discover(directory, pattern="test_*.py", top_level_dir=directory)
    else:
        suite = loader.loadTestsFromNames(targets)
    expected = suite.countTestCases()
    if not expected:
        print(f"{label}_ERROR=NO_TESTS_DISCOVERED", flush=True)
        return 1
    ids = set(test_ids(suite))
    if label == "PYTHON_WEB_TESTS":
        for prefix in ("test_chain_mihomo.", "test_converter_mellow.MellowOfficialParserTests."):
            if not any(test_id.startswith(prefix) for test_id in ids):
                print(f"{label}_ERROR=INTEGRATION_TESTS_NOT_DISCOVERED", flush=True)
                return 1
    print(f"{label}_DISCOVERED={expected}", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"{label}_RUN={result.testsRun}", flush=True)
    print(f"{label}_SKIPPED={len(result.skipped)}", flush=True)
    if result.testsRun != expected:
        print(f"{label}_ERROR=TEST_EXECUTION_COUNT_MISMATCH", flush=True)
        return 1
    # Missing required runtime/features must fail; only unconfigured external
    # parsers may skip. A configured but broken parser is never a silent SKIP.
    optional = ("OPENCLASH_TEST_MIHOMO", "OPENCLASH_TEST_MELLOW_PARSER")
    unexpected = [test.id() for test, reason in result.skipped
                  if not any(key in reason and not os.environ.get(key) for key in optional)]
    if unexpected:
        print(f"{label}_ERROR=UNEXPECTED_SKIPS", flush=True)
        for test_id in unexpected:
            print(f"UNEXPECTED_SKIP={test_id}", flush=True)
    if not result.wasSuccessful() or unexpected:
        return 1
    if label == "PYTHON_WEB_TESTS":
        for name, key in zip(("MIHOMO", "MELLOW"), optional):
            print(f"{name}_INTEGRATION={'PASS' if os.environ.get(key) else 'SKIP'}", flush=True)
    return 77 if result.skipped else 0


try:
    exit_code = main()
except SystemExit:
    # An import-time exit(0) must not impersonate a successful test run.
    print(f"{label}_ERROR=UNEXPECTED_SYSTEM_EXIT", flush=True)
    exit_code = 1
sys.exit(exit_code)
PYTEST
  then
    printf '%s=PASS\n' "$stage"
  else
    code=$?
    if [ "$code" -eq 77 ]; then
      skipped=1
      printf '%s=PASS_WITH_SKIPS\n' "$stage"
    else
      printf '%s=FAIL\n' "$stage"
      exit "$code"
    fi
  fi
}

[ "$#" -eq 0 ] || hold UNEXPECTED_ARGUMENTS 2

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
web=$root/openclash-sync-web
python_bin=${PYTHON:-python3}
command -v "$python_bin" >/dev/null 2>&1 || hold PYTHON_MISSING 10
"$python_bin" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || hold PYTHON_3_11_REQUIRED 11
[ -f "$root/vendor/pyyaml-6.0.2/yaml/__init__.py" ] || hold VENDORED_PYYAML_MISSING 12
PYTHONPATH=$root/vendor/pyyaml-6.0.2${PYTHONPATH:+:$PYTHONPATH}
export PYTHONPATH
run_check PYYAML_VERSION "$python_bin" -c 'import yaml; assert yaml.__version__ == "6.0.2", "PyYAML 6.0.2 required"'

stage=RUNTIME_PREFLIGHT
ruby_bin=${RUBY:-ruby}
node_bin=${OPENCLASH_TEST_NODE:-${NODE:-node}}
lua_bin=${OPENCLASH_TEST_LUA:-${LUA:-}}
ruby_bin=$(command -v "$ruby_bin") || hold RUBY_MISSING 13
node_bin=$(command -v "$node_bin") || hold NODE_MISSING 14
if [ -z "$lua_bin" ]; then
  lua_bin=$(command -v lua5.1 || command -v lua || true)
fi
[ -n "$lua_bin" ] && command -v "$lua_bin" >/dev/null 2>&1 || hold LUA_5_1_MISSING 15
lua_bin=$(command -v "$lua_bin")
run_check LUA_VERSION "$lua_bin" -e 'assert(_VERSION == "Lua 5.1", "Lua 5.1 required by router harnesses")'
OPENCLASH_TEST_NODE=$node_bin
OPENCLASH_TEST_LUA=$lua_bin
# Some official-parser fixtures use the node command directly.
PATH=$(dirname -- "$node_bin"):$(dirname -- "$ruby_bin"):$PATH
export PATH OPENCLASH_TEST_NODE OPENCLASH_TEST_LUA

stage=EXTERNAL_PARSER_PREFLIGHT
if [ -n "${OPENCLASH_TEST_MIHOMO:-}" ]; then
  case "$OPENCLASH_TEST_MIHOMO" in /*) ;; *) hold MIHOMO_REQUIRES_ABSOLUTE_PATH 16 ;; esac
  [ -f "$OPENCLASH_TEST_MIHOMO" ] && [ -x "$OPENCLASH_TEST_MIHOMO" ] || hold MIHOMO_INVALID 16
else
  skipped=1
  printf '%s\n' 'MIHOMO_INTEGRATION=SKIP' 'MIHOMO_INTEGRATION_REASON=NOT_CONFIGURED'
fi
if [ -n "${OPENCLASH_TEST_MELLOW_PARSER:-}" ]; then
  case "$OPENCLASH_TEST_MELLOW_PARSER" in /*) ;; *) hold MELLOW_REQUIRES_ABSOLUTE_PATH 17 ;; esac
  [ -f "$OPENCLASH_TEST_MELLOW_PARSER" ] && [ -r "$OPENCLASH_TEST_MELLOW_PARSER" ] || hold MELLOW_INVALID 17
  command -v node >/dev/null 2>&1 || hold MELLOW_NODE_NOT_ON_PATH 17
else
  skipped=1
  printf '%s\n' 'MELLOW_INTEGRATION=SKIP' 'MELLOW_INTEGRATION_REASON=NOT_CONFIGURED'
fi

stage=REQUIRED_TEST_FILES
for test_file in \
  "$web/tests/test_openclash_customizer.rb" "$web/tests/test_chain_customizer.rb" \
  "$web/tests/test_router_agent_lua.lua" "$web/tests/test_router_agent_capture.lua" \
  "$web/tests/test_router_agent_lua.py" "$web/tests/test_chain_mihomo.py" \
  "$web/tests/test_converter_mellow.py"; do
  if [ ! -f "$test_file" ] || [ -L "$test_file" ]; then
    printf 'FAILED_FILE=%s\n' "${test_file#"$root"/}"
    hold REQUIRED_TEST_FILE_MISSING 18
  fi
done

run_check SOURCE_SYNTAX "$python_bin" - "$ruby_bin" "$node_bin" "$lua_bin" <<'PYSYNTAX'
import os
from pathlib import Path
import subprocess
import sys

ruby, node, lua = sys.argv[1:]
root = Path.cwd()
# Inspect source only, not a developer's environments, build output or secrets.
excluded = {".git", ".venv", "venv", "__pycache__", "vendor", "node_modules",
            ".audit-tools", "build", "dist", "secrets", "deploy"}
files = list(root.glob("*.*"))
for name in ("tools", "tests", "openclash-sync-web"):
    for directory, dirs, names in os.walk(root / name, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not d.startswith("."))
        files.extend(Path(directory) / name for name in sorted(names))
for language, extension in (("PYTHON", ".py"), ("RUBY", ".rb"), ("LUA", ".lua"),
                            ("SHELL", ".sh"), ("JAVASCRIPT", ".js")):
    sources = sorted({path for path in files if path.suffix == extension})
    if not sources:
        print(f"{language}_SYNTAX=FAIL\nREASON=NO_SOURCE_FILES", flush=True)
        sys.exit(1)
    for path in sources:
        relative = path.relative_to(root)
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("source must be a regular, non-symlink file")
            if language == "PYTHON":
                compile(path.read_bytes(), str(relative), "exec")
                continue
            if language == "RUBY":
                command = [ruby, "-c", str(path)]
            elif language == "LUA":
                # No positional script argument: loadfile compiles but never runs it.
                command = [lua, "-e", "assert(loadfile(os.getenv('OPENCLASH_SYNTAX_FILE')))"]
            elif language == "SHELL":
                shebang = path.read_bytes().split(b"\n", 1)[0]
                command = ["bash" if b"bash" in shebang else "sh", "-n", str(path)]
            else:
                command = [node, "--check", str(path)]
            subprocess.run(command, check=True,
                           env={**os.environ, "OPENCLASH_SYNTAX_FILE": str(path)})
        except (OSError, SyntaxError, ValueError, subprocess.CalledProcessError) as error:
            print(f"{language}_SYNTAX=FAIL\nFAILED_SYNTAX_FILE={relative}", flush=True)
            print(str(error), file=sys.stderr)
            code = getattr(error, "returncode", 1)
            sys.exit(code if code > 0 else 128 - code)
    print(f"{language}_SYNTAX=PASS\n{language}_SYNTAX_FILES={len(sources)}", flush=True)
PYSYNTAX

# These legacy scripts own their test loop and exit status; importing them as
# unittest modules would let the first SystemExit(0) skip the second script.
run_check PYTHON_RECONCILER_TESTS "$python_bin" test_maying_converter_reconciler.py
run_check PYTHON_WORKER_TESTS "$python_bin" test_openclash_worker.py
run_unittests PYTHON_PUBLIC_TESTS discover tests
run_unittests PYTHON_WEB_TESTS discover "$web/tests"
run_check RUBY_WORKER_TESTS "$ruby_bin" test_openclash_router_stage_builder.rb
run_check RUBY_CUSTOMIZER_TESTS "$ruby_bin" "$web/tests/test_openclash_customizer.rb"
run_check RUBY_CHAIN_TESTS "$ruby_bin" "$web/tests/test_chain_customizer.rb"
run_check LUA_AGENT_BEHAVIOR "$lua_bin" "$web/tests/test_router_agent_lua.lua" "$web/openclash_web_router_agent.lua"
run_check LUA_CAPTURE_STATUS "$lua_bin" "$web/tests/test_router_agent_capture.lua" "$web/openclash_web_router_agent.lua"

# Real router/runtime-shape inputs and standalone native-parser probes are not
# read or executed here. They need a separate, explicitly configured validation.
printf '%s\n' 'REAL_RUNTIME_SHAPE=NOT_RUN' 'NATIVE_PARSER_PROBES=NOT_RUN' 'REQUIRED_OFFLINE_CHECKS=PASS'
if [ "$skipped" -eq 0 ]; then
  printf '%s\n' 'OFFLINE_CHECKS=PASS'
else
  printf '%s\n' 'OFFLINE_CHECKS=PASS_WITH_SKIPS'
fi
