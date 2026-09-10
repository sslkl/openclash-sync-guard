"""Execute extracted POSIX functions with synthetic IO, never router entrypoints."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def function_source(filename, name):
    text = (ROOT / filename).read_text(encoding="utf-8")
    start = text.index(name + "(){")
    end = text.index("\n}", start) + 2
    return text[start:end]


class TransactionRetryTests(unittest.TestCase):
    def shell(self, source):
        with tempfile.TemporaryDirectory(prefix="transaction-retry-") as temp:
            result = subprocess.run(
                ["/bin/sh", "-eu", "-c", source], cwd=temp,
                text=True, capture_output=True, timeout=5, check=False,
                env={"PATH": "/usr/bin:/bin", "HOME": temp, "TMPDIR": temp},
            )
        return result

    def test_connectivity_does_not_overwrite_caller_state(self):
        for filename in ("openclash_custom_transaction.sh", "openclash_custom_rollback_guard.sh"):
            with self.subTest(filename=filename):
                script = function_source(filename, "connectivity") + r'''
nslookup(){ return 1; }
curl(){ return 1; }
sleep(){ :; }
attempt=89
dns_ok=caller_dns
https_ok=caller_https
connectivity && exit 99
printf '%s\n' "$attempt:$dns_ok:$https_ok"
'''
                result = self.shell(script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "89:caller_dns:caller_https")

    def test_connectivity_retries_transient_dns_and_requires_https(self):
        for filename in ("openclash_custom_transaction.sh", "openclash_custom_rollback_guard.sh"):
            for https_success in (True, False):
                with self.subTest(filename=filename, https_success=https_success):
                    script = function_source(filename, "connectivity") + r'''
: > dns.calls
: > https.calls
nslookup(){ printf 'dns\n' >> dns.calls; [ "$(wc -l < dns.calls)" -ge 3 ]; }
curl(){ printf 'https\n' >> https.calls; return HTTPS_RC; }
sleep(){ :; }
rc=0
connectivity || rc=$?
printf '%s:%s:%s\n' "$rc" "$(wc -l < dns.calls | tr -d ' ')" "$(wc -l < https.calls | tr -d ' ')"
'''
                    result = self.shell(script.replace("HTTPS_RC", "0" if https_success else "1"))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "0:3:3" if https_success else "1:3:6")

    def activation_probe(self, connectivity_success):
        # Select only the post-restart loop and its real rollback branch. The
        # service-running command is the sole absolute command and is replaced
        # explicitly; every IO-bearing command below is a shell stub.
        body = function_source("openclash_custom_transaction.sh", "activate")
        loop = body[body.index("  attempt=0\n"):-2]
        self.assertEqual(loop.count("/etc/init.d/openclash running"), 1)
        loop = loop.replace("/etc/init.d/openclash running", "service_running")
        self.assertEqual(loop.count("awk '{print $22}'"), 1)
        loop = loop.replace("awk '{print $22}'", "process_start")
        script = function_source("openclash_custom_transaction.sh", "connectivity") + r'''
main="$PWD/main.yaml"
state="$PWD/state.json"
runtime="$PWD/runtime.yaml"
core_path="$PWD/core"
arm="$PWD/armed"
for file in "$main" "$state" "$runtime" "$core_path" "$arm"; do : > "$file"; done
backup="$PWD"
activation_backup="$PWD"
expected_config_sha=abc
expected_state_sha=abc
expected_core_sha=abc
old_identity=1:10
customizer=synthetic-customizer
target=synthetic-router
guard=restore_guard
guard_pid=999999
sleep_calls=0
activation_verified=false
: > dns.calls
: > https.calls
uci(){ printf '%s\n' "$main"; }
service_running(){ return 0; }
pidof(){ printf '2\n'; }
process_start(){ printf '20\n'; }
readlink(){ printf '%s\n' "$core_path"; }
sha256sum(){ printf 'abc  synthetic\n'; }
ruby(){ return 0; }
run_runtime_verifier(){ return 0; }
nslookup(){ printf 'dns\n' >> dns.calls; return CONNECTIVITY_RC; }
curl(){ printf 'https\n' >> https.calls; return CONNECTIVITY_RC; }
sleep(){
  if [ "$1" = 1 ]; then
    sleep_calls=$((sleep_calls+1))
    [ "$sleep_calls" -le 5 ] || { printf 'RETRY_BUDGET_EXCEEDED\n'; exit 77; }
  fi
}
restore_guard(){ printf 'RESTORE_CALLED\n' > restored; }
kill(){ :; }
wait(){ :; }
hold(){ printf 'HOLD:%s:%s\n' "$1" "$2"; exit "$2"; }
trap '[ ! -f restored ] || cat restored; printf "COUNTS:%s:%s\n" "$(wc -l < dns.calls | tr -d " ")" "$(wc -l < https.calls | tr -d " ")"' 0
probe_activation(){
''' + loop + r'''
}
probe_activation
printf 'VERIFIED:%s\n' "$activation_verified"
'''
        return self.shell(script.replace("CONNECTIVITY_RC", "0" if connectivity_success else "1"))

    def test_persistent_connectivity_failure_exits_to_rollback_after_one_probe_budget(self):
        result = self.activation_probe(False)
        self.assertEqual(result.returncode, 26, result.stdout + result.stderr)
        self.assertIn("RESTORE_CALLED", result.stdout)
        self.assertIn("HOLD:ACTIVATE:26", result.stdout)
        self.assertIn("COUNTS:3:6", result.stdout)
        self.assertNotIn("VERIFIED:true", result.stdout)

    def test_successful_connectivity_accepts_without_rollback(self):
        result = self.activation_probe(True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VERIFIED:true", result.stdout)
        self.assertIn("COUNTS:1:1", result.stdout)
        self.assertNotIn("RESTORE_CALLED", result.stdout)


if __name__ == "__main__":
    unittest.main()
