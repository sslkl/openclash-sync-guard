"""Ownership membership stays linear without weakening order or error contracts."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION = "OPENCLASH_SYNC_CUSTOM_V1"
PROGRAM = r"""
input = JSON.parse(STDIN.read)
large_includes = 0
trace = TracePoint.new(:c_call) do |event|
  if event.method_id == :include? && event.self.is_a?(Array) && event.self.length >= input.fetch("trace_min", 128)
    large_includes += 1
  end
end
begin
  trace.enable if input["trace"]
  result = case input.fetch("operation")
  when "parse"
    OpenClashCustomizer.parse_state(input.fetch("state"), request: input.fetch("request", false)).to_h
  when "ownership"
    OpenClashCustomizer.verify_ownership(YAML.dump(input.fetch("config")), input.fetch("state"))
  when "verify"
    OpenClashCustomizer.verify(YAML.dump(input.fetch("config")), input.fetch("state"))
  when "runtime"
    OpenClashCustomizer.verify_runtime(YAML.dump(input.fetch("config")), YAML.dump(input.fetch("runtime")), input.fetch("state"))
  when "render"
    rendered = OpenClashCustomizer.render(YAML.dump(input.fetch("config")), input.fetch("state"), input.fetch("desired"))
    {config: YAML.safe_load(rendered.config, permitted_classes: [Symbol], aliases: false), state: rendered.state}
  else
    raise "TEST_OPERATION"
  end
  output = {ok: true, result: result}
rescue StandardError => error
  output = {ok: false, error: error.message}
ensure
  trace.disable
end
puts JSON.generate(output.merge(large_includes: large_includes))
"""


def state(*lines):
    return "\n".join((VERSION, *lines)) + "\n"


def config(rules=None, filters=None):
    return {"proxies": [], "proxy-groups": [], "rules": rules or ["MATCH,DIRECT"],
            "dns": {"fake-ip-filter": filters or []}}


class CustomizerMembershipTests(unittest.TestCase):
    def invoke(self, operation, **payload):
        completed = subprocess.run(
            ["/usr/bin/ruby", "-r", str(ROOT / "openclash_customizer.rb"), "-rjson", "-e", PROGRAM],
            input=json.dumps({"operation": operation, **payload}, ensure_ascii=False),
            text=True, capture_output=True, timeout=20, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_membership_preserves_normalized_unicode_policies_and_original_order(self):
        value = state("RULE\tDOMAIN\tB.TEST.\t香港🙂", "RULE\tDOMAIN\ta.test\tDIRECT",
                      "FAKE\t+.B.TEST.", "FAKE\t*.a.test", "SUPPLEMENT_RULE\tDOMAIN,c.test,香港🙂",
                      "SUPPLEMENT_FAKE\tgeosite:中文", "OWNED_RULE\tDOMAIN\ta.test\tDIRECT",
                      "OWNED_RULE\tDOMAIN\tb.test\t香港🙂", "OWNED_FAKE\t*.a.test",
                      "OWNED_SUPPLEMENT_RULE\tDOMAIN,c.test,香港🙂", "OWNED_SUPPLEMENT_FAKE\tgeosite:中文")
        result = self.invoke("parse", state=value)
        self.assertTrue(result["ok"], result)
        model = result["result"]
        self.assertEqual(model["rules"], [["DOMAIN", "b.test", "香港🙂"], ["DOMAIN", "a.test", "DIRECT"]])
        self.assertEqual(model["owned_rules"], list(reversed(model["rules"])))
        self.assertEqual(model["filters"], ["+.b.test", "*.a.test"])
        self.assertEqual(model["supplemental_filters"], ["geosite:中文"])

    def test_owned_scope_errors_remain_distinct_and_exact(self):
        for desired, owned, error in (
            ("RULE\tDOMAIN\ta.test\tDIRECT", "OWNED_RULE\tDOMAIN\ta.test\t香港🙂", "OWNED_RULE_SCOPE"),
            ("FAKE\ta.test", "OWNED_FAKE\tb.test", "OWNED_FILTER_SCOPE"),
            ("SUPPLEMENT_RULE\tDOMAIN,a.test,DIRECT", "OWNED_SUPPLEMENT_RULE\tDOMAIN,a.test,DIRECT,no-resolve", "OWNED_SUPPLEMENT_RULE_SCOPE"),
            ("SUPPLEMENT_FAKE\tgeosite:cn", "OWNED_SUPPLEMENT_FAKE\tgeosite:CN", "OWNED_SUPPLEMENT_FILTER_SCOPE"),
        ):
            with self.subTest(error=error):
                result = self.invoke("parse", state=state(desired, owned))
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error"], error)

    def test_duplicate_checks_precede_scope_checks(self):
        for tag, item, error in (
            ("RULE", "DOMAIN\ta.test\tDIRECT", "RULE_DUPLICATE"),
            ("FAKE", "a.test", "FILTER_DUPLICATE"),
            ("OWNED_RULE", "DOMAIN\ta.test\tDIRECT", "OWNED_RULE_DUPLICATE"),
            ("OWNED_FAKE", "a.test", "OWNED_FILTER_DUPLICATE"),
            ("SUPPLEMENT_RULE", "DOMAIN,a.test,DIRECT", "SUPPLEMENT_RULE_DUPLICATE"),
            ("SUPPLEMENT_FAKE", "geosite:cn", "SUPPLEMENT_FILTER_DUPLICATE"),
            ("OWNED_SUPPLEMENT_RULE", "DOMAIN,a.test,DIRECT", "OWNED_SUPPLEMENT_RULE_DUPLICATE"),
            ("OWNED_SUPPLEMENT_FAKE", "geosite:cn", "OWNED_SUPPLEMENT_FILTER_DUPLICATE"),
        ):
            with self.subTest(tag=tag):
                result = self.invoke("parse", state=state(f"{tag}\t{item}", f"{tag}\t{item}"))
                self.assertEqual(result.get("error"), error, result)

    def test_scope_error_priority_and_request_ownership_rejection_are_unchanged(self):
        value = state("OWNED_RULE\tDOMAIN\ta.test\tDIRECT", "OWNED_FAKE\tb.test",
                      "OWNED_SUPPLEMENT_FAKE\tgeosite:cn")
        self.assertEqual(self.invoke("parse", state=value)["error"], "OWNED_RULE_SCOPE")
        self.assertEqual(self.invoke("parse", state=value, request=True)["error"], "REQUEST_OWNERSHIP")

    def test_verify_does_not_relax_owned_rule_prefix_order(self):
        value = state("RULE\tDOMAIN\ta.test\tDIRECT", "RULE\tDOMAIN\tb.test\tDIRECT",
                      "OWNED_RULE\tDOMAIN\ta.test\tDIRECT", "OWNED_RULE\tDOMAIN\tb.test\tDIRECT")
        original = config(["DOMAIN,a.test,DIRECT", "DOMAIN,b.test,DIRECT", "MATCH,DIRECT"])
        self.assertTrue(self.invoke("verify", state=value, config=original)["ok"])
        original["rules"][0:2] = reversed(original["rules"][0:2])
        self.assertEqual(self.invoke("verify", state=value, config=original)["error"], "VERIFY_OWNED_RULE")

    def test_verify_missing_members_keep_the_original_error_labels(self):
        cases = (("RULE\tDOMAIN\ta.test\tDIRECT", "VERIFY_RULE"),
                 ("FAKE\ta.test", "VERIFY_FILTER"),
                 ("SUPPLEMENT_RULE\tDOMAIN,a.test,DIRECT", "VERIFY_SUPPLEMENT_RULE"),
                 ("SUPPLEMENT_FAKE\tgeosite:cn", "VERIFY_SUPPLEMENT_FILTER"))
        for line, error in cases:
            with self.subTest(error=error):
                self.assertEqual(self.invoke("verify", state=state(line), config=config())["error"], error)
        for line, owned, error in (("FAKE\ta.test", "OWNED_FAKE\ta.test", "VERIFY_OWNED_FILTER"),
                                   ("SUPPLEMENT_FAKE\tgeosite:cn", "OWNED_SUPPLEMENT_FAKE\tgeosite:cn", "VERIFY_OWNED_SUPPLEMENT_FILTER")):
            with self.subTest(error=error):
                self.assertEqual(self.invoke("ownership", state=state(line, owned), config=config())["error"], error)

    def test_runtime_filter_membership_preserves_missing_and_type_failures(self):
        value = state("FAKE\ta.test", "SUPPLEMENT_FAKE\tgeosite:cn")
        original = config(filters=["a.test", "geosite:cn"])
        self.assertTrue(self.invoke("runtime", state=value, config=original, runtime=original)["ok"])
        for filters, error in ((["geosite:cn"], "RUNTIME_FILTER"), (["a.test"], "RUNTIME_SUPPLEMENT_FILTER"),
                               ([123], "RUNTIME_FILTERS")):
            with self.subTest(error=error):
                result = self.invoke("runtime", state=value, config=original, runtime=config(filters=filters))
                self.assertEqual(result.get("error"), error, result)

    def test_render_cancellation_removes_only_one_owned_filter_copy(self):
        value = state("FAKE\ta.test", "OWNED_FAKE\ta.test", "SUPPLEMENT_FAKE\tgeosite:cn",
                      "OWNED_SUPPLEMENT_FAKE\tgeosite:cn")
        result = self.invoke("render", state=value, config=config(filters=["a.test", "geosite:cn", "a.test", "geosite:cn"]), desired=state())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["config"]["dns"]["fake-ip-filter"], ["a.test", "geosite:cn"])

    def large_fixture(self):
        rules = [f"DOMAIN,r{i}.test,DIRECT" for i in range(128)]
        filters = [f"f{i}.test" for i in range(128)]
        supplement_rules = [f"DOMAIN,s{i}.test,DIRECT,no-resolve" for i in range(256)]
        supplement_filters = [f"geosite:synthetic-{i}" for i in range(256)]
        lines = []
        for tag, items in (("RULE", [rule.replace(",", "\t") for rule in rules]), ("FAKE", filters),
                           ("SUPPLEMENT_RULE", supplement_rules), ("SUPPLEMENT_FAKE", supplement_filters)):
            lines.extend(f"{tag}\t{item}" for item in items)
            lines.extend(f"OWNED_{tag}\t{item}" for item in items)
        return state(*lines), config(rules + supplement_rules + ["MATCH,DIRECT"], filters + supplement_filters)

    def assert_no_large_array_search(self, operation):
        value, original = self.large_fixture()
        result = self.invoke(operation, state=value, config=original, runtime=original, trace=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["large_includes"], 0, "large ownership/member sets must not be scanned repeatedly")

    def test_parse_uses_indexed_membership_for_all_four_owned_sets(self):
        self.assert_no_large_array_search("parse")

    def test_ownership_filter_verification_uses_indexed_membership(self):
        self.assert_no_large_array_search("ownership")

    def test_static_verification_uses_indexed_membership(self):
        self.assert_no_large_array_search("verify")

    def test_runtime_verification_uses_indexed_membership(self):
        self.assert_no_large_array_search("runtime")


if __name__ == "__main__":
    unittest.main()
