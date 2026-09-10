"""The security review catalog is an exact, fail-closed exception mechanism."""
from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import bandit_policy as policy


SOURCE = b"# context before\n# another line\nvalue = load_fixture()\n# after\n# final\n"
RELATIVE = "openclash-sync-web/server.py"


def finding():
    return {"path": RELATIVE, "rule": "B506", "severity": "MEDIUM", "confidence": "HIGH",
            "line": 3, "context_sha256": policy.context_hash(SOURCE, 3, [3])}


def catalog():
    entry = finding()
    del entry["line"]
    entry.update(count=1, reason="Synthetic constrained loader reviewed for this exact source context.")
    return {"schema": 1, "reviewed": [entry]}


def report(root):
    metric = {"SEVERITY.LOW": 2, "SEVERITY.MEDIUM": 1, "SEVERITY.HIGH": 0}
    return {"errors": [], "metrics": {str(root / RELATIVE): dict(metric), "_totals": dict(metric)},
            "results": [{"filename": str(root / RELATIVE), "test_id": "B506", "issue_severity": "MEDIUM",
                         "issue_confidence": "HIGH", "line_number": 3, "line_range": [3],
                         "issue_text": "synthetic detail must not be echoed"}]}


class BanditPolicyTests(unittest.TestCase):
    def approved(self):
        return policy.reviewed_catalog(json.dumps(catalog()).encode(), {RELATIVE: SOURCE})

    def test_exact_review_matches(self):
        self.assertEqual(policy.classify([finding()], self.approved()), ([], []))

    def test_context_includes_surrounding_source(self):
        self.assertNotEqual(policy.context_hash(SOURCE.replace(b"context before", b"changed before"), 3, [3]),
                            finding()["context_sha256"])
        self.assertNotEqual(policy.context_hash(SOURCE.replace(b"load_fixture", b"different_call"), 3, [3]),
                            finding()["context_sha256"])

    def test_range_is_bounded_sorted_and_not_boolean(self):
        for line, selected in ((0, [1]), (True, [1]), (3, []), (3, [4]), (3, [3, 3]), (3, [3, 2]),
                               (3, [3, 200]), (3, [True, 3]), (3, None)):
            with self.subTest(line=line, selected=selected), self.assertRaises(policy.PolicyError):
                policy.context_hash(SOURCE, line, selected)

    def test_modified_or_moved_finding_is_not_waived(self):
        for key, value in (("path", "tools/new.py"), ("rule", "B102"), ("confidence", "LOW"),
                           ("severity", "HIGH"), ("context_sha256", "0" * 64)):
            item = dict(finding(), **{key: value})
            unexpected, stale = policy.classify([item], self.approved())
            self.assertEqual(unexpected, [item])
            self.assertEqual(len(stale), 1)

    def test_missing_or_additional_occurrences_fail(self):
        self.assertEqual(len(policy.classify([], self.approved())[1]), 1)
        unexpected, stale = policy.classify([finding(), finding()], self.approved())
        self.assertEqual(len(unexpected), 2)
        self.assertEqual(len(stale), 1)

    def test_catalog_cannot_waive_high_or_low_or_unknown_sources(self):
        changes = (("severity", "HIGH"), ("severity", "LOW"), ("path", "tests/unreviewed.py"),
                   ("confidence", []), ("context_sha256", "short"), ("count", True), ("count", 0),
                   ("count", 17), ("reason", "too short"), ("rule", "B000, B001"))
        for key, value in changes:
            data = catalog()
            data["reviewed"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(policy.PolicyError):
                policy.reviewed_catalog(json.dumps(data).encode(), {RELATIVE: SOURCE})

    def test_catalog_rejects_duplicate_entries_unknown_fields_and_schema(self):
        duplicate = catalog()
        duplicate["reviewed"] *= 2
        extra = catalog()
        extra["reviewed"][0]["allow_all"] = True
        schema = catalog()
        schema["schema"] = True
        for data in (duplicate, extra, schema, {"schema": 1, "reviewed": {}}):
            with self.subTest(data=data), self.assertRaises(policy.PolicyError):
                policy.reviewed_catalog(json.dumps(data).encode(), {RELATIVE: SOURCE})

    def test_json_duplicate_keys_or_nonobject_rejected(self):
        for body in (b'{"schema":1,"schema":2}', b'[]', b'null', b'invalid'):
            with self.subTest(body=body), self.assertRaises(policy.PolicyError):
                policy.json_object(body)

    def test_normal_report_preserves_low_counts_and_omits_message(self):
        root = Path("/synthetic-checkout")
        findings, totals = policy.normalize_report(root, {RELATIVE: SOURCE}, report(root))
        self.assertEqual(findings, [finding()])
        self.assertEqual(totals, {"LOW": 2, "MEDIUM": 1, "HIGH": 0})
        self.assertNotIn("issue_text", findings[0])

    def test_report_skips_scope_metrics_and_metadata_fail_closed(self):
        root = Path("/synthetic-checkout")
        original = report(root)
        variants = []
        for field, value in (("errors", [{"filename": "omitted.py"}]), ("errors", None),
                             ("results", []), ("metrics", {})):
            variants.append(dict(original, **{field: value}))
        for field, value in (("filename", []), ("filename", str(root / "extra.py")),
                             ("issue_severity", "LOW"), ("issue_severity", []),
                             ("issue_confidence", {}), ("line_number", True), ("line_range", [900])):
            data = copy.deepcopy(original)
            data["results"][0][field] = value
            variants.append(data)
        bad_total = copy.deepcopy(original)
        bad_total["metrics"]["_totals"]["SEVERITY.LOW"] = 0
        variants.append(bad_total)
        for data in variants:
            with self.subTest(data=data), self.assertRaises(policy.PolicyError):
                policy.normalize_report(root, {RELATIVE: SOURCE}, data)

    def fixture_tree(self, root):
        (root / "openclash-sync-web").mkdir()
        (root / "tools").mkdir()
        (root / RELATIVE).write_bytes(SOURCE)
        (root / "FILES").write_text(RELATIVE + "\n")
        (root / "tools/bandit-reviewed.json").write_text(json.dumps(catalog()) + "\n")

    def test_manifest_is_explicit_and_does_not_read_unlisted_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.fixture_tree(root)
            (root / "not-in-release.py").write_text("raise RuntimeError('not imported or scanned')\n")
            self.assertEqual(policy.python_sources(root), {RELATIVE: SOURCE})

    def test_known_repository_metadata_is_not_scanned_as_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.fixture_tree(root)
            names = [".gitattributes", ".github/workflows/ci.yml", ".gitignore",
                     "openclash-sync-web/.gitignore", RELATIVE]
            (root / "FILES").write_text("\n".join(sorted(names)) + "\n")
            with mock.patch.object(policy, "read_source", wraps=policy.read_source) as reader:
                self.assertEqual(policy.python_sources(root), {RELATIVE: SOURCE})
            self.assertEqual([call.args[1] for call in reader.call_args_list], ["FILES", RELATIVE])

    def test_manifest_paths_and_symlink_sources_rejected_before_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.fixture_tree(root)
            for member in ("../outside.py", ".git/config.py", "/absolute.py", RELATIVE + "\n" + RELATIVE):
                (root / "FILES").write_text(member + "\n")
                with self.subTest(member=member), self.assertRaises(policy.PolicyError):
                    policy.python_sources(root)
            (root / "FILES").write_text(RELATIVE + "\n")
            (root / RELATIVE).rename(root / "real.py")
            (root / RELATIVE).symlink_to(root / "real.py")
            with self.assertRaises(policy.BindingError):
                policy.python_sources(root)

    def test_real_gate_invocation_is_unsuppressed_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.fixture_tree(root)
            def fake_scanner(command, **kwargs):
                self.assertIn("--ignore-nosec", command)
                self.assertIn("-ll", command)
                self.assertNotIn("-r", command)
                self.assertEqual(command[-1], str(root / RELATIVE))
                self.assertFalse(kwargs["check"])
                Path(command[command.index("-o") + 1]).write_text(json.dumps(report(root)))
                return subprocess.CompletedProcess(command, 1, b"", b"")
            out = io.StringIO()
            with mock.patch.object(policy.subprocess, "run", side_effect=fake_scanner), redirect_stdout(out):
                self.assertEqual(policy.audit(root, "synthetic-bandit"), 0)
            self.assertIn("BANDIT_LOW=2", out.getvalue())
            self.assertIn("BANDIT_POLICY=PASS_WITH_REVIEWED_FINDINGS", out.getvalue())
            self.assertNotIn("synthetic detail", out.getvalue())
            self.assertNotIn("load_fixture", out.getvalue())

    def test_scan_drift_or_exit_report_disagreement_never_passes(self):
        for drift in ("source", "catalog", "manifest", "exit", "tool_failure"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                self.fixture_tree(root)
                def fake_scanner(command, *, root=root, drift=drift, **kwargs):
                    Path(command[command.index("-o") + 1]).write_text(json.dumps(report(root)))
                    target = {"source": RELATIVE, "catalog": "tools/bandit-reviewed.json", "manifest": "FILES"}.get(drift)
                    if target:
                        path = root / target
                        path.write_bytes(path.read_bytes() + b"\n")
                    code = 0 if drift == "exit" else (2 if drift == "tool_failure" else 1)
                    return subprocess.CompletedProcess(command, code, b"", b"")
                with mock.patch.object(policy.subprocess, "run", side_effect=fake_scanner), self.assertRaises(policy.PolicyError):
                    policy.audit(root, "synthetic-bandit")


if __name__ == "__main__":
    unittest.main()
