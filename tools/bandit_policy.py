#!/usr/bin/env python3
"""Fail on unreviewed Bandit medium/high findings, without hiding test fixtures.

Bandit runs with --ignore-nosec against the explicit public Python manifest.
Review exceptions bind path, rule, severity, confidence and surrounding source
bytes. LOW findings stay visible in counts; this is not a claim of zero risk.
Only metadata is printed, never source text, issue messages or credential values.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

if __package__:
    from .release_bindings import BindingError, read_source
else:
    from release_bindings import BindingError, read_source


class PolicyError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON key")
        result[key] = value
    return result


def json_object(body: bytes):
    try:
        value = json.loads(body, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise PolicyError("invalid JSON report or review catalog") from exc
    if not isinstance(value, dict):
        raise PolicyError("expected JSON object")
    return value


def python_sources(root: Path) -> dict[str, bytes]:
    manifest = read_source(root, "FILES").decode("utf-8")
    names = manifest.splitlines()
    if not manifest.endswith("\n") or not names or names != sorted(set(names)) or len(names) > 4096:
        raise PolicyError("invalid public source manifest")
    bodies = {}
    for name in names:
        path = Path(name)
        if (path.is_absolute() or path.as_posix() != name or ".." in path.parts
                or (name not in {".gitattributes", ".gitignore", "openclash-sync-web/.gitignore"}
                    and any(part.startswith(".") and part != ".github" for part in path.parts))):
            raise PolicyError("unsafe public source member")
        if not name.endswith(".py") or name.startswith("vendor/pyyaml-6.0.2/"):
            continue
        if len(path.parts) > 1 and path.parts[0] not in {"tools", "tests", "openclash-sync-web"}:
            raise PolicyError("unexpected Python source directory")
        bodies[name] = read_source(root, name)
    if not bodies or "openclash-sync-web/server.py" not in bodies:
        raise PolicyError("incomplete public Python source scope")
    return bodies


def context_hash(body: bytes, line: int, line_range: list[int]) -> str:
    lines = body.splitlines()
    if (type(line) is not int or not 1 <= line <= len(lines)
            or not isinstance(line_range, list) or not line_range
            or any(type(n) is not int or not 1 <= n <= len(lines) for n in line_range)
            or line_range != sorted(set(line_range)) or line not in line_range):
        raise PolicyError("invalid finding source range")
    context = b"\n".join(lines[max(0, min(line_range) - 3):max(line_range) + 2])
    return hashlib.sha256(context).hexdigest()


def finding_key(finding: dict) -> tuple:
    return tuple(finding[key] for key in ("path", "rule", "severity", "confidence", "context_sha256"))


def reviewed_catalog(body: bytes, sources: dict[str, bytes]) -> dict[tuple, int]:
    value = json_object(body)
    if set(value) != {"schema", "reviewed"} or type(value["schema"]) is not int or value["schema"] != 1:
        raise PolicyError("invalid review schema")
    entries = value["reviewed"]
    if not isinstance(entries, list) or len(entries) > 128:
        raise PolicyError("invalid review count")
    result = {}
    fields = {"path", "rule", "severity", "confidence", "context_sha256", "count", "reason"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise PolicyError("invalid review entry")
        if (not isinstance(entry["path"], str) or entry["path"] not in sources
                or not isinstance(entry["rule"], str) or not re.fullmatch(r"B[0-9]{3}", entry["rule"])
                or entry["severity"] != "MEDIUM" or entry["confidence"] not in ("LOW", "MEDIUM", "HIGH")
                or not isinstance(entry["context_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["context_sha256"])
                or type(entry["count"]) is not int or not 1 <= entry["count"] <= 16
                or not isinstance(entry["reason"], str) or not 20 <= len(entry["reason"]) <= 800
                or any(ord(char) < 32 for char in entry["reason"])):
            raise PolicyError("unsafe or incomplete review entry")
        key = finding_key(entry)
        if key in result:
            raise PolicyError("duplicate review entry")
        result[key] = entry["count"]
    return result


def normalize_report(root: Path, sources: dict[str, bytes], report: dict) -> tuple[list[dict], dict[str, int]]:
    if report.get("errors") != []:
        raise PolicyError("Bandit skipped or failed a source file")
    metrics = report.get("metrics")
    raw_findings = report.get("results")
    expected_paths = {str(root / name) for name in sources}
    if (not isinstance(metrics, dict) or set(metrics) != expected_paths | {"_totals"}
            or not isinstance(raw_findings, list)):
        raise PolicyError("Bandit source coverage mismatch")
    totals = {}
    for severity in ("LOW", "MEDIUM", "HIGH"):
        key = "SEVERITY." + severity
        values = [metrics[path].get(key) if isinstance(metrics[path], dict) else None for path in expected_paths]
        total = metrics["_totals"].get(key) if isinstance(metrics["_totals"], dict) else None
        if type(total) is not int or total < 0 or any(type(n) is not int or n < 0 for n in values) or sum(values) != total:
            raise PolicyError("Bandit metrics mismatch")
        totals[severity] = total
    if len(raw_findings) != totals["MEDIUM"] + totals["HIGH"]:
        raise PolicyError("Bandit finding count mismatch")
    findings = []
    for issue in raw_findings:
        if (not isinstance(issue, dict) or not isinstance(issue.get("filename"), str)
                or issue["filename"] not in expected_paths):
            raise PolicyError("unexpected finding source")
        severity, confidence, rule = issue.get("issue_severity"), issue.get("issue_confidence"), issue.get("test_id")
        if (severity not in ("MEDIUM", "HIGH") or confidence not in ("LOW", "MEDIUM", "HIGH")
                or not isinstance(rule, str) or not re.fullmatch(r"B[0-9]{3}", rule)):
            raise PolicyError("invalid finding metadata")
        relative = Path(issue["filename"]).relative_to(root).as_posix()
        findings.append({"path": relative, "rule": rule, "severity": severity, "confidence": confidence,
                         "line": issue.get("line_number"),
                         "context_sha256": context_hash(sources[relative], issue.get("line_number"), issue.get("line_range"))})
    if Counter(f["severity"] for f in findings) != Counter({k: totals[k] for k in ("MEDIUM", "HIGH") if totals[k]}):
        raise PolicyError("Bandit severity count mismatch")
    return findings, totals


def classify(findings: list[dict], reviewed: dict[tuple, int]) -> tuple[list[dict], list[tuple]]:
    seen = Counter(finding_key(finding) for finding in findings)
    unexpected = [finding for finding in findings if finding["severity"] == "HIGH"
                  or seen[finding_key(finding)] != reviewed.get(finding_key(finding))]
    stale = [key for key, count in reviewed.items() if seen[key] != count]
    return unexpected, stale


def audit(root: Path, bandit: str) -> int:
    root = root.absolute()
    manifest_bytes = read_source(root, "FILES")
    sources = python_sources(root)
    catalog_bytes = read_source(root, "tools/bandit-reviewed.json")
    reviewed = reviewed_catalog(catalog_bytes, sources)
    # Only medium/high messages reach the JSON formatter. A malformed Unicode
    # password fixture can crash Bandit's LOW issue-message encoder; its LOW
    # count is nevertheless included, and all source files are still analyzed.
    with tempfile.TemporaryDirectory(prefix="openclash-bandit-") as temporary:
        report_path = Path(temporary) / "report.json"
        completed = subprocess.run(
            [bandit, "--ignore-nosec", "-q", "-ll", "-f", "json", "-o", str(report_path),
             *[str(root / name) for name in sources]],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        if completed.returncode not in (0, 1):
            raise PolicyError("Bandit execution failed")
        report = json_object(read_source(Path(temporary), "report.json"))
    for name, body in sources.items():
        if read_source(root, name) != body:
            raise PolicyError("source changed during Bandit scan")
    if read_source(root, "FILES") != manifest_bytes:
        raise PolicyError("source manifest changed during scan")
    if read_source(root, "tools/bandit-reviewed.json") != catalog_bytes:
        raise PolicyError("review catalog changed during scan")
    findings, totals = normalize_report(root, sources, report)
    if completed.returncode != (1 if findings else 0):
        raise PolicyError("Bandit exit status and report disagree")
    unexpected, stale = classify(findings, reviewed)
    print(f"BANDIT_FILES={len(sources)}\nBANDIT_HIGH={totals['HIGH']}\nBANDIT_MEDIUM={totals['MEDIUM']}\nBANDIT_LOW={totals['LOW']}")
    print(f"BANDIT_REVIEWED_MEDIUM={sum(reviewed.values())}\nBANDIT_UNREVIEWED={len(unexpected)}\nBANDIT_STALE_REVIEWS={len(stale)}")
    for finding in unexpected:
        print(f"UNREVIEWED={finding['path']}:{finding['line']}:{finding['rule']}:{finding['severity']}")
    for key in stale:
        print(f"STALE_REVIEW={key[0]}:{key[1]}:{key[4]}")
    print("BANDIT_POLICY=" + ("FAIL" if unexpected or stale else "PASS_WITH_REVIEWED_FINDINGS"))
    return 1 if unexpected or stale else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).absolute().parents[1])
    parser.add_argument("--bandit", default="bandit")
    args = parser.parse_args()
    try:
        return audit(args.root, args.bandit)
    except (PolicyError, BindingError, OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        # No source fragments, scanner stderr or raw exception data in logs.
        print(f"BANDIT_POLICY=FAIL\nREASON={type(exc).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
