"""Read-only release gates; no repository-wide inventory or config discovery.

FILES is one canonical relative path per line. SHA256SUMS uses sha256sum's
lowercase-hex, two-space text format. Order need not agree. Neither manifest
is payload: the test is hashed normally, without embedding its own checksum.
Only public source filenames beneath tests/ are inventoried for completeness;
no discovered file contents, hidden trees, caches, or configuration are scanned.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAMES = frozenset({"FILES", "SHA256SUMS"})
TEST_SOURCE_SUFFIXES = frozenset({".py", ".rb", ".lua", ".sh", ".js", ".mjs", ".cjs", ".ts"})


def member_parts(name: str) -> list[str]:
    parts = name.split("/")
    if (not name or name != name.strip() or "\\" in name or ":" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(part in ("", ".", "..") for part in parts)):
        raise ValueError(f"invalid canonical relative manifest path: {name!r}")
    if name in MANIFEST_NAMES:
        raise ValueError(f"manifest must not list itself or the other manifest: {name}")
    return parts


def manifest_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines or any(not line for line in lines):
        raise ValueError("manifest must be nonempty and contain no blank records")
    return lines


def parse_files(text: str) -> list[str]:
    names = manifest_lines(text)
    seen = set()
    for name in names:
        member_parts(name)
        if name in seen:
            raise ValueError(f"duplicate FILES member: {name}")
        seen.add(name)
    return names


def parse_checksums(text: str) -> dict[str, str]:
    checksums = {}
    for number, line in enumerate(manifest_lines(text), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError(f"invalid SHA256SUMS record on line {number}")
        digest, name = match.groups()
        member_parts(name)
        if name in checksums:
            raise ValueError(f"duplicate SHA256SUMS member: {name}")
        checksums[name] = digest
    return checksums


def regular_member(root: Path, name: str) -> Path:
    """Use lstat on every component: never accept a symlink or special file."""
    parts = member_parts(name)
    path = root
    for index, part in enumerate(parts):
        path = path / part
        mode = path.lstat().st_mode
        valid = stat.S_ISREG(mode) if index == len(parts) - 1 else stat.S_ISDIR(mode)
        if not valid:
            raise ValueError(f"manifest member is not a plain relative regular file: {name}")
    return path


def public_test_sources(root: Path) -> set[str]:
    """Inventory source names only; do not follow links or read configurations."""
    tests = root / "tests"
    if not stat.S_ISDIR(tests.lstat().st_mode):
        raise ValueError("tests must be a real directory, not a symlink")

    def fail_on_error(error: OSError) -> None:
        raise error

    sources = set()
    for directory, subdirs, filenames in os.walk(tests, followlinks=False, onerror=fail_on_error):
        subdirs[:] = sorted(name for name in subdirs
                            if not name.startswith(".") and name not in {"__pycache__", "node_modules"})
        for name in subdirs:
            if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                raise ValueError("public test source directories must not be symlinks")
        for name in sorted(filenames):
            if name.startswith(".") or Path(name).suffix not in TEST_SOURCE_SUFFIXES:
                continue
            relative = (Path(directory) / name).relative_to(root).as_posix()
            regular_member(root, relative)
            sources.add(relative)
    return sources


class DistributionManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in MANIFEST_NAMES:
            if not stat.S_ISREG((ROOT / name).lstat().st_mode):
                raise ValueError(f"{name} must be a regular file, not a symlink")
        cls.files = parse_files((ROOT / "FILES").read_bytes().decode("utf-8"))
        cls.checksums = parse_checksums((ROOT / "SHA256SUMS").read_bytes().decode("utf-8"))

    def test_unique_member_sets_match(self):
        # Parsers reject duplicates before any conversion to sets/dicts.
        self.assertEqual(set(self.files), set(self.checksums))

    def test_all_members_are_relative_regular_files(self):
        for name in sorted(set(self.files) | set(self.checksums)):
            with self.subTest(member=name):
                regular_member(ROOT, name)

    def test_recorded_hashes_match_payloads(self):
        # Read only declared payloads after path/metadata checks, never glob the repo.
        for name, expected in self.checksums.items():
            with self.subTest(member=name):
                path = regular_member(ROOT, name)
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                self.assertEqual(digest.hexdigest(), expected, f"SHA256 mismatch: {name}")

    def test_all_public_tests_and_harnesses_are_manifested(self):
        sources = public_test_sources(ROOT)
        self.assertTrue(sources, "public test source inventory must not be empty")
        for label, members in (("FILES", self.files), ("SHA256SUMS", self.checksums)):
            with self.subTest(manifest=label):
                self.assertFalse(sources - set(members),
                                 f"{label} omits public test sources: {sorted(sources - set(members))}")


class ManifestValidationTests(unittest.TestCase):
    """Synthetic rejection regressions: no temporary files or actual unsafe reads."""

    def test_member_order_is_not_significant(self):
        files = parse_files("tests/helper.lua\ntests/test_example.py\n")
        sums = parse_checksums(f"{'0' * 64}  tests/test_example.py\n"
                               f"{'1' * 64}  tests/helper.lua\n")
        self.assertNotEqual(files, list(sums))
        self.assertEqual(set(files), set(sums))

    def test_duplicate_members_are_rejected_even_with_identical_hashes(self):
        with self.assertRaisesRegex(ValueError, "duplicate FILES member"):
            parse_files("tests/helper.lua\ntests/helper.lua\n")
        for second_digest in ("0" * 64, "1" * 64):
            with self.subTest(second_digest=second_digest):
                with self.assertRaisesRegex(ValueError, "duplicate SHA256SUMS member"):
                    parse_checksums(f"{'0' * 64}  tests/helper.lua\n"
                                    f"{second_digest}  tests/helper.lua\n")

    def test_empty_or_blank_manifest_records_are_rejected(self):
        for parser, good in ((parse_files, "tests/helper.lua"),
                             (parse_checksums, f"{'0' * 64}  tests/helper.lua")):
            for text in ("", "\n", f"\n{good}\n", f"{good}\n\n"):
                with self.subTest(parser=parser.__name__, text=text):
                    with self.assertRaises(ValueError):
                        parser(text)

    def test_unsafe_paths_and_manifest_self_references_are_rejected(self):
        names = ("", "/outside.py", "../outside.py", "tests/../outside.py", "./server.py",
                 "tests//test_example.py", "tests/./test_example.py", "tests/", ".", "..",
                 "C:/outside.py", "C:outside.py", "tests\\test_example.py", " server.py",
                 "server.py ", "tests/tab\t.py", "tests/nul\x00.py", "tests/cr\r.py",
                 "FILES", "SHA256SUMS")
        for name in names:
            with self.subTest(member=name):
                with self.assertRaises(ValueError):
                    parse_files(f"{name}\n")
                with self.assertRaises(ValueError):
                    parse_checksums(f"{'0' * 64}  {name}\n")

    def test_malformed_checksum_records_are_rejected(self):
        for line in (f"{'0' * 63}  tests/helper.lua", f"{'0' * 65}  tests/helper.lua",
                     f"{'g' * 64}  tests/helper.lua", f"{'0' * 64} tests/helper.lua",
                     f"{'0' * 64}\ttests/helper.lua", f"{'0' * 64}   tests/helper.lua",
                     f"{'0' * 64}  "):
            with self.subTest(record=line):
                with self.assertRaises(ValueError):
                    parse_checksums(line)

    def test_symlinks_and_special_files_are_rejected(self):
        for mode in (stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            with self.subTest(mode=mode):
                with mock.patch.object(Path, "lstat", return_value=mock.Mock(st_mode=mode)):
                    with self.assertRaises(ValueError):
                        regular_member(ROOT, "example.py")

    def test_symlink_parent_is_rejected_before_leaf_lookup(self):
        with mock.patch.object(Path, "lstat", return_value=mock.Mock(st_mode=stat.S_IFLNK)) as lookup:
            with self.assertRaises(ValueError):
                regular_member(ROOT, "tests/helper.lua")
            lookup.assert_called_once_with()

    def test_missing_members_are_not_silently_ignored(self):
        with mock.patch.object(Path, "lstat", side_effect=FileNotFoundError("synthetic missing member")):
            with self.assertRaises(FileNotFoundError):
                regular_member(ROOT, "missing.py")


if __name__ == "__main__":
    unittest.main()
