"""Exercise only extracted metadata helpers, never installers or router state."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ('install_router_web_agent.sh', 'update_router_web_agent.sh')


class ShellMetadataHelperTests(unittest.TestCase):
    def setUp(self):
        # Keep generated fixtures under the caller's isolated TMPDIR for audit.
        self.root = Path(tempfile.mkdtemp(prefix='inode-helper-'))
        self.file = self.root / 'ordinary file\nwith newline.txt'
        self.file.write_text('synthetic metadata fixture\n')
        self.link = self.root / 'link'
        self.link.symlink_to(self.file)

    def call(self, script, path):
        source = (ROOT / script).read_text()
        helpers = re.findall(r'^inode\(\)\{[^\n]+\}$', source, re.M)
        self.assertEqual(len(helpers), 1)
        return subprocess.run(['/bin/sh', '-c', helpers[0] + '\ninode "$1"', 'metadata-check', str(path)],
                              text=True, capture_output=True, timeout=5, check=False,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C'})

    def test_regular_file_reports_exact_inode_with_unusual_path(self):
        for script in SCRIPTS:
            with self.subTest(script=script):
                result = self.call(script, self.file)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(os.lstat(self.file).st_ino))
                self.assertEqual(result.stderr, '')

    def test_missing_file_fails_instead_of_masking_pipeline_status(self):
        for script in SCRIPTS:
            with self.subTest(script=script):
                result = self.call(script, self.root / 'missing')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, '')

    def test_directory_is_not_treated_as_a_file_inode(self):
        for script in SCRIPTS:
            with self.subTest(script=script):
                result = self.call(script, self.root)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_symlink_is_not_treated_as_a_file_inode(self):
        for script in SCRIPTS:
            with self.subTest(script=script):
                result = self.call(script, self.link)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
