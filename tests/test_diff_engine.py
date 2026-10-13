import hashlib
import tempfile
import unittest
from pathlib import Path

from patchproof.diff_engine import compare_files


class DiffEngineTests(unittest.TestCase):
    def compare(self, before, after):
        with tempfile.TemporaryDirectory() as directory:
            old = Path(directory) / "old.py"
            new = Path(directory) / "new.py"
            old.write_bytes(before)
            new.write_bytes(after)
            return compare_files(old, new)

    def test_identical_sources(self):
        content = b"print('hello')\n"
        result = self.compare(content, content)
        self.assertFalse(result.changed)
        self.assertEqual(result.unified_diff, "")
        self.assertEqual(result.before_sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(result.before_sha256, result.after_sha256)

    def test_source_change_has_stable_diff_labels_and_raw_hashes(self):
        old, new = b"old()\n", b"new()\n"
        result = self.compare(old, new)
        self.assertTrue(result.changed)
        self.assertEqual(result.before_sha256, hashlib.sha256(old).hexdigest())
        self.assertEqual(result.after_sha256, hashlib.sha256(new).hexdigest())
        self.assertEqual(result.unified_diff,
                         "--- vulnerable.py\n+++ patched.py\n@@ -1 +1 @@\n-old()\n+new()\n")
        self.assertEqual(result, self.compare(old, new))

    def test_missing_final_newline_is_explicit(self):
        result = self.compare(b"same()", b"same()\n")
        self.assertTrue(result.changed)
        self.assertNotEqual(result.before_sha256, result.after_sha256)
        self.assertEqual(result.unified_diff,
                         "--- vulnerable.py\n+++ patched.py\n@@ -1 +1 @@\n-same()\n"
                         "\\ No newline at end of file\n+same()\n")

    def test_both_files_missing_newline(self):
        result = self.compare(b"old()", b"new()")
        self.assertEqual(result.unified_diff.count("\\ No newline at end of file"), 2)
        self.assertIn("-old()\n\\ No newline at end of file\n+new()\n", result.unified_diff)

    def test_crlf_bytes_are_preserved(self):
        result = self.compare(b"same()\r\n", b"same()\n")
        self.assertTrue(result.changed)
        self.assertIn("-same()\r\n+same()\n", result.unified_diff)
        self.assertNotIn("No newline", result.unified_diff)

    def test_empty_files_and_unicode(self):
        self.assertEqual(self.compare(b"", b"").unified_diff, "")
        result = self.compare(b"", "name = 'caf\u00e9'\n".encode())
        self.assertIn("+name = 'caf\u00e9'\n", result.unified_diff)

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(UnicodeDecodeError):
            self.compare(b"\xff", b"valid\n")


if __name__ == "__main__":
    unittest.main()
