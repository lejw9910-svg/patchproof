"""Offline model packet boundaries and public repair contracts."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from patchproof.research import prepare_packet
from patchproof.verifier import discover_labs, load_lab, ManifestError


ROOT = Path(__file__).resolve().parents[1]


class ResearchPacketTests(unittest.TestCase):
    def test_packets_include_baseline_identity_but_not_reference_or_test_answers(self):
        for lab in discover_labs(ROOT / "labs"):
            with self.subTest(lab=lab.id):
                packet = prepare_packet(lab)
                source = (lab.directory / "vulnerable.py").read_bytes()
                self.assertEqual(packet["baseline"]["sha256"], hashlib.sha256(source).hexdigest())
                self.assertEqual(packet["baseline"]["source"], source.decode("utf-8"))
                self.assertEqual(packet["manifest_sha256"], lab.manifest_sha256)
                self.assertNotIn("cases", packet)
                self.assertNotIn("patched", packet)
                self.assertNotIn("expected_patched", json.dumps(packet))
                self.assertFalse(packet["execution"]["claude_run_performed"])
                self.assertTrue(packet["public_contract"])

    def test_preparation_does_not_execute_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "example"
            root.mkdir()
            marker = Path(directory) / "executed"
            (root / "vulnerable.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            (root / "patched.py").write_text("raise RuntimeError('must not import')\n")
            data = {"schema_version": 1, "id": "example", "title": "Example", "cwe": "CWE-22", "cases": [
                {"id": "attack", "kind": "attack", "input": True, "expected_vulnerable": True, "expected_patched": False},
                {"id": "control", "kind": "regression", "input": False, "expected_vulnerable": False, "expected_patched": False},
            ]}
            (root / "manifest.json").write_text(json.dumps(data))
            lab = load_lab(root)
            with self.assertRaisesRegex(ValueError, "objective"):
                prepare_packet(lab)
            packet = prepare_packet(lab, objective="Keep reads in the declared workspace")
            self.assertFalse(marker.exists())
            self.assertEqual(packet["execution"]["network_requests"], 0)
            (root / "manifest.json").write_text(json.dumps(data) + "\n")
            with self.assertRaisesRegex(ManifestError, "changed"):
                prepare_packet(lab, objective="Contain reads")

    def test_empty_objective_is_rejected(self):
        lab = discover_labs(ROOT / "labs")[0]
        with self.assertRaises(ValueError):
            prepare_packet(lab, objective=" ")


if __name__ == "__main__":
    unittest.main()
