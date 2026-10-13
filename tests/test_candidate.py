"""External candidate verification, independent evidence, and report provenance."""

from datetime import datetime
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from patchproof.provenance import collect_run_metadata
from patchproof.report import render_json, render_markdown
from patchproof.sandbox import run_case
from patchproof.verifier import ManifestError, VerificationReport, load_lab, verify_lab, verify_labs


BASELINE = "def run(payload, workspace):\n    return 'vulnerable' if payload else 'normal'\n"
FIXED = "def run(payload, workspace):\n    return 'rejected' if payload else 'normal'\n"


class CandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "example"
        self.directory.mkdir()
        (self.directory / "vulnerable.py").write_text(BASELINE, encoding="utf-8")
        (self.directory / "patched.py").write_text(FIXED, encoding="utf-8")
        self.manifest = {
            "schema_version": 1, "id": "example", "title": "Example", "cwe": "CWE-22",
            "cases": [
                {"id": "attack", "kind": "attack", "input": True,
                 "expected_vulnerable": "vulnerable", "expected_patched": "rejected"},
                {"id": "normal", "kind": "regression", "input": False,
                 "expected_vulnerable": "normal", "expected_patched": "normal"},
            ],
        }
        self.write_manifest()
        self.lab = load_lab(self.directory)
        self.candidate = self.root / "reviewed-candidate.py"

    def write_manifest(self):
        (self.directory / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_valid_external_candidate_preserves_original_lab(self):
        original = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        candidate_bytes = (FIXED + "\n# Separately reviewed candidate.\n").encode()
        self.candidate.write_bytes(candidate_bytes)
        report = verify_labs((self.lab,), candidate=self.candidate)
        self.assertEqual(report.status, "pass")
        self.assertEqual(report.labs[0].diff.after_sha256, hashlib.sha256(candidate_bytes).hexdigest())
        self.assertEqual(report.labs[0].diff.before_sha256, hashlib.sha256(BASELINE.encode()).hexdigest())
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.directory.iterdir()})

    def test_unchanged_vulnerable_candidate_fails_attacks(self):
        self.candidate.write_text(BASELINE, encoding="utf-8")
        result = verify_lab(self.lab, candidate=self.candidate)
        self.assertEqual(result.status, "fail")
        self.assertFalse(result.diff.changed)
        self.assertEqual([case.status for case in result.cases], ["fail", "pass"])

    def test_candidate_that_rejects_everything_fails_functional_control(self):
        self.candidate.write_text("def run(payload, workspace):\n    return 'rejected'\n", encoding="utf-8")
        result = verify_lab(self.lab, candidate=self.candidate)
        self.assertEqual(result.status, "fail")
        self.assertEqual([case.status for case in result.cases], ["pass", "fail"])

    def test_candidate_requires_exactly_one_lab(self):
        self.candidate.write_text(FIXED, encoding="utf-8")
        for labs in ((), (self.lab, self.lab)):
            with self.subTest(lab_count=len(labs)), patch("patchproof.verifier.run_case") as run:
                with self.assertRaises(ManifestError):
                    verify_labs(labs, candidate=self.candidate)
                run.assert_not_called()

    def test_candidate_is_snapshotted_once_before_execution(self):
        candidate_bytes = FIXED.encode()
        self.candidate.write_bytes(candidate_bytes)
        seen_paths = []

        def execute_snapshot(module, payload, **kwargs):
            seen_paths.append(module)
            self.candidate.write_text("raise RuntimeError('edited after snapshot')\n", encoding="utf-8")
            return run_case(module, payload, **kwargs)

        with patch("patchproof.verifier.run_case", side_effect=execute_snapshot):
            result = verify_lab(self.lab, candidate=self.candidate)
        self.assertEqual(result.status, "pass")
        self.assertNotIn(self.candidate, seen_paths)
        self.assertEqual(result.diff.after_sha256, hashlib.sha256(candidate_bytes).hexdigest())

    def test_pickle_execution_followed_by_denial_fails_independent_observation(self):
        # Protocol 0 reconstructs only str('marker'); no commands or external data.
        reconstruct = "        pickle.loads(b'cbuiltins\\nstr\\n(Vmarker\\ntR.')\n"
        deceptive = ("import pickle\ndef run(payload, workspace):\n    if payload:\n"
                     + reconstruct + "        return 'rejected'\n    return 'normal'\n")
        (self.directory / "vulnerable.py").write_text(deceptive, encoding="utf-8")
        self.manifest["cases"][0]["expected_vulnerable"] = "rejected"
        for case in self.manifest["cases"]:
            case["expected_vulnerable_observations"] = {"pickle_class_resolutions": int(case["kind"] == "attack")}
            case["expected_patched_observations"] = {"pickle_class_resolutions": 0}
        self.write_manifest()
        lab = load_lab(self.directory)
        self.candidate.write_text(deceptive, encoding="utf-8")
        result = verify_lab(lab, candidate=self.candidate)
        attack = result.cases[0]
        self.assertEqual(attack.patched.value, attack.expected_patched)
        self.assertEqual(attack.patched.observations, {"pickle_class_resolutions": 1})
        self.assertEqual(attack.status, "fail")
        self.candidate.write_text(FIXED, encoding="utf-8")
        self.assertEqual(verify_lab(lab, candidate=self.candidate).status, "pass")

    def test_report_records_context_limits_tool_hashes_and_observations(self):
        self.candidate.write_text(FIXED, encoding="utf-8")
        report = verify_labs((self.lab,), candidate=self.candidate, timeout=3.0, max_output_bytes=32_768)
        metadata = report.metadata
        self.assertEqual(metadata["limits"], {"timeout_seconds": 3.0, "max_output_bytes": 32_768})
        self.assertIsNotNone(datetime.fromisoformat(metadata["timestamp_utc"].replace("Z", "+00:00")).tzinfo)
        self.assertTrue(metadata["python_version"])
        self.assertEqual(set(metadata["platform"]), {"system", "release", "machine"})
        package = Path(__file__).resolve().parents[1] / "src" / "patchproof"
        self.assertIn("_worker.py", metadata["tool_source_sha256"])
        for relative, digest in metadata["tool_source_sha256"].items():
            self.assertEqual(digest, hashlib.sha256((package / relative).read_bytes()).hexdigest())
        document = json.loads(render_json(report))
        self.assertEqual(document["metadata"], metadata)
        self.assertEqual(document["labs"][0]["cases"][0]["patched"]["observations"],
                         {"pickle_class_resolutions": 0})
        markdown = render_markdown(report)
        self.assertIn(metadata["timestamp_utc"], markdown)
        self.assertIn('"pickle_class_resolutions": 0', markdown)
        self.assertIn('"expected_patched_observations": null', markdown)
        self.assertEqual(markdown, render_markdown(report))

    def test_direct_report_construction_has_independent_default_metadata(self):
        first = VerificationReport(())
        second = VerificationReport(())
        first.metadata["limits"]["timeout_seconds"] = 99
        self.assertIsNone(second.metadata["limits"]["timeout_seconds"])
        self.assertEqual(set(collect_run_metadata()), set(second.metadata))


if __name__ == "__main__":
    unittest.main()
