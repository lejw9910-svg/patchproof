"""End-to-end lab checks and negative controls for patch verification."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest

from patchproof.__main__ import main
from patchproof.report import render_json, render_markdown
from patchproof.verifier import VerificationReport, discover_labs, verify_labs


ROOT = Path(__file__).resolve().parents[1]


class BundledLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.labs = discover_labs(ROOT / "labs")
        cls.report = verify_labs(cls.labs)

    def test_all_four_labs_reproduce_block_and_preserve_controls(self):
        self.assertEqual({lab.id for lab in self.labs}, {
            "path-traversal", "insecure-deserialization", "auth-bypass", "sql-injection",
        })
        self.assertEqual(self.report.status, "pass")
        for lab in self.report.labs:
            with self.subTest(lab=lab.id):
                self.assertEqual(lab.status, "pass")
                self.assertTrue(lab.diff.changed)
                self.assertGreaterEqual(sum(case.kind == "attack" for case in lab.cases), 2)
                self.assertGreaterEqual(sum(case.kind == "regression" for case in lab.cases), 2)
                self.assertTrue(all(case.status == "pass" for case in lab.cases))

    def test_reports_preserve_auditable_evidence(self):
        document = json.loads(render_json(self.report))
        self.assertEqual(document["status"], "pass")
        self.assertEqual(document["schema_version"], 1)
        markdown = render_markdown(self.report)
        for lab in document["labs"]:
            self.assertIn(lab["manifest_sha256"], markdown)
            self.assertIn(lab["diff"]["before_sha256"], markdown)
            self.assertIn(lab["diff"]["after_sha256"], markdown)
            for case in lab["cases"]:
                self.assertIn("input", case)
                self.assertIn("expected_patched", case)
                self.assertIn("value", case["patched"])
                self.assertIn(case["id"], markdown)
        self.assertEqual(markdown, render_markdown(self.report))
        self.assertIn("not a security isolation boundary", markdown)

    def test_reports_keep_escaped_surrogates_encodable(self):
        lab = self.report.labs[0]
        case = replace(lab.cases[0], input="\ud800", expected_patched="\ud800")
        lab = replace(lab, title="Boundary \ud800", cases=(case,))
        report = VerificationReport((lab,))
        rendered_json = render_json(report)
        rendered_markdown = render_markdown(report)
        rendered_json.encode("utf-8")
        rendered_markdown.encode("utf-8")
        self.assertEqual(json.loads(rendered_json)["labs"][0]["cases"][0]["input"], "\ud800")
        self.assertIn(r"\ud800", rendered_markdown)


class NegativeControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = self.root / "example"
        self.lab.mkdir()
        baseline = "def run(payload, workspace):\n    return 'vulnerable' if payload else 'normal'\n"
        (self.lab / "vulnerable.py").write_text(baseline)
        manifest = {
            "schema_version": 1, "id": "example", "title": "Example", "cwe": "CWE-22",
            "cases": [
                {"id": "attack", "kind": "attack", "input": True,
                 "expected_vulnerable": "vulnerable", "expected_patched": "rejected"},
                {"id": "normal", "kind": "regression", "input": False,
                 "expected_vulnerable": "normal", "expected_patched": "normal"},
            ],
        }
        (self.lab / "manifest.json").write_text(json.dumps(manifest))

    def run_cli(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(list(args))
        return code, output.getvalue(), errors.getvalue()

    def test_patch_that_disables_all_behavior_fails(self):
        (self.lab / "patched.py").write_text("def run(payload, workspace):\n    return 'rejected'\n")
        code, output, _ = self.run_cli("verify", "--labs-dir", str(self.root), "--format", "json")
        report = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(report["labs"][0]["cases"][0]["status"], "pass")
        self.assertEqual(report["labs"][0]["cases"][1]["status"], "fail")

    def test_fixed_baseline_cannot_prove_patch(self):
        fixed = "def run(payload, workspace):\n    return 'rejected' if payload else 'normal'\n"
        (self.lab / "patched.py").write_text(fixed)
        (self.lab / "vulnerable.py").write_text(fixed)
        code, output, _ = self.run_cli("verify", "--labs-dir", str(self.root), "--format", "json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["status"], "inconclusive")

    def test_crashing_patch_is_an_error_not_mitigation(self):
        (self.lab / "patched.py").write_text("def run(payload, workspace):\n    raise RuntimeError('broken')\n")
        code, output, _ = self.run_cli("verify", "--labs-dir", str(self.root), "--format", "json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["status"], "error")

    def test_report_output_and_unknown_selection(self):
        (self.lab / "patched.py").write_text("def run(payload, workspace):\n    return 'rejected' if payload else 'normal'\n")
        destination = self.root / "reports" / "evidence.json"
        code, output, errors = self.run_cli("verify", "--labs-dir", str(self.root), "--lab", "example",
                                            "--format", "json", "--output", str(destination))
        self.assertEqual(code, 0)
        self.assertEqual(output, "")
        self.assertIn("PASS", errors)
        self.assertEqual(json.loads(destination.read_text())["status"], "pass")
        code, _, errors = self.run_cli("verify", "--labs-dir", str(self.root), "--lab", "missing")
        self.assertEqual(code, 2)
        self.assertIn("Unknown labs", errors)

    def test_invalid_source_is_reported_without_traceback(self):
        (self.lab / "patched.py").write_text("def broken(\n")
        code, output, errors = self.run_cli("verify", "--labs-dir", str(self.root))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("patchproof:", errors)
        self.assertNotIn("Traceback", errors)


if __name__ == "__main__":
    unittest.main()
