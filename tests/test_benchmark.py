"""A bad patch must fail the intended check, not merely crash or change output."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from patchproof.benchmark import render_benchmark_markdown, run_benchmark
from patchproof.sandbox import ExecutionResult
from patchproof.verifier import verify_lab


ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"
EVALUATION = ROOT / "evaluation"


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {}

        def record(lab, *, candidate, **kwargs):
            result = verify_lab(lab, candidate=candidate, **kwargs)
            cls.results[(lab.id, candidate.name)] = result
            return result

        # These are real subprocess executions; retain typed results for fault
        # injection tests without needlessly rerunning the complete corpus.
        with patch("patchproof.benchmark.verify_lab", side_effect=record):
            cls.report = run_benchmark(LABS, EVALUATION)
        cls.manifest = json.loads((EVALUATION / "manifest.json").read_text())

    def run_one(self, experiment, observed=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = {"schema_version": 1, "title": "Fault injection test", "experiments": [experiment]}
            (root / "manifest.json").write_text(json.dumps(value))
            if experiment["source"] == "candidate" and ".." not in Path(experiment["candidate"]).parts:
                path = root / experiment["candidate"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("def run(payload, workspace):\n    return None\n")
            with patch("patchproof.benchmark.verify_lab", return_value=observed):
                return run_benchmark(LABS, root)

    def experiment(self, identifier):
        return deepcopy(next(item for item in self.manifest["experiments"] if item["id"] == identifier))

    def test_curated_corpus_accepts_references_and_rejects_all_declared_bad_patches(self):
        self.assertEqual(self.report["status"], "pass", self.report)
        self.assertEqual(self.report["metrics"], {
            "experiments": 17, "expected_good": 4, "expected_bad": 13,
            "accepted_good": 4, "rejected_bad": 13, "false_acceptances": 0,
            "false_rejections": 0, "errors": 0, "inconclusive": 0, "check_mismatches": 0,
        })
        self.assertEqual(self.report["tool"], "patchproof")
        self.assertIn("benchmark.py", self.report["metadata"]["tool_source_sha256"])
        for experiment in self.report["experiments"]:
            with self.subTest(experiment=experiment["id"]):
                self.assertEqual(experiment["status"], "pass")
                self.assertTrue(experiment["result"]["cases"])
                for case in experiment["result"]["cases"]:
                    self.assertEqual(case["vulnerable"]["status"], "ok")
                    self.assertEqual(case["patched"]["status"], "ok")

    def test_load_then_deny_is_caught_by_observation_despite_matching_every_return(self):
        experiment = next(item for item in self.report["experiments"]
                          if item["id"] == "insecure-deserialization-load-then-deny")
        self.assertEqual(experiment["classification"], "rejected_bad")
        for case in experiment["result"]["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["patched"]["value"], case["expected_patched"])
                if case["kind"] == "attack":
                    self.assertEqual(case["status"], "fail")
                    self.assertEqual(case["patched"]["observations"]["pickle_class_resolutions"], 1)
                    self.assertEqual(case["expected_patched_observations"]["pickle_class_resolutions"], 0)
                else:
                    self.assertEqual(case["status"], "pass")

    def test_execution_error_never_counts_as_detecting_bad_patch(self):
        reference = self.results[("auth-bypass", "patched.py")]
        first = replace(reference.cases[0], status="error", patched=ExecutionResult("timeout"))
        observed = replace(reference, status="error", cases=(first,) + reference.cases[1:])
        report = self.run_one(self.experiment("auth-bypass-unchanged"), observed)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["metrics"]["errors"], 1)
        self.assertEqual(report["metrics"]["rejected_bad"], 0)

    def test_failed_baseline_control_never_counts_as_detection(self):
        reference = self.results[("auth-bypass", "patched.py")]
        cases = list(reference.cases)
        index = next(index for index, case in enumerate(cases) if case.id == "valid-admin")
        cases[index] = replace(cases[index], status="fail", vulnerable=ExecutionResult("ok", {"wrong": True}))
        observed = replace(reference, status="fail", cases=tuple(cases))
        report = self.run_one(self.experiment("auth-bypass-unchanged"), observed)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["metrics"]["inconclusive"], 1)
        self.assertEqual(report["metrics"]["rejected_bad"], 0)

    def test_unrelated_candidate_failure_does_not_satisfy_targeted_check(self):
        reference = self.results[("auth-bypass", "patched.py")]
        cases = list(reference.cases)
        index = next(index for index, case in enumerate(cases) if case.id == "valid-admin")
        cases[index] = replace(cases[index], status="fail", patched=ExecutionResult("ok", {"wrong": True}))
        observed = replace(reference, status="fail", cases=tuple(cases))
        report = self.run_one(self.experiment("auth-bypass-unchanged"), observed)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["metrics"]["check_mismatches"], 1)
        self.assertEqual(report["metrics"]["rejected_bad"], 0)

    def test_false_acceptance_is_reported(self):
        reference = self.results[("auth-bypass", "patched.py")]
        report = self.run_one(self.experiment("auth-bypass-unchanged"), reference)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["metrics"]["false_acceptances"], 1)
        self.assertEqual(report["metrics"]["rejected_bad"], 0)

    def test_missing_independent_observation_is_error_instead_of_detection(self):
        mutation = self.results[("insecure-deserialization", "load-then-deny.py")]
        first = replace(mutation.cases[0], patched=replace(mutation.cases[0].patched, observations={}))
        observed = replace(mutation, cases=(first,) + mutation.cases[1:])
        report = self.run_one(self.experiment("insecure-deserialization-load-then-deny"), observed)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["metrics"]["errors"], 1)
        self.assertEqual(report["metrics"]["rejected_bad"], 0)

    def test_unknown_targeted_case_is_configuration_error(self):
        experiment = self.experiment("auth-bypass-unchanged")
        experiment["required_fail_cases"] = ["does-not-exist"]
        report = self.run_one(experiment)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["metrics"]["errors"], 1)
        self.assertEqual(report["metrics"]["rejected_bad"], 0)

    def test_candidate_path_cannot_escape_evaluation_directory(self):
        experiment = self.experiment("auth-bypass-partial")
        experiment["candidate"] = "../outside.py"
        report = self.run_one(experiment)
        self.assertEqual(report["status"], "error")
        self.assertIn("relative Python source path", report["experiments"][0]["reason"])

    def test_malformed_manifest_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ('{"schema_version":1,"schema_version":1}',
                          '{"schema_version":1,"title":"Empty","experiments":[]}'):
                with self.subTest(value=value):
                    (root / "manifest.json").write_text(value)
                    report = run_benchmark(LABS, root)
                    self.assertEqual(report["status"], "error")
                    self.assertEqual(report["metrics"]["rejected_bad"], 0)
                    self.assertEqual(report["experiments"], [])

    def test_reports_keep_scope_hashes_and_complete_json_evidence(self):
        markdown = render_benchmark_markdown(self.report)
        self.assertIn("neither a held-out", markdown)
        self.assertIn("insecure-deserialization-load-then-deny", markdown)
        self.assertIn("Candidate SHA-256", markdown)
        decoded = json.loads(json.dumps(self.report, allow_nan=False))
        self.assertEqual(len(decoded["experiments"]), 17)
        self.assertIn("unified_diff", decoded["experiments"][0]["result"]["diff"])


if __name__ == "__main__":
    unittest.main()
