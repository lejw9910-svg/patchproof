"""Guard against false claims of successful patch verification."""

import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from patchproof.sandbox import ExecutionResult
from patchproof.verifier import (
    Case, ManifestError, aggregate_status, evaluate_case, json_equal, load_lab,
    verify_lab, verify_labs,
)


def manifest():
    return {
        "schema_version": 1, "id": "example", "title": "Example", "cwe": "CWE-22",
        "cases": [
            {"id": "escape", "kind": "attack", "input": {"attack": True},
             "expected_vulnerable": {"status": "vulnerable"}, "expected_patched": {"status": "rejected"}},
            {"id": "normal", "kind": "regression", "input": {"attack": False},
             "expected_vulnerable": {"status": "ok"}, "expected_patched": {"status": "ok"}},
        ],
    }


class OutcomeTests(unittest.TestCase):
    def test_attack_outcome_matrix(self):
        case = Case("attack", "attack", {}, {"allowed": True}, {"allowed": False})
        ok = lambda value: ExecutionResult("ok", value, returncode=0)
        scenarios = [
            (ok({"allowed": True}), ok({"allowed": False}), "pass"),
            (ok({"allowed": True}), ok({"allowed": True}), "fail"),
            (ok({"allowed": False}), ok({"allowed": False}), "inconclusive"),
            (ok({"allowed": True}), ok({"error": "unrelated"}), "fail"),
            (ok({"allowed": True}), ExecutionResult("error"), "error"),
            (ExecutionResult("timeout"), ok({"allowed": False}), "error"),
            (ok({"allowed": True}), ExecutionResult("output_limit"), "error"),
        ]
        for baseline, patched, expected in scenarios:
            with self.subTest(expected=expected, baseline=baseline, patched=patched):
                self.assertEqual(evaluate_case(case, baseline, patched).status, expected)

    def test_regression_must_work_on_both_versions(self):
        case = Case("normal", "regression", {}, ["record"], ["record"])
        for baseline, patched, expected in [(["record"], ["record"], "pass"),
                                             ([], ["record"], "fail"),
                                             (["record"], [], "fail")]:
            with self.subTest(baseline=baseline, patched=patched):
                result = evaluate_case(case, ExecutionResult("ok", baseline), ExecutionResult("ok", patched))
                self.assertEqual(result.status, expected)

    def test_observations_prevent_a_matching_denial_from_proving_a_fix(self):
        case = Case("attack", "attack", {}, "rejected", "rejected",
                    {"pickle_class_resolutions": 1}, {"pickle_class_resolutions": 0})
        def observed(count):
            return ExecutionResult("ok", "rejected", observations={"pickle_class_resolutions": count})
        for baseline, patched, expected in [(1, 0, "pass"), (1, 1, "fail"), (0, 0, "inconclusive")]:
            with self.subTest(baseline=baseline, patched=patched):
                result = evaluate_case(case, observed(baseline), observed(patched))
                self.assertEqual(result.status, expected)
                self.assertEqual(result.expected_patched_observations, {"pickle_class_resolutions": 0})

    def test_missing_or_coerced_observations_do_not_match(self):
        case = Case("attack", "attack", None, "vulnerable", "rejected",
                    {"pickle_class_resolutions": 1}, {"pickle_class_resolutions": 0})
        baseline = ExecutionResult("ok", "vulnerable", observations={"pickle_class_resolutions": 1})
        for observations in ({}, {"pickle_class_resolutions": False}, {"pickle_class_resolutions": 0.0}):
            with self.subTest(observations=observations):
                patched = ExecutionResult("ok", "rejected", observations=observations)
                self.assertEqual(evaluate_case(case, baseline, patched).status, "fail")

    def test_regression_observations_must_match_on_both_versions(self):
        case = Case("normal", "regression", None, "normal", "normal",
                    {"pickle_class_resolutions": 0}, {"pickle_class_resolutions": 0})
        for baseline, patched, expected in [(0, 0, "pass"), (1, 0, "fail"), (0, 1, "fail")]:
            with self.subTest(baseline=baseline, patched=patched):
                result = evaluate_case(
                    case,
                    ExecutionResult("ok", "normal", observations={"pickle_class_resolutions": baseline}),
                    ExecutionResult("ok", "normal", observations={"pickle_class_resolutions": patched}),
                )
                self.assertEqual(result.status, expected)

    def test_json_comparison_does_not_coerce_security_values(self):
        self.assertFalse(json_equal({"allowed": True}, {"allowed": 1}))
        self.assertFalse(json_equal([1], [1.0]))
        self.assertTrue(json_equal({"a": [True], "b": None}, {"b": None, "a": [True]}))
        case = Case("attack", "attack", None, True, False)
        self.assertEqual(evaluate_case(case, ExecutionResult("ok", True), ExecutionResult("ok", 0)).status, "fail")

    def test_aggregate_requires_evidence_and_preserves_failures(self):
        self.assertEqual(aggregate_status([]), "inconclusive")
        self.assertEqual(aggregate_status(["pass", "inconclusive"]), "inconclusive")
        self.assertEqual(aggregate_status(["fail", "inconclusive"]), "fail")
        self.assertEqual(aggregate_status(["pass", "fail", "error"]), "error")
        with self.assertRaises(ManifestError):
            verify_labs(())


class ManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "example"
        self.directory.mkdir()
        (self.directory / "vulnerable.py").write_text("def run(payload, workspace):\n    return payload\n")
        (self.directory / "patched.py").write_text("def run(payload, workspace):\n    return payload\n")

    def write(self, value):
        (self.directory / "manifest.json").write_text(json.dumps(value), encoding="utf-8")

    def test_valid_manifest_keeps_inputs_and_source_identity(self):
        self.write(manifest())
        lab = load_lab(self.directory)
        self.assertEqual(lab.cases[0].input, {"attack": True})
        self.assertEqual(len(lab.manifest_sha256), 64)

    def test_observations_can_distinguish_otherwise_identical_attack_values(self):
        value = manifest()
        attack = value["cases"][0]
        attack["expected_vulnerable"] = attack["expected_patched"]
        attack["expected_vulnerable_observations"] = {"pickle_class_resolutions": 1}
        attack["expected_patched_observations"] = {"pickle_class_resolutions": 0}
        self.write(value)
        case = load_lab(self.directory).cases[0]
        self.assertEqual(case.expected_vulnerable, case.expected_patched)
        self.assertEqual(case.expected_vulnerable_observations, {"pickle_class_resolutions": 1})

    def test_observation_schema_rejects_invalid_or_one_sided_expectations(self):
        invalid_values = [None, {}, [], {"unknown": 0}, {"pickle_class_resolutions": -1},
                          {"pickle_class_resolutions": True}, {"pickle_class_resolutions": 1.0}]
        for invalid in invalid_values:
            for key in ("expected_vulnerable_observations", "expected_patched_observations"):
                value = manifest()
                value["cases"][0].update(expected_vulnerable_observations={"pickle_class_resolutions": 1},
                                          expected_patched_observations={"pickle_class_resolutions": 0})
                value["cases"][0][key] = invalid
                self.write(value)
                with self.subTest(key=key, invalid=invalid), self.assertRaises(ManifestError):
                    load_lab(self.directory)
        for key in ("expected_vulnerable_observations", "expected_patched_observations"):
            value = manifest()
            value["cases"][0][key] = {"pickle_class_resolutions": 0}
            self.write(value)
            with self.subTest(missing_pair=key), self.assertRaises(ManifestError):
                load_lab(self.directory)

    def test_regression_cannot_change_observations(self):
        value = manifest()
        value["cases"][1].update(expected_vulnerable_observations={"pickle_class_resolutions": 1},
                                  expected_patched_observations={"pickle_class_resolutions": 0})
        self.write(value)
        with self.assertRaises(ManifestError):
            load_lab(self.directory)

    def test_nested_loaded_case_mutation_is_rejected_before_execution(self):
        for field_name in ("input", "expected_vulnerable", "expected_patched"):
            self.write(manifest())
            lab = load_lab(self.directory)
            getattr(lab.cases[0], field_name)["changed"] = "mutated"
            with self.subTest(field=field_name), patch("patchproof.verifier.run_case") as run:
                with self.assertRaisesRegex(ManifestError, "mutated"):
                    verify_lab(lab)
                run.assert_not_called()

    def test_json_coercion_does_not_hide_loaded_mutation(self):
        self.write(manifest())
        lab = load_lab(self.directory)
        lab.cases[0].input["attack"] = 1
        with self.assertRaisesRegex(ManifestError, "mutated"):
            verify_lab(lab)

    def test_loaded_observation_mutation_is_rejected(self):
        value = manifest()
        value["cases"][0].update(expected_vulnerable_observations={"pickle_class_resolutions": 1},
                                  expected_patched_observations={"pickle_class_resolutions": 0})
        self.write(value)
        lab = load_lab(self.directory)
        lab.cases[0].expected_patched_observations["pickle_class_resolutions"] = 1
        with self.assertRaisesRegex(ManifestError, "mutated"):
            verify_lab(lab)

    def test_loaded_metadata_mutation_is_rejected(self):
        self.write(manifest())
        lab = replace(load_lab(self.directory), title="Unrecorded title")
        with self.assertRaisesRegex(ManifestError, "mutated"):
            verify_lab(lab)

    def test_raw_manifest_change_is_rejected_even_if_semantics_match(self):
        self.write(manifest())
        lab = load_lab(self.directory)
        path = self.directory / "manifest.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with patch("patchproof.verifier.run_case") as run:
            with self.assertRaisesRegex(ManifestError, "manifest changed"):
                verify_lab(lab)
            run.assert_not_called()

    def test_missing_attack_or_control_is_rejected(self):
        for index in (0, 1):
            value = manifest()
            value["cases"] = [value["cases"][index]]
            self.write(value)
            with self.subTest(index=index), self.assertRaises(ManifestError):
                load_lab(self.directory)

    def test_ambiguous_expectations_are_rejected(self):
        for index in (0, 1):
            value = manifest()
            value["cases"][index]["expected_patched"] = {"status": "vulnerable"}
            self.write(value)
            with self.subTest(index=index), self.assertRaises(ManifestError):
                load_lab(self.directory)

    def test_invalid_metadata_and_cases_are_rejected(self):
        for key, invalid in [("schema_version", True), ("schema_version", 2),
                             ("id", "../escape"), ("id", "different"), ("title", ""),
                             ("cwe", "22"), ("cases", []), ("cases", "not-a-list")]:
            value = manifest()
            value[key] = invalid
            self.write(value)
            with self.subTest(key=key, invalid=invalid), self.assertRaises(ManifestError):
                load_lab(self.directory)

    def test_duplicate_case_ids_or_json_keys_are_rejected(self):
        value = manifest()
        value["cases"][1]["id"] = value["cases"][0]["id"]
        self.write(value)
        with self.assertRaises(ManifestError):
            load_lab(self.directory)
        path = self.directory / "manifest.json"
        path.write_text(json.dumps(manifest()).replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        with self.assertRaises(ManifestError):
            load_lab(self.directory)

    def test_nonfinite_or_oversized_cases_are_rejected(self):
        for invalid in (float("nan"), float("inf"), "x" * 65_537):
            value = manifest()
            value["cases"][0]["input"] = invalid
            self.write(value)
            with self.subTest(type=type(invalid)), self.assertRaises(ManifestError):
                load_lab(self.directory)
        path = self.directory / "manifest.json"
        path.write_text(json.dumps(manifest()).replace('"attack": true', '"attack": 1e999'))
        with self.assertRaises(ManifestError):
            load_lab(self.directory)

    def test_missing_module_is_rejected_before_execution(self):
        self.write(manifest())
        (self.directory / "patched.py").unlink()
        with self.assertRaises(ManifestError):
            load_lab(self.directory)


if __name__ == "__main__":
    unittest.main()
