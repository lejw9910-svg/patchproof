"""Evaluate the verifier against a declared, curated local mutation corpus.

These experiments measure agreement with known fixture expectations. They are
not held-out tests, a model comparison, or evidence of real-world generalization.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import html
import json
import math
from pathlib import Path, PurePosixPath
import re

from . import __version__
from .provenance import collect_run_metadata
from .verifier import Lab, json_equal, load_lab, verify_lab


SCOPE = (
    "Curated synthetic mutation checks over the same four local lab corpora. "
    "Candidates and expectations were authored together; this is neither a held-out "
    "evaluation nor a measure of model performance or real-world patch correctness. "
    "A rejection is credited only after complete executions, reproduced baselines, "
    "and all declared checks. Errors and inconclusive evidence never count as detections. "
    "The runner and audit observations are not a hostile-code security boundary."
)


class BenchmarkError(ValueError):
    """The declared evaluation cannot be run as a valid experiment."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"Duplicate evaluation JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise BenchmarkError(f"Non-finite evaluation JSON number: {value}")


def _identifier(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", value):
        raise BenchmarkError(f"{label} must be a short lowercase identifier")
    return value


def _case_ids(value, label):
    if not isinstance(value, list) or len(value) > 256:
        raise BenchmarkError(f"{label} must be a list of case identifiers")
    result = [_identifier(item, label) for item in value]
    if len(set(result)) != len(result):
        raise BenchmarkError(f"{label} contains duplicate case identifiers")
    return result


def _read_manifest(directory: Path):
    with (directory / "manifest.json").open("rb") as handle:
        raw = handle.read(1_048_577)
    if len(raw) > 1_048_576:
        raise BenchmarkError("Evaluation manifest exceeds 1 MiB")
    data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(data, dict) or set(data) != {"schema_version", "title", "experiments"}:
        raise BenchmarkError("Evaluation keys must be schema_version, title, and experiments")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise BenchmarkError("Only evaluation schema_version 1 is supported")
    if not isinstance(data["title"], str) or not 1 <= len(data["title"].strip()) <= 200:
        raise BenchmarkError("Evaluation title must be a nonempty string of at most 200 characters")
    experiments = data["experiments"]
    if not isinstance(experiments, list) or not 1 <= len(experiments) <= 256:
        raise BenchmarkError("Evaluation must contain between 1 and 256 experiments")
    ids = set()
    for entry in experiments:
        required = {"id", "lab_id", "source", "expected_outcome", "description",
                    "required_safe_response_cases", "required_fail_cases"}
        if not isinstance(entry, dict) or not required <= set(entry) or set(entry) - required - {"candidate"}:
            raise BenchmarkError("Experiment contains missing or unknown keys")
        identifier = _identifier(entry["id"], "Experiment id")
        if identifier in ids:
            raise BenchmarkError(f"Duplicate experiment id: {identifier}")
        ids.add(identifier)
        _identifier(entry["lab_id"], "Experiment lab_id")
        if not isinstance(entry["description"], str) or not 1 <= len(entry["description"].strip()) <= 1000:
            raise BenchmarkError(f"{identifier}: description must be a nonempty short string")
        source = entry["source"]
        if source not in ("reference", "baseline", "candidate"):
            raise BenchmarkError(f"{identifier}: invalid source selection")
        if (source == "candidate") != ("candidate" in entry):
            raise BenchmarkError(f"{identifier}: only candidate sources require a candidate path")
        expected = entry["expected_outcome"]
        if expected not in ("pass", "fail"):
            raise BenchmarkError(f"{identifier}: expected_outcome must be pass or fail")
        if source == "reference" and expected != "pass":
            raise BenchmarkError(f"{identifier}: a known-good reference must expect pass")
        if source == "baseline" and expected != "fail":
            raise BenchmarkError(f"{identifier}: an unchanged baseline must expect fail")
        safe = _case_ids(entry["required_safe_response_cases"], "required_safe_response_cases")
        failures = _case_ids(entry["required_fail_cases"], "required_fail_cases")
        if expected == "fail" and not failures:
            raise BenchmarkError(f"{identifier}: negative experiments need a targeted failing check")
        if expected == "pass" and failures:
            raise BenchmarkError(f"{identifier}: known-good experiments cannot require failed checks")
        if source == "candidate" and expected == "fail" and not safe:
            raise BenchmarkError(f"{identifier}: negative mutations need a declared safe attack response")
    return data, hashlib.sha256(raw).hexdigest()


def _candidate_path(entry, lab: Lab, evaluation_dir: Path) -> Path:
    if entry["source"] == "reference":
        return lab.directory / "patched.py"
    if entry["source"] == "baseline":
        return lab.directory / "vulnerable.py"
    value = entry["candidate"]
    if not isinstance(value, str) or not value or "\\" in value:
        raise BenchmarkError("Candidate must be a relative POSIX path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".py":
        raise BenchmarkError("Candidate must be a contained relative Python source path")
    path = (evaluation_dir / value).resolve()
    try:
        path.relative_to(evaluation_dir)
    except ValueError as exc:
        raise BenchmarkError("Candidate resolves outside the evaluation directory") from exc
    if not path.is_file():
        raise BenchmarkError(f"Candidate does not exist: {value}")
    return path


def _baseline_matches(expected, observed) -> bool:
    if not json_equal(observed.vulnerable.value, expected.expected_vulnerable):
        return False
    required = getattr(expected, "expected_vulnerable_observations", None)
    if required is None:
        return True
    actual = getattr(observed.vulnerable, "observations", None)
    return isinstance(actual, dict) and all(
        key in actual and json_equal(value, actual[key]) for key, value in required.items()
    )


def _assess(entry, lab: Lab, result):
    cases = {case.id: case for case in result.cases}
    expected = {case.id: case for case in lab.cases}
    if len(cases) != len(result.cases) or cases.keys() != expected.keys():
        return "error", {}, "Verifier returned incomplete or duplicate case evidence"
    safe_checks = {
        identifier: cases[identifier].patched.status == "ok"
        and json_equal(cases[identifier].patched.value, expected[identifier].expected_patched)
        for identifier in entry["required_safe_response_cases"]
    }
    failing_checks = {
        identifier: cases[identifier].status == "fail"
        for identifier in entry["required_fail_cases"]
    }
    checks = {"safe_responses": safe_checks, "failing_cases": failing_checks}
    if result.status == "error" or any(
        case.status == "error" or case.vulnerable.status != "ok" or case.patched.status != "ok"
        for case in cases.values()
    ):
        return "error", checks, "Execution or observation error; no rejection credited"
    for identifier, case in cases.items():
        for version in ("vulnerable", "patched"):
            required = getattr(expected[identifier], f"expected_{version}_observations", None)
            if required is not None:
                actual = getattr(getattr(case, version), "observations", None)
                if not isinstance(actual, dict) or any(
                    key not in actual or type(actual[key]) is not int or actual[key] < 0
                    for key in required
                ):
                    return "error", checks, "Required independent observation is missing or malformed"
    if result.status == "inconclusive" or any(
        case.status == "inconclusive" or not _baseline_matches(expected[case.id], case)
        for case in cases.values()
    ):
        return "inconclusive", checks, "Baseline evidence was not reproduced; no rejection credited"
    if result.status not in ("pass", "fail") or any(case.status not in ("pass", "fail") for case in cases.values()):
        return "error", checks, "Verifier returned an unknown outcome"
    if result.status != entry["expected_outcome"]:
        classification = "false_acceptance" if entry["expected_outcome"] == "fail" else "false_rejection"
        return classification, checks, "Observed classification differs from the declared expectation"
    if not all(safe_checks.values()) or not all(failing_checks.values()):
        return "check_mismatch", checks, "Classification matched, but a declared experiment check did not"
    category = "accepted_good" if entry["expected_outcome"] == "pass" else "rejected_bad"
    return category, checks, "Classification and all declared checks matched"


def run_benchmark(labs_dir: Path, evaluation_dir: Path, *, timeout: float = 2.0,
                  max_output_bytes: int = 65_536) -> dict:
    """Run trusted local candidates; return evidence even for configuration errors."""
    metrics = {key: 0 for key in (
        "experiments", "expected_good", "expected_bad", "accepted_good", "rejected_bad",
        "false_acceptances", "false_rejections", "errors", "inconclusive", "check_mismatches",
    )}
    report = {"schema_version": 1, "tool": "patchproof", "version": __version__,
              "status": "error", "scope": SCOPE, "metadata": {},
              "evaluation_manifest_sha256": None, "metrics": metrics, "experiments": []}
    try:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise BenchmarkError("timeout must be a positive finite number")
        if type(max_output_bytes) is not int or max_output_bytes <= 0:
            raise BenchmarkError("max_output_bytes must be a positive integer")
        report["metadata"] = collect_run_metadata(timeout=timeout, max_output_bytes=max_output_bytes)
        labs_dir, evaluation_dir = Path(labs_dir).resolve(), Path(evaluation_dir).resolve()
        manifest, digest = _read_manifest(evaluation_dir)
        report.update(title=manifest["title"], evaluation_manifest_sha256=digest)
        experiments = manifest["experiments"]
    except (OSError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        metrics["errors"] = 1
        report["error"] = f"Invalid evaluation configuration: {exc}"
        return report

    metrics["experiments"] = len(experiments)
    metrics["expected_good"] = sum(item["expected_outcome"] == "pass" for item in experiments)
    metrics["expected_bad"] = len(experiments) - metrics["expected_good"]
    labs = {}
    categories = {"accepted_good": "accepted_good", "rejected_bad": "rejected_bad",
                  "false_acceptance": "false_acceptances", "false_rejection": "false_rejections",
                  "error": "errors", "inconclusive": "inconclusive", "check_mismatch": "check_mismatches"}
    for entry in experiments:
        experiment = {**entry, "observed_outcome": None, "classification": "error",
                      "intended_checks": {}, "result": None}
        try:
            lab_id = entry["lab_id"]
            if lab_id not in labs:
                labs[lab_id] = load_lab(labs_dir / lab_id)
            lab = labs[lab_id]
            case_map = {case.id: case for case in lab.cases}
            for identifier in entry["required_safe_response_cases"] + entry["required_fail_cases"]:
                if identifier not in case_map:
                    raise BenchmarkError(f"Declared check names unknown case: {identifier}")
            if any(case_map[identifier].kind != "attack" for identifier in entry["required_safe_response_cases"]):
                raise BenchmarkError("Safe-response checks must identify attack cases")
            candidate = _candidate_path(entry, lab, evaluation_dir)
            result = verify_lab(lab, candidate=candidate, timeout=timeout, max_output_bytes=max_output_bytes)
            experiment["result"] = asdict(result)
            experiment["observed_outcome"] = result.status
            category, checks, reason = _assess(entry, lab, result)
            experiment.update(classification=category, intended_checks=checks, reason=reason)
        except (OSError, ValueError, TypeError, SyntaxError, RecursionError) as exc:
            experiment.update(classification="error", reason=f"Experiment could not complete: {exc}")
        metrics[categories[experiment["classification"]]] += 1
        experiment["status"] = (
            "pass" if experiment["classification"] in ("accepted_good", "rejected_bad") else
            "error" if experiment["classification"] == "error" else "fail"
        )
        report["experiments"].append(experiment)
    if metrics["errors"]:
        report["status"] = "error"
    elif metrics["accepted_good"] + metrics["rejected_bad"] == len(experiments):
        report["status"] = "pass"
    else:
        report["status"] = "fail"
    return report


def _text(value) -> str:
    value = str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")
    value = html.escape(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)


def render_benchmark_markdown(data: dict) -> str:
    """Render classifications and intended-check evidence without rate claims."""
    metrics = data["metrics"]
    lines = ["# Patchproof curated mutation evaluation", "", f"**Overall: {data['status'].upper()}**", "",
             data["scope"], "", f"- Accepted reference patches: {metrics['accepted_good']} / {metrics['expected_good']}",
             f"- Rejected negative candidates: {metrics['rejected_bad']} / {metrics['expected_bad']}",
             f"- False acceptances: {metrics['false_acceptances']}; false rejections: {metrics['false_rejections']}",
             f"- Errors: {metrics['errors']}; inconclusive: {metrics['inconclusive']}; check mismatches: {metrics['check_mismatches']}", ""]
    if data.get("error"):
        lines.extend([_text(data["error"]), ""])
    if data.get("evaluation_manifest_sha256"):
        lines.extend([f"Evaluation manifest SHA-256: `{data['evaluation_manifest_sha256']}`", ""])
    lines.extend(["| Experiment | Expected | Observed | Classification | Intended checks |",
                  "| --- | --- | --- | --- | --- |"])
    for experiment in data["experiments"]:
        checks = experiment["intended_checks"]
        values = [value for group in checks.values() for value in group.values()]
        checks_text = f"{sum(values)} / {len(values)}" if checks else "unavailable"
        lines.append(f"| `{experiment['id']}` | {experiment['expected_outcome']} | "
                     f"{experiment['observed_outcome'] or 'unavailable'} | "
                     f"{_text(experiment['classification'])} | {checks_text} |")
    for experiment in data["experiments"]:
        lines.extend(["", "<details>", f"<summary>{_text(experiment['id'])}</summary>", "",
                      _text(experiment["description"]), "", _text(experiment["reason"]), ""])
        result = experiment["result"]
        if result:
            lines.extend([f"- Lab manifest SHA-256: `{result['manifest_sha256']}`",
                          f"- Baseline SHA-256: `{result['diff']['before_sha256']}`",
                          f"- Candidate SHA-256: `{result['diff']['after_sha256']}`", "",
                          "| Case | Verdict | Reason |", "| --- | --- | --- |"])
            for case in result["cases"]:
                lines.append(f"| `{case['id']}` | {case['status']} | {_text(case['reason'])} |")
        lines.extend(["", "</details>"])
    return "\n".join(lines) + "\n"
