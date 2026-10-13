"""Validate lab manifests and compare baseline, patch, and functional controls.

Expectations are supplied by the lab author, not inferred from a process exit
code. A successful run establishes only the behavior declared by that corpus.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
import tempfile
from typing import Any

from .analyzer import Finding, analyze_file
from .diff_engine import SourceDiff, compare_files
from .provenance import collect_run_metadata
from .sandbox import ExecutionResult, run_case


class ManifestError(ValueError):
    """A local lab does not satisfy the verification contract."""


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    input: Any
    expected_vulnerable: Any
    expected_patched: Any
    expected_vulnerable_observations: dict[str, int] | None = None
    expected_patched_observations: dict[str, int] | None = None


@dataclass(frozen=True)
class Lab:
    id: str
    title: str
    cwe: str
    directory: Path
    manifest_sha256: str
    cases: tuple[Case, ...]


@dataclass(frozen=True)
class CaseResult:
    id: str
    kind: str
    status: str
    reason: str
    input: Any
    expected_vulnerable: Any
    expected_patched: Any
    vulnerable: ExecutionResult
    patched: ExecutionResult
    expected_vulnerable_observations: dict[str, int] | None = None
    expected_patched_observations: dict[str, int] | None = None


@dataclass(frozen=True)
class LabResult:
    id: str
    title: str
    cwe: str
    status: str
    manifest_sha256: str
    diff: SourceDiff
    findings: dict[str, tuple[Finding, ...]]
    cases: tuple[CaseResult, ...]


@dataclass(frozen=True)
class VerificationReport:
    labs: tuple[LabResult, ...]
    metadata: dict[str, Any] = field(default_factory=collect_run_metadata)

    @property
    def status(self) -> str:
        return aggregate_status(lab.status for lab in self.labs)


def aggregate_status(statuses) -> str:
    """Errors take precedence; an empty corpus can never pass."""
    values = set(statuses)
    if not values:
        return "inconclusive"
    unknown = values - {"pass", "fail", "inconclusive", "error"}
    if unknown:
        raise ValueError(f"Unknown verification status: {sorted(unknown)}")
    for status in ("error", "fail", "inconclusive", "pass"):
        if status in values:
            return status
    raise AssertionError("unreachable")


def json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's True == 1 coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(json_equal(a, b) for a, b in zip(left, right))
    return left == right


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ManifestError(f"Non-finite JSON number: {value}")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", value):
        raise ManifestError(f"{label} must be a short lowercase identifier")
    return value


def _validate_observations(value: Any, case_id: str) -> None:
    if (not isinstance(value, dict) or not value
            or set(value) - {"pickle_class_resolutions"}
            or any(type(count) is not int or count < 0 for count in value.values())):
        raise ManifestError(
            f"Case {case_id}: observations must be a nonempty object of supported "
            "counters (pickle_class_resolutions) with nonnegative integer values"
        )


def load_lab(directory: Path) -> Lab:
    """Read a strict manifest without importing or executing any fixture code."""
    directory = Path(directory).resolve()
    manifest = directory / "manifest.json"
    try:
        with manifest.open("rb") as handle:
            raw = handle.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ManifestError("Manifest exceeds 1 MiB")
        data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError(f"Cannot read {manifest}: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("Manifest must be a JSON object")
    required = {"schema_version", "id", "title", "cwe", "cases"}
    if set(data) != required:
        raise ManifestError(f"Manifest keys must be exactly: {', '.join(sorted(required))}")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ManifestError("Only manifest schema_version 1 is supported")
    lab_id = _identifier(data["id"], "Lab id")
    if lab_id != directory.name:
        raise ManifestError("Lab id must match its directory name")
    if not isinstance(data["title"], str) or not data["title"].strip() or len(data["title"]) > 200:
        raise ManifestError("Lab title must be a nonempty string of at most 200 characters")
    if not isinstance(data["cwe"], str) or not re.fullmatch(r"CWE-[1-9][0-9]*", data["cwe"]):
        raise ManifestError("Lab cwe must have the form CWE-123")
    for filename in ("vulnerable.py", "patched.py"):
        if not (directory / filename).is_file():
            raise ManifestError(f"Missing lab module: {filename}")
    entries = data["cases"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise ManifestError("Lab must declare between 1 and 256 cases")
    cases = []
    ids = set()
    for entry in entries:
        keys = {"id", "kind", "input", "expected_vulnerable", "expected_patched"}
        observation_keys = {"expected_vulnerable_observations", "expected_patched_observations"}
        if not isinstance(entry, dict) or set(entry) not in (keys, keys | observation_keys):
            raise ManifestError(
                f"Each case requires: {', '.join(sorted(keys))}; "
                "observation expectations must be supplied for both versions or neither"
            )
        case_id = _identifier(entry["id"], "Case id")
        if case_id in ids:
            raise ManifestError(f"Duplicate case id: {case_id}")
        ids.add(case_id)
        kind = entry["kind"]
        if kind not in ("attack", "regression"):
            raise ManifestError(f"Case {case_id}: kind must be attack or regression")
        if observation_keys <= set(entry):
            for key in observation_keys:
                _validate_observations(entry[key], case_id)
            if entry["expected_vulnerable_observations"].keys() != entry["expected_patched_observations"].keys():
                raise ManifestError(f"Case {case_id}: both versions must declare the same observation keys")
        same = (
            json_equal(entry["expected_vulnerable"], entry["expected_patched"])
            and json_equal(entry.get("expected_vulnerable_observations"), entry.get("expected_patched_observations"))
        )
        if kind == "attack" and same:
            raise ManifestError(f"Attack {case_id} must expect different baseline and patched behavior")
        if kind == "regression" and not same:
            raise ManifestError(f"Regression {case_id} must preserve the same expected behavior")
        # Round-trip validation also rejects numeric overflow such as 1e999.
        try:
            encoded = json.dumps(entry, allow_nan=False)
        except (ValueError, RecursionError) as exc:
            raise ManifestError(f"Case {case_id}: invalid JSON value") from exc
        if len(encoded.encode("utf-8")) > 65_536:
            raise ManifestError(f"Case {case_id} exceeds 64 KiB")
        cases.append(Case(**entry))
    if {case.kind for case in cases} != {"attack", "regression"}:
        raise ManifestError("Each lab needs both attack cases and regression controls")
    return Lab(lab_id, data["title"], data["cwe"], directory, hashlib.sha256(raw).hexdigest(), tuple(cases))


def discover_labs(directory: Path) -> tuple[Lab, ...]:
    directory = Path(directory)
    if not directory.is_dir():
        raise ManifestError(f"Labs directory does not exist: {directory}")
    manifests = sorted(directory.glob("*/manifest.json"))
    if not manifests:
        raise ManifestError(f"No lab manifests found under {directory}")
    return tuple(load_lab(manifest.parent) for manifest in manifests)


def evaluate_case(case: Case, vulnerable: ExecutionResult, patched: ExecutionResult) -> CaseResult:
    """Classify observations; crashes and missing baselines never prove a fix."""
    def matches(execution: ExecutionResult, value: Any, observations: dict[str, int] | None) -> bool:
        return json_equal(execution.value, value) and (
            observations is None or all(
                key in execution.observations and json_equal(execution.observations[key], expected)
                for key, expected in observations.items()
            )
        )

    baseline_matches = matches(vulnerable, case.expected_vulnerable, case.expected_vulnerable_observations)
    patch_matches = matches(patched, case.expected_patched, case.expected_patched_observations)
    if vulnerable.status != "ok" or patched.status != "ok":
        status = "error"
        reason = f"Execution error (baseline: {vulnerable.status}; patched: {patched.status})."
    elif case.kind == "attack" and not baseline_matches:
        status = "inconclusive"
        reason = "Baseline did not reproduce the declared vulnerable behavior."
    elif case.kind == "regression" and not baseline_matches:
        status = "fail"
        reason = "Baseline failed the functional control."
    elif not patch_matches:
        status = "fail"
        reason = ("Patch did not match the declared response and observations." if case.kind == "attack"
                  else "Patch failed the functional control.")
    else:
        status = "pass"
        reason = ("Baseline reproduced; patch matched the declared response and observations." if case.kind == "attack"
                  else "Functional behavior preserved on both versions.")
    return CaseResult(case.id, case.kind, status, reason, case.input,
                      case.expected_vulnerable, case.expected_patched, vulnerable, patched,
                      case.expected_vulnerable_observations, case.expected_patched_observations)


def _revalidate_lab(lab: Lab) -> Lab:
    """Bind execution to fresh cases with the originally loaded manifest hash.

    Frozen dataclasses do not freeze nested JSON dictionaries. Reject changes
    to the file or loaded case values, then use a fresh, unshared parsed copy.
    """
    fresh = load_lab(lab.directory)
    if fresh.manifest_sha256 != lab.manifest_sha256:
        raise ManifestError(f"Lab {lab.id}: manifest changed since it was loaded")

    def semantics(value: Lab) -> dict[str, Any]:
        return {"id": value.id, "title": value.title, "cwe": value.cwe,
                "cases": [asdict(case) for case in value.cases]}

    try:
        unchanged = json_equal(semantics(lab), semantics(fresh))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ManifestError(f"Lab {lab.id}: loaded manifest data was mutated") from exc
    if not unchanged:
        raise ManifestError(f"Lab {lab.id}: loaded manifest data was mutated")
    return fresh


def verify_lab(lab: Lab, *, timeout: float = 2.0, max_output_bytes: int = 65_536,
               candidate: Path | None = None) -> LabResult:
    """Verify snapshots of trusted fixtures or a reviewed external patch candidate."""
    lab = _revalidate_lab(lab)
    with tempfile.TemporaryDirectory(prefix="patchproof-sources-") as temporary:
        snapshot = Path(temporary)
        for filename in ("vulnerable.py", "patched.py"):
            source = Path(candidate) if filename == "patched.py" and candidate is not None else lab.directory / filename
            (snapshot / filename).write_bytes(source.read_bytes())
        vulnerable_path = snapshot / "vulnerable.py"
        patched_path = snapshot / "patched.py"
        diff = compare_files(vulnerable_path, patched_path)
        findings = {
            "vulnerable": tuple(analyze_file(vulnerable_path)),
            "patched": tuple(analyze_file(patched_path)),
        }
        results = tuple(
            evaluate_case(
                case,
                run_case(vulnerable_path, case.input, timeout=timeout, max_output_bytes=max_output_bytes),
                run_case(patched_path, case.input, timeout=timeout, max_output_bytes=max_output_bytes),
            )
            for case in lab.cases
        )
    return LabResult(lab.id, lab.title, lab.cwe, aggregate_status(case.status for case in results),
                     lab.manifest_sha256, diff, findings, results)


def verify_labs(labs: tuple[Lab, ...], *, timeout: float = 2.0,
                max_output_bytes: int = 65_536, candidate: Path | None = None) -> VerificationReport:
    if not labs:
        raise ManifestError("Cannot verify an empty corpus")
    if candidate is not None and len(labs) != 1:
        raise ManifestError("A candidate file requires exactly one selected lab")
    metadata = collect_run_metadata(timeout=timeout, max_output_bytes=max_output_bytes)
    return VerificationReport(
        tuple(verify_lab(lab, timeout=timeout, max_output_bytes=max_output_bytes, candidate=candidate)
              for lab in labs), metadata=metadata,
    )
