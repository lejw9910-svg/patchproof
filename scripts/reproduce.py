"""Reproduce local test and benchmark evidence; never invokes a model or network API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from patchproof.benchmark import render_benchmark_markdown, run_benchmark
from patchproof.evidence import create_bundle, verify_bundle
from patchproof.report import render_json, render_markdown
from patchproof.research import prepare_packet
from patchproof.verifier import discover_labs, json_equal, verify_labs


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("reports/application"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    print("Running unit, negative-control, and end-to-end tests...", flush=True)
    with (output / "tests.txt").open("w", encoding="utf-8") as transcript:
        completed = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                                   cwd=root, stdout=transcript, stderr=subprocess.STDOUT, check=False)
    if completed.returncode:
        print(f"Tests failed; inspect {output / 'tests.txt'}", file=sys.stderr)
        return completed.returncode
    print("Verifying the reference patches and capturing source evidence...", flush=True)
    labs = discover_labs(root / "labs")
    report = verify_labs(labs)
    (output / "verification.json").write_text(render_json(report), encoding="utf-8")
    (output / "verification.md").write_text(render_markdown(report), encoding="utf-8")
    create_bundle(report, labs, output / "evidence.zip")
    integrity = verify_bundle(output / "evidence.zip")
    write_json(output / "integrity.json", integrity)
    print("Evaluating the declared good and faulty candidate patches...", flush=True)
    benchmark = run_benchmark(root / "labs", root / "evaluation")
    write_json(output / "benchmark.json", benchmark)
    (output / "benchmark.md").write_text(render_benchmark_markdown(benchmark), encoding="utf-8")
    comparison = next((item for item in benchmark["experiments"]
                       if item["id"] == "insecure-deserialization-load-then-deny"), None)
    if comparison and comparison["result"]:
        result = comparison["result"]
        case_comparison = []
        for case in result["cases"]:
            output_only_pass = (
                case["vulnerable"]["status"] == case["patched"]["status"] == "ok"
                and json_equal(case["vulnerable"]["value"], case["expected_vulnerable"])
                and json_equal(case["patched"]["value"], case["expected_patched"])
            )
            case_comparison.append({
                "id": case["id"], "kind": case["kind"],
                "output_only_would_pass": output_only_pass,
                "observed_verdict": case["status"],
                "patched_observations": case["patched"]["observations"],
                "expected_patched_observations": case["expected_patched_observations"],
            })
        write_json(output / "case-study.json", {
            "schema_version": 1,
            "experiment": comparison["id"],
            "interpretation": "Counterfactual output-only comparison of these same observed executions, not a historical run or model experiment.",
            "manifest_sha256": result["manifest_sha256"],
            "candidate_sha256": result["diff"]["after_sha256"],
            "output_only_would_pass": all(case["output_only_would_pass"] for case in case_comparison),
            "observed_status": result["status"],
            "cases": case_comparison,
        })
    selected = next(lab for lab in labs if lab.id == "insecure-deserialization")
    write_json(output / "claude-packet.json", prepare_packet(selected))
    summary = {
        "schema_version": 1,
        "status": "pass" if report.status == "pass" and benchmark["status"] == "pass" else "fail",
        "tests_exit_code": completed.returncode,
        "verification_status": report.status,
        "lab_count": len(labs),
        "case_count": sum(len(lab.cases) for lab in labs),
        "attack_cases": sum(case.kind == "attack" for lab in labs for case in lab.cases),
        "regression_cases": sum(case.kind == "regression" for lab in labs for case in lab.cases),
        "benchmark_status": benchmark["status"],
        "benchmark_metrics": benchmark.get("metrics", {}),
        "evidence_integrity": integrity,
        "claude_run_performed": False,
        "scope": "Local curated synthetic evidence; no third-party vulnerability finding, hosted CI run, model evaluation, or CVP approval is claimed.",
    }
    write_json(output / "summary.json", summary)
    print(f"{summary['status'].upper()}: evidence written to {output}", flush=True)
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
