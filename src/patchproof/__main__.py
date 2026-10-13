"""Command-line entry point; all verification targets are trusted local fixtures."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import math
from pathlib import Path
import sys

from . import __version__
from .analyzer import analyze_file
from .diff_engine import compare_files
from .evidence import create_bundle, verify_bundle
from .research import prepare_packet
from .report import render_json, render_markdown
from .verifier import ManifestError, discover_labs, verify_labs


def _positive_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive finite number") from exc
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return result


def _positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if result <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def _default_labs() -> Path:
    local = Path.cwd() / "labs"
    if local.is_dir():
        return local
    return Path(__file__).resolve().parents[2] / "labs"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify patches against trusted local vulnerability fixtures.")
    parser.add_argument("--version", action="version", version=f"patchproof {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="validate and list available local labs")
    listing.add_argument("--labs-dir", type=Path, default=_default_labs())
    verify = commands.add_parser("verify", help="compare baseline, patch, and functional controls")
    verify.add_argument("--labs-dir", type=Path, default=_default_labs(), help="trusted lab root (default: repository labs)")
    verify.add_argument("--lab", action="append", default=[], help="lab identifier; repeat to select several")
    verify.add_argument("--candidate", type=Path, help="reviewed, trusted replacement Python source; requires exactly one --lab")
    verify.add_argument("--bundle", type=Path, help="also write a checksum-verified source and evidence ZIP")
    verify.add_argument("--timeout", type=_positive_float, default=2.0, help="seconds per case and version (default: 2)")
    verify.add_argument("--max-output-bytes", type=_positive_int, default=65_536,
                        help="combined output limit per execution (default: 65536)")
    verify.add_argument("--format", choices=("markdown", "json"), default="markdown")
    verify.add_argument("--output", type=Path, help="write a report file instead of stdout")
    analyze = commands.add_parser("analyze", help="show advisory AST findings; does not execute source")
    analyze.add_argument("path", type=Path)
    diff = commands.add_parser("diff", help="show source hashes and a unified diff")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    prepare = commands.add_parser("prepare", help="prepare an offline Claude review packet; sends no data")
    prepare.add_argument("--labs-dir", type=Path, default=_default_labs())
    prepare.add_argument("--lab", required=True, help="one lab identifier")
    prepare.add_argument("--objective", help="public repair objective; required for custom labs")
    prepare.add_argument("--output", type=Path)
    benchmark = commands.add_parser("benchmark", help="evaluate correct and intentionally faulty patches")
    benchmark.add_argument("--labs-dir", type=Path, default=_default_labs())
    benchmark.add_argument("--evaluation-dir", type=Path, default=_default_labs().parent / "evaluation")
    benchmark.add_argument("--timeout", type=_positive_float, default=2.0)
    benchmark.add_argument("--max-output-bytes", type=_positive_int, default=65_536)
    benchmark.add_argument("--format", choices=("markdown", "json"), default="markdown")
    benchmark.add_argument("--output", type=Path)
    check = commands.add_parser("check-bundle", help="check evidence ZIP integrity without extracting or executing it")
    check.add_argument("path", type=Path)
    return parser


def _emit(rendered: str, output: Path | None, status: str) -> None:
    if output is None:
        print(rendered, end="")
        return
    encoded = rendered.encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Encode before opening so invalid text cannot truncate an existing report.
    output.write_bytes(encoded)
    print(f"{status.upper()}: wrote {output}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check-bundle":
            print(json.dumps(verify_bundle(args.path), indent=2, allow_nan=False))
            return 0
        if args.command == "benchmark":
            from .benchmark import run_benchmark, render_benchmark_markdown
            data = run_benchmark(args.labs_dir, args.evaluation_dir, timeout=args.timeout,
                                 max_output_bytes=args.max_output_bytes)
            rendered = (json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
                        if args.format == "json" else render_benchmark_markdown(data))
            _emit(rendered, args.output, data["status"])
            return {"pass": 0, "fail": 1, "inconclusive": 2, "error": 2}[data["status"]]
        if args.command == "analyze":
            findings = analyze_file(args.path)
            print(json.dumps({"advisory_only": True, "findings": [asdict(item) for item in findings]}, indent=2))
            return 0
        if args.command == "diff":
            result = compare_files(args.before, args.after)
            print(f"Baseline SHA-256: {result.before_sha256}\nPatched SHA-256:  {result.after_sha256}")
            print(result.unified_diff or "(identical source files)", end="" if result.unified_diff else "\n")
            return 0
        labs = discover_labs(args.labs_dir)
        if args.command == "list":
            for lab in labs:
                print(f"{lab.id}\t{lab.cwe}\t{len(lab.cases)} cases\t{lab.title}")
            return 0
        if args.command == "prepare":
            matches = [lab for lab in labs if lab.id == args.lab]
            if not matches:
                raise ManifestError(f"Unknown lab: {args.lab}")
            packet = prepare_packet(matches[0], objective=args.objective)
            _emit(json.dumps(packet, indent=2, ensure_ascii=True, allow_nan=False) + "\n", args.output, "prepared locally")
            return 0
        if args.lab:
            unknown = set(args.lab) - {lab.id for lab in labs}
            if unknown:
                raise ManifestError(f"Unknown labs: {', '.join(sorted(unknown))}")
            labs = tuple(lab for lab in labs if lab.id in args.lab)
        if args.candidate is not None and (len(args.lab) != 1 or len(labs) != 1):
            raise ManifestError("--candidate requires exactly one --lab")
        if args.output and args.bundle and args.output.resolve() == args.bundle.resolve():
            raise ValueError("Report and evidence bundle must have different destinations")
        report = verify_labs(labs, timeout=args.timeout, max_output_bytes=args.max_output_bytes,
                             candidate=args.candidate)
        rendered = render_json(report) if args.format == "json" else render_markdown(report)
        if args.bundle:
            create_bundle(report, labs, args.bundle, candidate=args.candidate)
            print(f"Evidence bundle: {args.bundle}", file=sys.stderr)
        _emit(rendered, args.output, report.status)
        return {"pass": 0, "fail": 1, "inconclusive": 2, "error": 2}[report.status]
    except (OSError, ValueError, SyntaxError, RecursionError) as exc:
        print(f"patchproof: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("patchproof: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
