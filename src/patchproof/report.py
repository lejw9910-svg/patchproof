"""Portable Markdown and JSON evidence reports."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import html
import json
import re

from . import __version__
from .verifier import VerificationReport


SCOPE = ("Results cover only the declared local cases and author-supplied expectations. "
         "AST findings are advisory. The process runner is not a security isolation boundary.")


def report_dict(report: VerificationReport) -> dict:
    return {
        "schema_version": 1,
        "tool": "patchproof",
        "version": __version__,
        "status": report.status,
        "scope": SCOPE,
        "metadata": report.metadata,
        "labs": [asdict(lab) for lab in report.labs],
    }


def render_json(report: VerificationReport) -> str:
    # JSON may legally contain escaped lone surrogates. Keep evidence escaped
    # so reports remain writable as UTF-8 even for those boundary cases.
    return json.dumps(report_dict(report), indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _text(value: str) -> str:
    value = value.encode("utf-8", errors="backslashreplace").decode("utf-8")
    value = html.escape(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)


def _fence(content: str, language: str = "json") -> str:
    longest = max((len(match.group()) for match in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content.rstrip()}\n{fence}"


def render_markdown(report: VerificationReport) -> str:
    lines = [
        "# Patchproof verification", "",
        f"**Overall: {report.status.upper()}** · Patchproof {__version__}", "",
        SCOPE, "",
        "## Run metadata", "",
        _fence(json.dumps(report.metadata, indent=2, ensure_ascii=True, allow_nan=False)), "",
        "## Results", "",
        "| Lab | CWE | Result | Cases |",
        "| --- | --- | --- | ---: |",
    ]
    for lab in report.labs:
        counts = Counter(case.status for case in lab.cases)
        summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
        lines.append(f"| {_text(lab.title)} | {lab.cwe} | {lab.status.upper()} | {summary} |")
    for lab in report.labs:
        lines.extend([
            "", f"## {_text(lab.title)}", "",
            f"**{lab.status.upper()}** · `{lab.id}` · {lab.cwe}", "",
            f"- Manifest SHA-256: `{lab.manifest_sha256}`",
            f"- Baseline SHA-256: `{lab.diff.before_sha256}`",
            f"- Patched SHA-256: `{lab.diff.after_sha256}`", "",
            "### Cases", "",
            "| Case | Kind | Result | Reason |",
            "| --- | --- | --- | --- |",
        ])
        for case in lab.cases:
            lines.append(f"| `{case.id}` | {case.kind} | {case.status.upper()} | {_text(case.reason)} |")
        lines.extend(["", "### Advisory source findings", ""])
        for version, findings in lab.findings.items():
            if not findings:
                lines.append(f"- {version}: no supported patterns detected; this is not a safety verdict.")
            for finding in findings:
                lines.append(f"- {version}:{finding.line} — {finding.rule_id} ({finding.cwe}): {_text(finding.message)}")
        lines.extend(["", "<details>", "<summary>Case evidence (inputs, expectations, observations)</summary>", ""])
        for case in lab.cases:
            observations = {}
            for version in ("vulnerable", "patched"):
                execution = getattr(case, version)
                observations[version] = {
                    "status": execution.status,
                    "value": execution.value,
                    "returncode": execution.returncode,
                    "observations": execution.observations,
                }
                if execution.stderr:
                    observations[version]["stderr"] = execution.stderr
                if execution.status != "ok" and execution.stdout:
                    observations[version]["stdout"] = execution.stdout
            evidence = {
                "id": case.id,
                "input": case.input,
                "expected_vulnerable": case.expected_vulnerable,
                "expected_patched": case.expected_patched,
                "expected_vulnerable_observations": case.expected_vulnerable_observations,
                "expected_patched_observations": case.expected_patched_observations,
                "observed": observations,
            }
            lines.extend([f"#### `{case.id}`", "", _fence(json.dumps(evidence, indent=2, ensure_ascii=True, allow_nan=False)), ""])
        lines.extend(["</details>", "", "<details>", "<summary>Source diff</summary>", "",
                      _fence(lab.diff.unified_diff or "(identical source files)", "diff"), "", "</details>"])
    return "\n".join(lines) + "\n"

