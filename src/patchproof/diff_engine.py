"""Deterministic UTF-8 source diffs with hashes of the original file bytes."""

from __future__ import annotations

from dataclasses import dataclass
import difflib
import hashlib
from pathlib import Path


@dataclass(frozen=True)
class SourceDiff:
    before_sha256: str
    after_sha256: str
    unified_diff: str
    changed: bool


def _lines(text: str) -> list[str]:
    # Treat LF as the separator, preserving CRLF and all other source bytes.
    parts = text.split("\n")
    return [part + "\n" for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def compare_files(before: Path, after: Path) -> SourceDiff:
    """Compare UTF-8 files, including a missing final newline; I/O errors propagate."""
    before_bytes = Path(before).read_bytes()
    after_bytes = Path(after).read_bytes()
    before_text = before_bytes.decode("utf-8")
    after_text = after_bytes.decode("utf-8")
    output: list[str] = []
    for line in difflib.unified_diff(
        _lines(before_text),
        _lines(after_text),
        fromfile="vulnerable.py",
        tofile="patched.py",
        lineterm="\n",
    ):
        output.append(line)
        if not line.endswith("\n"):
            output.append("\n\\ No newline at end of file\n")
    return SourceDiff(
        before_sha256=hashlib.sha256(before_bytes).hexdigest(),
        after_sha256=hashlib.sha256(after_bytes).hexdigest(),
        unified_diff="".join(output),
        changed=before_bytes != after_bytes,
    )
