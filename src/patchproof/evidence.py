"""Portable, unsigned evidence archives; checking never executes their contents.

Checksums detect damage and inconsistent artifacts, not forgery. Someone able
to replace an archive can also replace its checksums and reported observations.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import zipfile
import zlib

from .report import render_json, render_markdown
from .verifier import Lab, VerificationReport, json_equal


MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 256
MAX_MANIFEST_BYTES = 256 * 1024
MANIFEST_NAME = "bundle-manifest.json"
INTEGRITY_WARNING = (
    "Integrity only: this unsigned bundle does not establish authenticity, "
    "authorization, or the truth of its reported observations."
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LAB_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}\Z")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: object) -> str:
    if not isinstance(name, str) or not name or len(name) > 512:
        raise ValueError("Bundle member names must be nonempty relative paths")
    if "\\" in name or ":" in name or any(ord(char) < 32 for char in name):
        raise ValueError(f"Unsafe bundle member path: {name!r}")
    if any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError(f"Unsafe bundle member path: {name!r}")
    return name


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("JSON number exceeds finite float range")
    return result


def _json(data: bytes, label: str):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"Invalid {label}: {exc}") from exc


def _hashes(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value or len(value) >= MAX_ENTRIES:
        raise ValueError(f"{label} must be a nonempty, bounded path-to-SHA256 mapping")
    for name, digest in value.items():
        _safe_name(name)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"Invalid SHA256 for {name!r} in {label}")
    return value


def _tool_hashes(document: dict) -> dict[str, str]:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("Report is missing run metadata")
    hashes = _hashes(metadata.get("tool_source_sha256"), "tool source hashes")
    if any(not name.endswith(".py") for name in hashes):
        raise ValueError("Tool source hashes must identify Python source files")
    return hashes


def _lab_records(document: object) -> dict[str, dict]:
    if not isinstance(document, dict) or document.get("tool") != "patchproof":
        raise ValueError("Bundle report must identify Patchproof")
    labs = document.get("labs")
    if not isinstance(labs, list) or not labs:
        raise ValueError("Bundle report must contain lab evidence")
    records = {}
    for lab in labs:
        if not isinstance(lab, dict):
            raise ValueError("Invalid lab evidence")
        lab_id = lab.get("id")
        if not isinstance(lab_id, str) or not _LAB_ID.fullmatch(lab_id) or lab_id in records:
            raise ValueError("Invalid or duplicate lab identifier in report")
        if not isinstance(lab.get("diff"), dict):
            raise ValueError(f"Lab {lab_id} is missing source fingerprints")
        records[lab_id] = lab
    return records


def _expected_artifacts(document: dict) -> dict[str, str]:
    expected = {}
    for lab_id, lab in _lab_records(document).items():
        expected[f"labs/{lab_id}/manifest.json"] = lab.get("manifest_sha256")
        expected[f"labs/{lab_id}/vulnerable.py"] = lab["diff"].get("before_sha256")
        expected[f"labs/{lab_id}/patched.py"] = lab["diff"].get("after_sha256")
    for name, digest in _tool_hashes(document).items():
        expected[f"src/patchproof/{name}"] = digest
    return _hashes(expected, "reported artifact hashes")


def _check_coherence(contents: dict[str, bytes]) -> None:
    if not {"report.json", "report.md"} <= contents.keys():
        raise ValueError("Bundle must contain JSON and Markdown reports")
    document = _json(contents["report.json"], "report.json")
    expected = _expected_artifacts(document)
    if set(contents) != set(expected) | {"report.json", "report.md"}:
        raise ValueError("Bundle artifact set does not match the report")
    for name, digest in expected.items():
        if _digest(contents[name]) != digest:
            raise ValueError(f"Artifact does not match report fingerprint: {name}")
    for lab_id, reported in _lab_records(document).items():
        manifest = _json(contents[f"labs/{lab_id}/manifest.json"], f"{lab_id} manifest")
        if not isinstance(manifest, dict):
            raise ValueError(f"Invalid manifest for {lab_id}")
        for key in ("id", "title", "cwe"):
            if not json_equal(manifest.get(key), reported.get(key)):
                raise ValueError(f"Report metadata differs from manifest for {lab_id}: {key}")
        declared_cases = manifest.get("cases")
        observed_cases = reported.get("cases")
        if not isinstance(declared_cases, list) or not isinstance(observed_cases, list):
            raise ValueError(f"Missing cases for {lab_id}")
        if not declared_cases or len(declared_cases) != len(observed_cases):
            raise ValueError(f"Report case count differs from manifest for {lab_id}")
        for declared, observed in zip(declared_cases, observed_cases):
            if not isinstance(declared, dict) or not isinstance(observed, dict):
                raise ValueError(f"Invalid case evidence for {lab_id}")
            for key, value in declared.items():
                if key not in observed or not json_equal(value, observed[key]):
                    raise ValueError(f"Report case differs from manifest for {lab_id}: {key}")


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError(f"Artifact exceeds the 16 MiB bundle limit: {path.name}")
    return data


def create_bundle(report: VerificationReport, labs: tuple[Lab, ...], destination: Path,
                  *, candidate: Path | None = None) -> Path:
    """Atomically write a ZIP after matching current inputs to the recorded run.

    A changed or missing source, manifest, or tool file aborts creation. These
    checks bind the archived bytes to recorded hashes, not to an author identity.
    """
    destination = Path(destination)
    if candidate is not None and len(labs) != 1:
        raise ValueError("A candidate override requires exactly one lab")
    contents = {
        "report.json": render_json(report).encode("utf-8"),
        "report.md": render_markdown(report).encode("utf-8"),
    }
    total_bytes = sum(map(len, contents.values()))
    document = _json(contents["report.json"], "report.json")
    records = _lab_records(document)
    if len(labs) != len(records) or {lab.id for lab in labs} != set(records):
        raise ValueError("Selected labs do not match the verification report")
    expected = _expected_artifacts(document)
    sources: dict[str, Path] = {}
    for lab in labs:
        sources[f"labs/{lab.id}/manifest.json"] = lab.directory / "manifest.json"
        sources[f"labs/{lab.id}/vulnerable.py"] = lab.directory / "vulnerable.py"
        sources[f"labs/{lab.id}/patched.py"] = (
            Path(candidate) if candidate is not None else lab.directory / "patched.py"
        )
    package = Path(__file__).resolve().parent
    current_tool_files = {path.relative_to(package).as_posix(): path for path in package.rglob("*.py")}
    if set(current_tool_files) != set(_tool_hashes(document)):
        raise ValueError("Tool source file set changed after verification")
    for name, path in current_tool_files.items():
        sources[f"src/patchproof/{name}"] = path
    destination_resolved = destination.resolve()
    for name, path in sources.items():
        if path.resolve() == destination_resolved:
            raise ValueError("Bundle destination would overwrite a verification input")
        data = _read_bounded(path)
        if _digest(data) != expected[name]:
            raise ValueError(f"Input changed after verification: {name}")
        total_bytes += len(data)
        if total_bytes > MAX_BUNDLE_BYTES:
            raise ValueError("Bundle exceeds the 16 MiB uncompressed size limit")
        contents[name] = data
    _check_coherence(contents)
    manifest = {
        "schema_version": 1,
        "algorithm": "sha256",
        "files": {name: _digest(data) for name, data in sorted(contents.items())},
    }
    contents[MANIFEST_NAME] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(contents) > MAX_ENTRIES or sum(map(len, contents.values())) > MAX_BUNDLE_BYTES:
        raise ValueError("Bundle exceeds its file count or uncompressed size limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".patchproof-bundle-", suffix=".zip",
                                         dir=destination.parent, delete=False) as handle:
            temporary_path = Path(handle.name)
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as archive:
            for name, data in sorted(contents.items()):
                member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, data)
        verify_bundle(temporary_path)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return destination


def verify_bundle(path: Path) -> dict:
    """Check bounded archive contents without extracting or executing anything."""
    path = Path(path)
    if path.stat().st_size > MAX_BUNDLE_BYTES + MAX_MANIFEST_BYTES:
        raise ValueError("Archive file exceeds the bundle size limit")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            members = archive.infolist()
            if not 1 <= len(members) <= MAX_ENTRIES:
                raise ValueError("Bundle must contain at most 256 files")
            names = set()
            total_bytes = 0
            for member in members:
                name = _safe_name(member.filename)
                if member.orig_filename != name or name in names:
                    raise ValueError(f"Duplicate or invalid bundle member: {name!r}")
                names.add(name)
                file_type = stat.S_IFMT(member.external_attr >> 16)
                if member.is_dir() or file_type not in (0, stat.S_IFREG):
                    raise ValueError("Bundle members must be regular files; links are forbidden")
                if member.flag_bits & 1:
                    raise ValueError("Encrypted bundle members are forbidden")
                if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError("Unsupported bundle compression method")
                total_bytes += member.file_size
                if total_bytes > MAX_BUNDLE_BYTES:
                    raise ValueError("Bundle exceeds the 16 MiB uncompressed size limit")
            if MANIFEST_NAME not in names:
                raise ValueError("Missing bundle-manifest.json")
            if archive.getinfo(MANIFEST_NAME).file_size > MAX_MANIFEST_BYTES:
                raise ValueError("Bundle manifest is too large")
            manifest = _json(archive.read(MANIFEST_NAME), MANIFEST_NAME)
            if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "algorithm", "files"}:
                raise ValueError("Invalid bundle manifest fields")
            if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
                raise ValueError("Unsupported bundle manifest schema")
            if manifest["algorithm"] != "sha256":
                raise ValueError("Unsupported bundle checksum algorithm")
            hashes = _hashes(manifest["files"], "bundle files")
            if MANIFEST_NAME in hashes or names != set(hashes) | {MANIFEST_NAME}:
                raise ValueError("Bundle file set differs from its manifest")
            contents = {}
            for name, digest in hashes.items():
                data = archive.read(name)
                if _digest(data) != digest:
                    raise ValueError(f"Bundle checksum mismatch: {name}")
                contents[name] = data
            _check_coherence(contents)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError,
            RecursionError, EOFError, zlib.error) as exc:
        raise ValueError(f"Invalid evidence archive: {exc}") from exc
    return {"status": "pass", "files_verified": len(hashes), "warning": INTEGRITY_WARNING}
