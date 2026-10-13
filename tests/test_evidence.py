"""Evidence archives retain matching inputs and reject unsafe or damaged ZIPs."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from patchproof.evidence import (
    MANIFEST_NAME, MAX_BUNDLE_BYTES, MAX_ENTRIES, create_bundle, verify_bundle,
)
from patchproof.verifier import load_lab, verify_labs


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="patchproof-evidence-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "example"
        self.directory.mkdir()
        (self.directory / "vulnerable.py").write_text(
            "def run(payload, workspace):\n    return 'vulnerable' if payload else 'normal'\n"
        )
        (self.directory / "patched.py").write_text(
            "def run(payload, workspace):\n    return 'rejected' if payload else 'normal'\n"
        )
        manifest = {
            "schema_version": 1, "id": "example", "title": "Example", "cwe": "CWE-22",
            "cases": [
                {"id": "attack", "kind": "attack", "input": True,
                 "expected_vulnerable": "vulnerable", "expected_patched": "rejected"},
                {"id": "normal", "kind": "regression", "input": False,
                 "expected_vulnerable": "normal", "expected_patched": "normal"},
            ],
        }
        (self.directory / "manifest.json").write_text(json.dumps(manifest))
        self.lab = load_lab(self.directory)
        self.report = verify_labs((self.lab,))
        self.bundle = create_bundle(self.report, (self.lab,), self.root / "evidence.zip")

    def contents(self):
        with zipfile.ZipFile(self.bundle) as archive:
            return {member.filename: archive.read(member) for member in archive.infolist()}

    def rewrite(self, contents, *, update_checksums=False):
        if update_checksums:
            manifest = json.loads(contents[MANIFEST_NAME])
            manifest["files"] = {name: hashlib.sha256(data).hexdigest()
                                 for name, data in contents.items() if name != MANIFEST_NAME}
            contents[MANIFEST_NAME] = json.dumps(manifest).encode()
        with zipfile.ZipFile(self.bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in contents.items():
                archive.writestr(name, data)

    def test_round_trip_includes_exact_inputs_reports_and_tool_sources(self):
        summary = verify_bundle(self.bundle)
        contents = self.contents()
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["files_verified"], len(contents) - 1)
        self.assertIn("unsigned", summary["warning"])
        self.assertIn("report.md", contents)
        document = json.loads(contents["report.json"])
        self.assertEqual(document["metadata"], self.report.metadata)
        for name in ("manifest.json", "vulnerable.py", "patched.py"):
            self.assertEqual(contents[f"labs/example/{name}"], (self.directory / name).read_bytes())
        for name, digest in self.report.metadata["tool_source_sha256"].items():
            self.assertEqual(hashlib.sha256(contents[f"src/patchproof/{name}"]).hexdigest(), digest)

    def test_same_report_produces_identical_archive_bytes(self):
        second = create_bundle(self.report, (self.lab,), self.root / "second.zip")
        self.assertEqual(self.bundle.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(second) as archive:
            self.assertTrue(all(member.date_time == (1980, 1, 1, 0, 0, 0)
                                for member in archive.infolist()))

    def test_candidate_override_archives_the_executed_candidate(self):
        candidate = self.root / "candidate.py"
        candidate.write_text((self.directory / "patched.py").read_text() + "# reviewed candidate\n")
        report = verify_labs((self.lab,), candidate=candidate)
        create_bundle(report, (self.lab,), self.bundle, candidate=candidate)
        self.assertEqual(self.contents()["labs/example/patched.py"], candidate.read_bytes())
        self.assertEqual(verify_bundle(self.bundle)["status"], "pass")
        with self.assertRaises(ValueError):
            create_bundle(report, (self.lab, self.lab), self.bundle, candidate=candidate)

    def test_failed_verification_can_have_an_intact_evidence_bundle(self):
        candidate = self.root / "bad-candidate.py"
        candidate.write_bytes((self.directory / "vulnerable.py").read_bytes())
        report = verify_labs((self.lab,), candidate=candidate)
        self.assertEqual(report.status, "fail")
        create_bundle(report, (self.lab,), self.bundle, candidate=candidate)
        self.assertEqual(verify_bundle(self.bundle)["status"], "pass")
        self.assertEqual(json.loads(self.contents()["report.json"])["status"], "fail")

    def test_changed_inputs_refuse_creation_and_preserve_existing_destination(self):
        original_bundle = self.bundle.read_bytes()
        for name in ("manifest.json", "vulnerable.py", "patched.py"):
            with self.subTest(name=name):
                path = self.directory / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                try:
                    with self.assertRaisesRegex(ValueError, "changed after verification"):
                        create_bundle(self.report, (self.lab,), self.bundle)
                    self.assertEqual(self.bundle.read_bytes(), original_bundle)
                finally:
                    path.write_bytes(original)

    def test_tool_fingerprint_mismatch_refuses_creation(self):
        metadata = dict(self.report.metadata)
        metadata["tool_source_sha256"] = dict(metadata["tool_source_sha256"])
        name = next(iter(metadata["tool_source_sha256"]))
        metadata["tool_source_sha256"][name] = "0" * 64
        report = replace(self.report, metadata=metadata)
        original = self.bundle.read_bytes()
        with self.assertRaisesRegex(ValueError, "changed after verification"):
            create_bundle(report, (self.lab,), self.bundle)
        self.assertEqual(original, self.bundle.read_bytes())

    def test_creation_never_overwrites_a_verification_input(self):
        with self.assertRaisesRegex(ValueError, "overwrite a verification input"):
            create_bundle(self.report, (self.lab,), self.directory / "manifest.json")

    def test_failed_atomic_replace_preserves_destination_and_removes_temporary(self):
        original = self.bundle.read_bytes()
        with patch("patchproof.evidence.os.replace", side_effect=OSError("simulated write failure")):
            with self.assertRaises(OSError):
                create_bundle(self.report, (self.lab,), self.bundle)
        self.assertEqual(original, self.bundle.read_bytes())
        self.assertEqual(list(self.root.glob(".patchproof-bundle-*")), [])

    def test_corrupted_content_is_rejected(self):
        contents = self.contents()
        contents["labs/example/patched.py"] += b"# altered\n"
        self.rewrite(contents)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            verify_bundle(self.bundle)

    def test_updated_checksum_cannot_hide_source_report_mismatch(self):
        contents = self.contents()
        contents["labs/example/patched.py"] += b"# altered\n"
        self.rewrite(contents, update_checksums=True)
        with self.assertRaisesRegex(ValueError, "report fingerprint"):
            verify_bundle(self.bundle)

    def test_report_expectations_must_match_archived_manifest(self):
        contents = self.contents()
        document = json.loads(contents["report.json"])
        document["labs"][0]["cases"][0]["expected_patched"] = "vulnerable"
        contents["report.json"] = json.dumps(document).encode()
        self.rewrite(contents, update_checksums=True)
        with self.assertRaisesRegex(ValueError, "case differs from manifest"):
            verify_bundle(self.bundle)

    def test_check_never_executes_bundled_code_or_claims_authenticity(self):
        contents = self.contents()
        marker = self.root / "executed"
        source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n".encode()
        contents["labs/example/patched.py"] = source
        document = json.loads(contents["report.json"])
        document["labs"][0]["diff"]["after_sha256"] = hashlib.sha256(source).hexdigest()
        contents["report.json"] = json.dumps(document).encode()
        self.rewrite(contents, update_checksums=True)
        summary = verify_bundle(self.bundle)
        self.assertFalse(marker.exists())
        self.assertIn("does not establish authenticity", summary["warning"])

    def test_missing_or_extra_members_are_rejected(self):
        original = self.contents()
        variants = [
            {name: value for name, value in original.items() if name != "report.md"},
            dict(original, unexpected=b"extra"),
        ]
        for contents in variants:
            with self.subTest(names=set(contents) ^ set(original)):
                self.rewrite(contents)
                with self.assertRaisesRegex(ValueError, "file set differs"):
                    verify_bundle(self.bundle)

    def test_extra_member_declared_in_checksum_index_is_still_rejected(self):
        contents = self.contents()
        contents["unexpected.py"] = b"extra"
        self.rewrite(contents, update_checksums=True)
        with self.assertRaisesRegex(ValueError, "artifact set"):
            verify_bundle(self.bundle)

    def test_unsafe_member_paths_are_rejected(self):
        original = self.contents()
        for name in ("../outside.py", "/absolute.py", "a\\b.py", "C:relative.py", "a//b", "a/./b"):
            with self.subTest(name=name):
                self.rewrite(dict(original, **{name: b"unsafe"}))
                with self.assertRaisesRegex(ValueError, "Unsafe bundle member path"):
                    verify_bundle(self.bundle)

    def test_duplicate_members_are_rejected(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.bundle, "a") as archive:
                archive.writestr("report.md", b"duplicate")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            verify_bundle(self.bundle)

    def test_symlink_members_are_rejected(self):
        member = zipfile.ZipInfo("symbolic-link")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.bundle, "a") as archive:
            archive.writestr(member, "../../outside")
        with self.assertRaisesRegex(ValueError, "links are forbidden"):
            verify_bundle(self.bundle)

    def test_encrypted_members_are_rejected_before_reading(self):
        data = bytearray(self.bundle.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = data.index(signature) + offset
            data[position] |= 1
        self.bundle.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "Encrypted"):
            verify_bundle(self.bundle)

    def test_malformed_compressed_payload_is_reported_as_invalid_archive(self):
        with zipfile.ZipFile(self.bundle) as archive:
            offset = archive.getinfo(MANIFEST_NAME).header_offset
        data = bytearray(self.bundle.read_bytes())
        name_length = int.from_bytes(data[offset + 26:offset + 28], "little")
        extra_length = int.from_bytes(data[offset + 28:offset + 30], "little")
        # A final DEFLATE block with reserved BTYPE=3 is structurally invalid.
        data[offset + 30 + name_length + extra_length] = 0x07
        self.bundle.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "Invalid evidence archive"):
            verify_bundle(self.bundle)

    def test_malformed_manifest_and_non_zip_are_rejected(self):
        original = self.contents()
        for data in (b"invalid-json", b"[]", b'{"schema_version":1,"schema_version":1}',
                     b'{"schema_version":true,"algorithm":"sha256","files":{}}',
                     b'{"schema_version":1,"algorithm":"md5","files":{}}'):
            with self.subTest(data=data):
                contents = dict(original)
                contents[MANIFEST_NAME] = data
                self.rewrite(contents)
                with self.assertRaises(ValueError):
                    verify_bundle(self.bundle)
        self.bundle.write_bytes(b"not a ZIP")
        with self.assertRaises(ValueError):
            verify_bundle(self.bundle)

    def test_archive_file_and_uncompressed_size_limits_are_enforced(self):
        with zipfile.ZipFile(self.bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("oversized", b"x" * (MAX_BUNDLE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "uncompressed size"):
            verify_bundle(self.bundle)
        with self.bundle.open("wb") as handle:
            handle.truncate(MAX_BUNDLE_BYTES * 2)
        with self.assertRaisesRegex(ValueError, "Archive file exceeds"):
            verify_bundle(self.bundle)

    def test_entry_count_is_bounded(self):
        with zipfile.ZipFile(self.bundle, "w") as archive:
            for index in range(MAX_ENTRIES + 1):
                archive.writestr(str(index), b"")
        with self.assertRaisesRegex(ValueError, "at most 256"):
            verify_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()
