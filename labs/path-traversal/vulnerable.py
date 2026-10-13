"""Intentionally vulnerable path lookup over disposable local fixtures."""

from pathlib import Path


def _fixtures(workspace: Path, use_symlink: bool) -> Path:
    public = workspace / "public"
    (public / "docs").mkdir(parents=True, exist_ok=True)
    (workspace / "private").mkdir(exist_ok=True)
    (workspace / "public-backup").mkdir(exist_ok=True)
    (public / "welcome.txt").write_text("Welcome to Patchproof.\n", encoding="utf-8")
    (public / "docs" / "guide.txt").write_text("Nested public guide.\n", encoding="utf-8")
    (workspace / "private" / "secret.txt").write_text("SYNTHETIC_PRIVATE_RECORD\n", encoding="utf-8")
    (workspace / "public-backup" / "secret.txt").write_text("SYNTHETIC_BACKUP_RECORD\n", encoding="utf-8")
    if use_symlink:
        (public / "shortcut").symlink_to(workspace / "private", target_is_directory=True)
    return public


def run(payload, workspace: Path):
    if not isinstance(payload, dict):
        return {"status": "rejected", "reason": "invalid-request"}
    requested = payload.get("path")
    if not isinstance(requested, str) or not requested or "\x00" in requested or len(requested) > 4096:
        return {"status": "rejected", "reason": "invalid-path"}
    try:
        public = _fixtures(workspace, "shortcut" in Path(requested).parts)
        candidate = public / requested
        # Harness guard: even the vulnerable example may read only this workspace.
        # This does NOT enforce the application's public-directory boundary.
        candidate.resolve().relative_to(workspace.resolve())
    except ValueError:
        return {"status": "rejected", "reason": "outside-fixture-workspace"}
    except (OSError, RuntimeError):
        return {"status": "rejected", "reason": "fixture-unavailable"}
    try:
        # BUG: joining a caller's path does not constrain it to public/.
        return {"status": "ok", "content": candidate.read_text(encoding="utf-8")}
    except FileNotFoundError:
        return {"status": "rejected", "reason": "not-found"}
    except (OSError, UnicodeError):
        return {"status": "rejected", "reason": "unreadable-file"}
