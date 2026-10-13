"""Capture portable run context and on-disk tool source identities."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import platform
from typing import Any


def collect_run_metadata(
    *, timeout: float | None = None, max_output_bytes: int | None = None
) -> dict[str, Any]:
    """Record context once per report; omitted limits mean they were not recorded.

    Hashes describe the package files on disk when this function runs. They
    support reproducing a run, not attesting an unmodified interpreter or host.
    """
    package = Path(__file__).resolve().parent
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "limits": {"timeout_seconds": timeout, "max_output_bytes": max_output_bytes},
        "tool_source_sha256": {
            path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(package.rglob("*.py"))
        },
    }
