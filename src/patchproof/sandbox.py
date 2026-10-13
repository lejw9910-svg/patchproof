"""Run trusted local lab cases with time and output bounds.

Each invocation gets a temporary working directory and a scrubbed environment.
This is process hygiene, not a security boundary: target code retains the
current user's filesystem and network access. Only execute trusted lab code.
On POSIX, descendants in the worker's process group are terminated as well.
Audit observations count Python events in the worker only; they do not cover
subprocesses and are not protected against hostile code tampering.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any


MAX_INPUT_BYTES = 65_536


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    value: object = None
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    duration_seconds: float = 0.0
    observations: dict[str, int] = field(default_factory=dict)


def _reject_constant(value: str) -> Any:
    raise ValueError(f"Non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds finite float range")
    return number


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(data: bytes) -> object:
    return json.loads(
        data.decode("utf-8"),
        parse_constant=_reject_constant,
        parse_float=_finite_float,
        object_pairs_hook=_unique_object,
    )


def _environment(workspace: Path) -> dict[str, str]:
    environment = {
        "HOME": str(workspace),
        "USERPROFILE": str(workspace),
        "TMPDIR": str(workspace),
        "TMP": str(workspace),
        "TEMP": str(workspace),
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    # Windows needs these paths to load runtime system libraries. No other
    # inherited environment variables, credentials, or Python settings pass in.
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR"):
            if name in os.environ:
                environment[name] = os.environ[name]
    return environment


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass


def run_case(
    module: Path,
    payload: object,
    *,
    timeout: float = 2.0,
    max_output_bytes: int = 65_536,
) -> ExecutionResult:
    """Call ``module.run(payload, workspace)`` in a fresh Python process.

    ``status`` is ``ok``, ``error``, ``timeout``, or ``output_limit``. The
    output budget covers stdout and stderr together. Python target prints go
    to stderr; stdout is reserved for the JSON response protocol. Invalid
    settings raise ValueError; case or serialization failures return ``error``.

    Input is limited to 64 KiB of JSON. This runner does not restrict memory,
    filesystem access, or network access, and is unsuitable for hostile code.
    Windows cleanup terminates the worker only; POSIX also kills descendants
    that remain in its process group.

    Successful results include a ``pickle_class_resolutions`` count from a
    Python audit hook installed before target import. It counts in-worker
    ``pickle.find_class`` events, not all deserialization or subprocess events,
    and cannot establish safety against hostile code that tampers with it.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a positive finite number")
    try:
        timeout_seconds = float(timeout)
    except OverflowError as exc:
        raise ValueError("timeout must be a positive finite number") from exc
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be a positive finite number")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes <= 0
    ):
        raise ValueError("max_output_bytes must be a positive integer")

    started = time.monotonic()

    def failure(message: str) -> ExecutionResult:
        return ExecutionResult(
            "error", stderr=message, duration_seconds=time.monotonic() - started
        )

    try:
        module = Path(module).resolve(strict=True)
        if not module.is_file():
            return failure("Target module must be a file")
        # ensure_ascii keeps the byte bound independent of terminal encoding.
        encoded = json.dumps(payload, allow_nan=False, ensure_ascii=True).encode("utf-8")
        if len(encoded) > MAX_INPUT_BYTES:
            return failure(f"Input exceeds {MAX_INPUT_BYTES} bytes")
    except (OSError, TypeError, ValueError, RecursionError) as exc:
        return failure(f"Invalid case input: {exc}")

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    completed = {name: threading.Event() for name in buffers}
    changed = threading.Event()
    exceeded = threading.Event()
    lock = threading.Lock()
    reader_errors: list[str] = []
    captured_bytes = 0

    def drain(name: str, stream: Any) -> None:
        nonlocal captured_bytes
        try:
            while True:
                chunk = os.read(stream.fileno(), 8192)
                if not chunk:
                    break
                with lock:
                    remaining = max_output_bytes - captured_bytes
                    kept = chunk[:remaining]
                    buffers[name].extend(kept)
                    captured_bytes += len(kept)
                    if len(chunk) > remaining:
                        exceeded.set()
                        changed.set()
                        break
        except (OSError, ValueError) as exc:
            with lock:
                reader_errors.append(str(exc))
        finally:
            stream.close()
            completed[name].set()
            changed.set()

    status: str | None = None
    returncode: int | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="patchproof-") as directory:
            workspace = Path(directory)
            # A regular input file avoids a potentially blocking stdin write
            # and removes the need for another writer thread.
            with tempfile.TemporaryFile(dir=workspace) as input_file:
                input_file.write(encoded)
                input_file.seek(0)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        "-S",
                        str(Path(__file__).with_name("_worker.py").resolve()),
                        str(module),
                    ],
                    cwd=workspace,
                    env=_environment(workspace),
                    stdin=input_file,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=os.name == "posix",
                    shell=False,
                )
                threads: list[threading.Thread] = []
                group_stopped = False
                try:
                    for name in buffers:
                        stream = getattr(process, name)
                        thread = threading.Thread(
                            target=drain, args=(name, stream), daemon=True
                        )
                        thread.start()
                        threads.append(thread)
                    deadline = started + timeout_seconds
                    while True:
                        if exceeded.is_set():
                            status = "output_limit"
                            break
                        returncode = process.poll()
                        if returncode is not None and not group_stopped:
                            # Even a successful case must not leave background
                            # descendants running or holding captured pipes open.
                            _stop_process_group(process)
                            group_stopped = True
                        if returncode is not None and all(
                            event.is_set() for event in completed.values()
                        ):
                            break
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            status = "timeout"
                            break
                        changed.wait(min(remaining, 0.02))
                        changed.clear()
                finally:
                    if not group_stopped:
                        _stop_process_group(process)
                    returncode = process.wait(timeout=1.0)
                    for thread in threads:
                        thread.join(timeout=0.5)
                    for name in buffers:
                        if not completed[name].is_set():
                            status = status or "error"
    except (OSError, subprocess.SubprocessError) as exc:
        return failure(f"Could not execute case: {exc}")

    with lock:
        raw_stdout = bytes(buffers["stdout"])
        raw_stderr = bytes(buffers["stderr"])
    stdout = raw_stdout.decode("utf-8", errors="replace")
    stderr = raw_stderr.decode("utf-8", errors="replace")
    value: object = None
    observations: dict[str, int] = {}
    if exceeded.is_set():
        status = "output_limit"
    elif status is None:
        if returncode != 0 or reader_errors:
            status = "error"
        else:
            try:
                response = _load_json(raw_stdout)
                if not isinstance(response, dict) or set(response) != {"value", "observations"}:
                    raise ValueError("Expected an object with exactly 'value' and 'observations' keys")
                observed = response["observations"]
                if not isinstance(observed, dict) or set(observed) != {"pickle_class_resolutions"}:
                    raise ValueError("Expected exactly the 'pickle_class_resolutions' observation")
                count = observed["pickle_class_resolutions"]
                if type(count) is not int or count < 0:
                    raise ValueError("'pickle_class_resolutions' must be a nonnegative integer")
                value = response["value"]
                observations = observed
                status = "ok"
            except (UnicodeError, ValueError, RecursionError) as exc:
                status = "error"
                stderr = (stderr + "\n" if stderr else "") + f"Invalid worker response: {exc}"
    return ExecutionResult(
        status or "error",
        value=value,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        duration_seconds=time.monotonic() - started,
        observations=observations,
    )
