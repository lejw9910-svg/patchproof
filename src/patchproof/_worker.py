"""Private JSON worker for trusted local labs; no hostile-code isolation.

The audit hook counts ``pickle.find_class`` events within this worker, including
target import. It does not observe subprocesses or every deserialization action,
and it is not a tamper-proof boundary against hostile target code.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import json
import math
from pathlib import Path
import sys
import traceback


MAX_INPUT_BYTES = 65_536


def _reject_constant(value: str) -> None:
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


def main() -> int:
    original_stdout = sys.stdout
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected exactly one target module path")
        raw_input = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw_input) > MAX_INPUT_BYTES:
            raise ValueError(f"Input exceeds {MAX_INPUT_BYTES} bytes")
        payload = json.loads(
            raw_input.decode("utf-8"),
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            object_pairs_hook=_unique_object,
        )
        module_path = Path(sys.argv[1])
        if not module_path.is_absolute():
            raise ValueError("Target module path must be absolute")
        observations = {"pickle_class_resolutions": 0}

        def observe(event: str, args: tuple[object, ...]) -> None:
            if event == "pickle.find_class":
                observations["pickle_class_resolutions"] += 1

        # Observe independently of the target's returned acceptance/denial.
        # Register before import so module-level reconstruction is visible too.
        sys.addaudithook(observe)
        with redirect_stdout(sys.stderr):
            spec = importlib.util.spec_from_file_location("_patchproof_target", module_path)
            if spec is None or spec.loader is None:
                raise ValueError("Unable to load target module")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            run = getattr(module, "run", None)
            if not callable(run):
                raise ValueError("Target module must define run(payload, workspace)")
            value = run(payload, Path.cwd())
            response = json.dumps(
                {"value": value, "observations": observations},
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
            )
        original_stdout.write(response + "\n")
        original_stdout.flush()
        return 0
    except BaseException:
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
