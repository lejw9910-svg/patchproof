"""Negative evaluation candidate: reject executable formats but break valid JSON arrays."""

import json
import math
from pathlib import Path


def _reject_constant(value):
    raise ValueError("non-finite JSON constant")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def run(payload, workspace: Path):
    if not isinstance(payload, dict):
        return {"status": "rejected", "reason": "invalid-request"}
    format_name = payload.get("format")
    if format_name == "pickle":
        return {"status": "rejected", "reason": "unsafe-serialization-format"}
    if format_name != "json":
        return {"status": "rejected", "reason": "unsupported-format"}
    data = payload.get("data")
    if not isinstance(data, str) or len(data) > 8192:
        return {"status": "rejected", "reason": "invalid-data"}
    try:
        value = json.loads(data, parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        return {"status": "rejected", "reason": "invalid-json"}
    # REGRESSION: a format restriction unnecessarily removes supported JSON arrays.
    if isinstance(value, list):
        return {"status": "rejected", "reason": "invalid-json"}
    return {"status": "ok", "value": value}
