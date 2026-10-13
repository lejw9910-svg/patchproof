"""Intentionally unsafe reconstruction using fixed, harmless pickle fixtures."""

import json
import math
import pickle
from pathlib import Path


class _BenignReconstruction:
    def __init__(self, expression):
        self.expression = expression

    def __reduce__(self):
        # These expressions are fixed below; neither invokes a shell nor uses IO.
        return eval, (self.expression,)


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
    if format_name == "json":
        data = payload.get("data")
        if not isinstance(data, str) or len(data) > 8192:
            return {"status": "rejected", "reason": "invalid-data"}
        try:
            value = json.loads(data, parse_constant=_reject_constant, parse_float=_finite_float)
        except (ValueError, RecursionError):
            return {"status": "rejected", "reason": "invalid-json"}
        return {"status": "ok", "value": value}
    if format_name == "pickle":
        # Select local examples instead of accepting arbitrary executable blobs.
        expressions = {
            "callable-marker": "'PICKLE_RECONSTRUCTION_EXECUTED'",
            "callable-record": "{'marker': 'PICKLE_EXPRESSION_EXECUTED', 'answer': 6 * 7}",
        }
        fixture = payload.get("fixture")
        if not isinstance(fixture, str) or fixture not in expressions:
            return {"status": "rejected", "reason": "unknown-fixture"}
        serialized = pickle.dumps(_BenignReconstruction(expressions[fixture]), protocol=4)
        # BUG: loads invokes the callable encoded by __reduce__.
        value = pickle.loads(serialized)
        return {"status": "ok", "value": value}
    return {"status": "rejected", "reason": "unsupported-format"}
