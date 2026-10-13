"""Negative evaluation candidate: reject every request, including legitimate use."""

from pathlib import Path


def run(payload: object, workspace: Path) -> dict:
    # A successful security response alone cannot establish patch correctness.
    return {'status': 'invalid_input'}
