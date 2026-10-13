"""Authorization uses only roles from the server-held synthetic token database."""

from pathlib import Path


TOKENS = {
    "admin-demo-token": {"username": "admin", "role": "admin"},
    "alice-demo-token": {"username": "alice", "role": "member"},
    "bob-demo-token": {"username": "bob", "role": "member"},
}


def run(payload: object, workspace: Path) -> dict:
    """Ignore client role claims after looking up an authenticated account."""
    if not isinstance(payload, dict):
        return {"status": "invalid_input"}
    token = payload.get("token")
    if not isinstance(token, str) or token not in TOKENS:
        return {"status": "unauthorized"}
    account = TOKENS[token]
    action = payload.get("action", "profile")
    if action == "profile":
        return {"status": "ok", "data": dict(account)}
    if action not in ("admin_panel", "read_audit"):
        return {"status": "invalid_input"}

    # FIX: identity and privilege both come from authenticated server state.
    if account["role"] != "admin":
        return {"status": "forbidden"}
    if action == "admin_panel":
        return {"status": "ok", "data": {"users": ["admin", "alice", "bob"]}}
    return {"status": "ok", "data": {"events": ["demo login", "demo settings update"]}}
