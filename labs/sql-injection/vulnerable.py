"""Intentionally vulnerable authentication against a disposable SQLite database."""

import sqlite3
from contextlib import closing
from pathlib import Path


ACCOUNTS = (
    (1, "admin", "admin", "admin-demo-only"),
    (2, "reader", "member", "reader's-demo-only"),
    (3, "analyst", "member", "analyst-demo-only"),
)


def run(payload: object, workspace: Path) -> dict:
    if not isinstance(payload, dict):
        return {"status": "invalid_input"}
    account_id = payload.get("account_id")
    password = payload.get("password")
    if (
        isinstance(account_id, bool)
        or not isinstance(account_id, (str, int))
        or not isinstance(password, str)
        or len(password) > 128
    ):
        return {"status": "invalid_input"}
    if isinstance(account_id, str) and not 1 <= len(account_id) <= 256:
        return {"status": "invalid_input"}
    if isinstance(account_id, int) and not 1 <= account_id <= 1_000_000:
        return {"status": "invalid_input"}

    with closing(sqlite3.connect(":memory:")) as database:
        database.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)"
        )
        database.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", ACCOUNTS)
        # FLAW: binding the password does not protect interpolated account_id.
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE id = {account_id} AND password = ? ORDER BY id"
        )
        try:
            account = database.execute(query, (password,)).fetchone()
        except (sqlite3.Error, UnicodeError):
            return {"status": "invalid_input"}
    if account is None:
        return {"status": "unauthorized"}
    if not isinstance(account[0], int) or not all(isinstance(value, str) for value in account[1:]):
        return {"status": "invalid_input"}
    return {
        "status": "ok",
        "account": {"id": account[0], "username": account[1], "role": account[2]},
    }
