"""Validate the identifier and bind every request value as a SQL parameter."""

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
    if isinstance(account_id, str):
        if not (
            1 <= len(account_id) <= 256
            and account_id.isascii()
            and account_id.isdecimal()
        ):
            return {"status": "invalid_input"}
        account_id = int(account_id)
    if not 1 <= account_id <= 1_000_000:
        return {"status": "invalid_input"}

    with closing(sqlite3.connect(":memory:")) as database:
        database.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)"
        )
        database.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", ACCOUNTS)
        # FIX: both request values are data, never executable SQL syntax.
        query = "SELECT id, username, role FROM users WHERE id = ? AND password = ? ORDER BY id"
        try:
            account = database.execute(query, (account_id, password)).fetchone()
        except (sqlite3.Error, UnicodeError):
            return {"status": "invalid_input"}
    if account is None:
        return {"status": "unauthorized"}
    return {
        "status": "ok",
        "account": {"id": account[0], "username": account[1], "role": account[2]},
    }
