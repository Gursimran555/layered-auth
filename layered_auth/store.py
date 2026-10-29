"""SQLite storage.

The first version used a JSON file plus two text files. Two logins at the same
time could both read failed_attempts=4, both write 5, and the attacker gets an
extra guess. SQLite gives atomic updates for free and is still a single file.
"""

from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    password_hash   BLOB NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL
);
CREATE TABLE IF NOT EXISTS challenges (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    method      TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS otps (
    username      TEXT PRIMARY KEY,
    code_mac      TEXT NOT NULL,
    expires_at    REAL NOT NULL,
    attempts_left INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS totp (
    username  TEXT PRIMARY KEY,
    secret    TEXT NOT NULL,
    active    INTEGER NOT NULL DEFAULT 0,
    last_step INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE IF NOT EXISTS tokens (
    jti         TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    issued_at   REAL NOT NULL,
    expires_at  REAL NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_by_user ON tokens(username);
"""


class Store:
    def __init__(self, path: str = "auth.db"):
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def one(self, sql: str, *args):
        return self.conn.execute(sql, args).fetchone()

    def run(self, sql: str, *args) -> int:
        return self.conn.execute(sql, args).rowcount

    def close(self):
        self.conn.close()
