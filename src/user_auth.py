"""Local account and per-user scan-history storage for the Streamlit app."""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager


APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.abspath(os.getenv(
    "PHISHGUARD_DATABASE_PATH",
    os.path.join(APP_ROOT, "data", "phishguard.sqlite3"),
))
HASH_ITERATIONS = 600_000


@contextmanager
def _connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database():
    with _connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_id_id "
            "ON scan_history(user_id, id DESC)"
        )


def _password_digest(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, HASH_ITERATIONS
    )


def create_account(username, password):
    username = str(username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
        raise ValueError("Username must be 3–30 characters using letters, numbers, dot, underscore, or hyphen.")
    if len(password or "") < 10:
        raise ValueError("Choose a password with at least 10 characters.")

    salt = secrets.token_bytes(16)
    digest = _password_digest(password, salt)
    try:
        with _connection() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username, password_salt, password_hash) VALUES (?, ?, ?)",
                (username, salt.hex(), digest.hex()),
            )
            return {"id": cursor.lastrowid, "username": username}
    except sqlite3.IntegrityError as error:
        raise ValueError("That username is already registered.") from error


def authenticate_account(username, password):
    username = str(username or "").strip()
    with _connection() as connection:
        row = connection.execute(
            "SELECT id, username, password_salt, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    salt = bytes.fromhex(row["password_salt"])
    actual = _password_digest(password or "", salt).hex()
    if not hmac.compare_digest(actual, row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"]}


def save_scan(user_id, item):
    record = json.dumps(item, ensure_ascii=False, default=str)
    with _connection() as connection:
        connection.execute(
            "INSERT INTO scan_history(user_id, record_json) VALUES (?, ?)",
            (int(user_id), record),
        )


def get_scan_history(user_id, limit=200):
    with _connection() as connection:
        rows = connection.execute(
            "SELECT record_json FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (int(user_id), max(1, min(int(limit), 1000))),
        ).fetchall()
    return [json.loads(row["record_json"]) for row in rows]


def delete_scan_history(user_id):
    with _connection() as connection:
        connection.execute("DELETE FROM scan_history WHERE user_id = ?", (int(user_id),))
