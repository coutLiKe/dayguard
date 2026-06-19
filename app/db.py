"""SQLite stub. Kept for v4 when we add event history.

Currently unused — no panel writes events yet. When a panel does start logging
(e.g. clipboard-watcher service in v4), this file is where the schema lives.
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "dayguard.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                panel TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
