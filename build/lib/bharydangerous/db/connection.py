"""SQLite database connection manager for BHARYDANGEROUS-Investigator."""
import sqlite3
from pathlib import Path
from typing import Generator
from contextlib import contextmanager

def get_db_connection(db_path: Path | str) -> sqlite3.Connection:
    """
    Open SQLite database connection with row factory, foreign keys, and WAL mode.
    """
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

@contextmanager
def db_session(db_path: Path | str) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for atomic database operations with automatic rollback on error."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
