"""Database schema initializer and migration runner."""
from pathlib import Path
from bharydangerous.db.connection import get_db_connection

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def initialize_database(db_path: Path | str) -> None:
    """Read schema.sql and initialize all tables in the specified SQLite database."""
    conn = get_db_connection(db_path)
    try:
        with SCHEMA_PATH.open("r", encoding="utf-8") as f:
            ddl = f.read()
        conn.executescript(ddl)
        conn.commit()
    finally:
        conn.close()

def is_database_initialized(db_path: Path | str) -> bool:
    """Check if the cases table exists in the database."""
    if not Path(db_path).is_file():
        return False
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cases';")
        return cur.fetchone() is not None
    finally:
        conn.close()
