"""
backend/models/db.py
---------------------
Database connection, initialisation, and shared helpers.

All blueprints import get_db() from here.
"""
import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


def get_db(db_path: str | Path) -> sqlite3.Connection:
    """
    Open a SQLite connection with row_factory set.
    Caller is responsible for using it as a context manager (with get_db(...) as conn).
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrent read/write
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | Path) -> None:
    """
    Create the database file, run schema.sql, and apply migrations.
    Safe to call on every startup — all statements use IF NOT EXISTS.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    schema_path = Path(__file__).resolve().parent.parent.parent / "database" / "schema.sql"
    schema_sql = schema_path.read_text()

    with get_db(db_path) as conn:
        conn.executescript(schema_sql)
        conn.commit()

    _run_migrations(db_path)
    logger.info("Database ready at %s", db_path)


def _run_migrations(db_path: Path) -> None:
    """
    Apply any SQL migration files in database/migrations/ in order.
    Tracks applied migrations in a _migrations table.
    """
    migrations_dir = Path(__file__).resolve().parent.parent.parent / "database" / "migrations"
    if not migrations_dir.exists():
        return

    with get_db(db_path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS _migrations (
               name TEXT PRIMARY KEY,
               applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"""
        )
        conn.commit()

        applied = {r["name"] for r in conn.execute("SELECT name FROM _migrations").fetchall()}

        for sql_file in sorted(migrations_dir.glob("*.sql")):
            if sql_file.name in applied:
                continue
            try:
                conn.executescript(sql_file.read_text())
                conn.execute("INSERT INTO _migrations (name) VALUES (?)", (sql_file.name,))
                conn.commit()
                logger.info("Migration applied: %s", sql_file.name)
            except Exception as e:
                logger.warning("Migration %s failed (may already be applied): %s", sql_file.name, e)