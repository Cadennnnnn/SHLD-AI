import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DB_PATH = PROJECT_ROOT / "data" / "shld_memory.db"

def initialize_memory() -> None:
    """Create the persistent memory table if it does not exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

def save_memory(incident_id: str, content: str) -> None:
    """Save a note associated with an incident."""
    initialize_memory()
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            "INSERT INTO incident_memory (incident_id, content) VALUES (?, ?)",
            (incident_id, content),
        )

def get_memories(incident_id: str) -> list[dict[str, str]]:
    """Retrieve saved notes for an incident."""
    initialize_memory()
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT incident_id, content, created_at
            FROM incident_memory
            WHERE incident_id = ?
            ORDER BY id DESC
            """,
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]
