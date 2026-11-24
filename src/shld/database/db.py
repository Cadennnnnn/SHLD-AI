import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DB_PATH = PROJECT_ROOT / "data" / "shld.db"

def get_connection() -> sqlite3.Connection:
    """Open a connection to the SHLD database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection

def initialize_database() -> None:
    """Create the security events table if it does not exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                incident_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

def add_event(
    event_id: str,
    incident_id: str,
    event_type: str,
    severity: str,
    description: str,
    source_ip: str = "",
) -> None:
    """Insert a security event into the database."""
    initialize_database()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO security_events (
                event_id, incident_id, event_type,
                severity, description, source_ip
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_id, incident_id, event_type, severity, description, source_ip),
        )

def query_events(incident_id: str) -> list[dict]:
    """Return events associated with an incident."""
    initialize_database()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT event_id, incident_id, event_type, severity,
                   description, source_ip, created_at
            FROM security_events
            WHERE incident_id = ?
            ORDER BY created_at DESC
            """,
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]
