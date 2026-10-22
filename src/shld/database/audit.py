
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DB_PATH = PROJECT_ROOT / "data" / "shld_audit.db"


def initialize_audit() -> None:
    """Create the persistent approval audit table."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                target TEXT NOT NULL,
                proposed_action TEXT NOT NULL,
                justification TEXT NOT NULL,
                decision TEXT NOT NULL CHECK (
                    decision IN ('approved', 'rejected')
                ),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def record_approval_decision(
    thread_id: str,
    incident_id: str,
    target: str,
    proposed_action: str,
    justification: str,
    approved: bool,
) -> None:
    """Persist a human approval or rejection decision."""
    values = (
        thread_id,
        incident_id,
        target,
        proposed_action,
        justification,
        "approved" if approved else "rejected",
    )

    initialize_audit()

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO approval_audit (
                thread_id,
                incident_id,
                target,
                proposed_action,
                justification,
                decision
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            values,
        )


def get_approval_audit(
    incident_id: str | None = None,
) -> list[dict]:
    """Retrieve approval decisions, optionally filtered by incident."""
    initialize_audit()

    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row

        if incident_id:
            rows = connection.execute(
                """
                SELECT *
                FROM approval_audit
                WHERE incident_id = ?
                ORDER BY id DESC
                """,
                (incident_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT *
                FROM approval_audit
                ORDER BY id DESC
                """
            ).fetchall()

    return [dict(row) for row in rows]
