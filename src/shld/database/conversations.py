import sqlite3
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DB_PATH = PROJECT_ROOT / "data" / "shld_conversations.db"

def initialize_conversations() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                thread_id TEXT PRIMARY KEY,
                title TEXT NOT NULL DEFAULT 'New investigation',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

def create_conversation(title: str = "New investigation") -> str:
    initialize_conversations()
    thread_id = str(uuid.uuid4())
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            "INSERT INTO conversations (thread_id, title) VALUES (?, ?)",
            (thread_id, title.strip()[:80] or "New investigation"),
        )
    return thread_id

def list_conversations(limit: int = 50) -> list[dict[str, str]]:
    initialize_conversations()
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT thread_id, title, created_at, updated_at
            FROM conversations
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 200)),),
        ).fetchall()
    return [dict(row) for row in rows]

def touch_conversation(thread_id: str, first_message: str | None = None) -> None:
    initialize_conversations()
    title = (first_message or "").strip().replace("\n", " ")[:80]
    with sqlite3.connect(DB_PATH) as connection:
        existing = connection.execute(
            "SELECT 1 FROM conversations WHERE thread_id = ?",
            (thread_id,),
        ).fetchone()
        if not existing:
            connection.execute(
                "INSERT INTO conversations (thread_id, title) VALUES (?, ?)",
                (thread_id, title or "New investigation"),
            )
        elif title:
            connection.execute(
                """
                UPDATE conversations
                SET title = CASE WHEN title = 'New investigation' THEN ? ELSE title END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE thread_id = ?
                """,
                (title, thread_id),
            )
        else:
            connection.execute(
                "UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
                (thread_id,),
            )
