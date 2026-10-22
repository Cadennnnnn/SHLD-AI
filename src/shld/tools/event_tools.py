from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from langchain.tools import tool

from shld.database.db import DB_PATH, query_events
from shld.llm import create_llm

ALLOWED_COLUMNS = {
    "id", "event_id", "incident_id", "event_type", "severity",
    "description", "source_ip", "created_at",
}
FORBIDDEN_SQL = (
    "insert", "update", "delete", "drop", "alter", "create", "replace",
    "attach", "detach", "pragma", "vacuum", "into", "load_extension",
)

@tool
def search_security_events(incident_id: str) -> str:
    """Search recorded security events associated with an incident ID."""
    if not incident_id.strip():
        return "Error: incident_id is required."
    events = query_events(incident_id)
    if not events:
        return f"No security events found for incident {incident_id}."
    return "\n".join(
        f"Event: {event['event_id']} | Incident: {event['incident_id']} | "
        f"Type: {event['event_type']} | Severity: {event['severity']} | "
        f"Description: {event['description']} | "
        f"Source IP: {event['source_ip'] or 'Unknown'} | "
        f"Created at: {event['created_at']}"
        for event in events
    )

def _generate_select(question: str) -> str:
    prompt = (
        "Convert the user's question into one SQLite SELECT statement for the "
        "table security_events only. Available columns: id, event_id, incident_id, "
        "event_type, severity, description, source_ip, created_at. Use only "
        "read-only SELECT statements; never use joins, subqueries, PRAGMA, comments, "
        "multiple statements, or any other table. Return SQL only, without markdown.\n"
        f"Question: {question}"
    )
    result = create_llm().invoke(prompt)
    content = getattr(result, "content", result)
    sql = content if isinstance(content, str) else str(content)
    sql = re.sub(r"^```(?:sql)?\s*|\s*```$", "", sql.strip(), flags=re.IGNORECASE)
    return sql.strip().rstrip(";")

def _validate_select(sql: str) -> None:
    if not sql or not re.match(r"(?is)^select\b", sql):
        raise ValueError("Generated query is not a SELECT statement.")
    if ";" in sql or "--" in sql or "/*" in sql or "*/" in sql:
        raise ValueError("Multiple statements and SQL comments are not allowed.")
    lowered = sql.lower()
    if any(re.search(rf"\b{word}\b", lowered) for word in FORBIDDEN_SQL):
        raise ValueError("The generated query contains a forbidden SQL operation.")
    if re.search(r"\b(join|union|intersect|except|with|select)\b", lowered[6:]):
        raise ValueError("Subqueries and set operations are not allowed.")
    table_names = re.findall(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", lowered)
    if not table_names or any(table != "security_events" for table in table_names):
        raise ValueError("Queries may read only from security_events.")
    selected = sql.split(" from ", 1)[0].split(" FROM ", 1)[0]
    selected_without_aliases = re.sub(
        r"(?i)\bAS\s+[a-zA-Z_][a-zA-Z0-9_]*", "", selected
    )
    if "*" not in selected_without_aliases:
        identifiers = re.findall(
            r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
            selected_without_aliases[6:],
        )
        if any(item.lower() not in ALLOWED_COLUMNS | {"as", "distinct", "count", "avg", "min", "max", "sum"} for item in identifiers):
            raise ValueError("The query uses an unsupported column or expression.")

@tool
def query_security_events_nl(question: str) -> str:
    """Translate a natural-language question into a restricted read-only SQL query over security_events."""
    if not question.strip():
        return "A question about recorded security events is required."
    try:
        sql = _generate_select(question)
        _validate_select(sql)
        db_path = Path(DB_PATH).resolve()
        if not db_path.exists():
            return "No security event database exists yet."
        connection = sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(sql).fetchmany(100)
        finally:
            connection.close()
        if not rows:
            return f"No recorded security events matched the question. Read-only SQL: {sql}"
        formatted = "\n".join(str(dict(row)) for row in rows)
        return f"Read-only SQL used: {sql}\nMatching recorded events:\n{formatted}"
    except Exception as exc:
        return (
            "The natural-language SQL query could not be executed safely. "
            f"Reason: {type(exc).__name__}: {exc}. No data was modified."
        )
