"""
trace_analysis.py
-----------------
Genera un reporte de trazabilidad consultando las bases de datos SQLite del sistema SHLD-AI.
Produce: evaluation/results/trace_report.json

Bases consultadas:
  - shld_conversations.db  → historial de conversaciones
  - shld_audit.db          → decisiones de aprobación humana
  - shld.db                → eventos de seguridad
"""

import json
import sqlite3
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
DATA_DIR = Path("data")
RESULTS_DIR = Path("evaluation/results")


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------

def query_db(db_filename: str, sql: str) -> list[dict]:
    """
    Ejecuta una consulta SQL sobre una base SQLite ubicada en DATA_DIR.

    Args:
        db_filename: Nombre del archivo .db (ej. 'shld.db').
        sql: Sentencia SELECT a ejecutar.

    Returns:
        Lista de filas como diccionarios. Retorna [] si el archivo no existe.
    """
    db_path = DATA_DIR / db_filename
    if not db_path.exists():
        print(f"[AVISO] No se encontró la base de datos: {db_path}")
        return []

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"[ERROR] Consulta fallida en {db_filename}: {e}")
        return []


def build_report(conversations: list, audit: list, events: list) -> dict:
    """
    Construye el diccionario de reporte a partir de los datos consultados.

    Args:
        conversations: Registros de shld_conversations.db
        audit: Registros de shld_audit.db
        events: Registros de shld.db (máx. 20 más recientes en el reporte)

    Returns:
        Diccionario estructurado listo para serializar a JSON.
    """
    decision_counts = Counter(row["decision"] for row in audit)

    return {
        "conversations": {
            "total": len(conversations),
            "data": conversations,
        },
        "audit": {
            "total": len(audit),
            "approved": decision_counts.get("approved", 0),
            "rejected": decision_counts.get("rejected", 0),
            "data": audit,
        },
        "security_events": {
            "total": len(events),
            "data": events[:20],  # limitar para no inflar el archivo
        },
    }


# ---------------------------------------------------------------------------
# Script principal
# ---------------------------------------------------------------------------

def main():
    """Consulta las bases de datos y guarda el reporte de trazabilidad."""

    conversations = query_db(
        "shld_conversations.db",
        "SELECT * FROM conversations ORDER BY updated_at DESC",
    )
    audit = query_db(
        "shld_audit.db",
        "SELECT * FROM approval_audit ORDER BY id DESC",
    )
    events = query_db(
        "shld.db",
        "SELECT * FROM security_events ORDER BY created_at DESC",
    )

    report = build_report(conversations, audit, events)

    # Crear directorio de resultados si no existe
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    output_path = RESULTS_DIR / "trace_report.json"
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Resumen en consola
    print(f"Conversaciones registradas : {len(conversations)}")
    print(f"Decisiones de aprobación   : {len(audit)}")
    print(f"Eventos de seguridad       : {len(events)}")
    print(f"Reporte guardado en        : {output_path}")


if __name__ == "__main__":
    main()