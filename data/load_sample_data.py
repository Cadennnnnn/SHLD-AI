"""
Carga datos de prueba para demostrar el flujo completo de SHLD-AI.
Ejecutar desde la raíz del proyecto:
    python data/load_sample_data.py
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "shld.db"

EVENTS = [
    # Incidente 1: Acceso no autorizado — activa flujo completo con aprobación
    ("EVT-001", "INC-2024-001", "unauthorized_access", "critical",
     "Login fallido repetido desde IP externa hacia servidor DB-01. "
     "Se detectaron 47 intentos en 3 minutos. Patrón consistente con ataque de fuerza bruta.",
     "185.220.101.45"),

    ("EVT-002", "INC-2024-001", "privilege_escalation", "high",
     "Intento de escalación de privilegios detectado en DB-01 tras acceso exitoso "
     "con credenciales de usuario 'backup_svc'. Proceso ejecutado: net localgroup administrators.",
     "185.220.101.45"),

    ("EVT-003", "INC-2024-001", "data_exfiltration", "critical",
     "Transferencia de datos inusual desde DB-01 hacia IP externa. "
     "Volumen: 2.3 GB en 8 minutos. Puerto destino: 443. Protocolo: HTTPS tunelizado.",
     "185.220.101.45"),

    # Incidente 2: Malware — para demostrar variabilidad de categorías
    ("EVT-004", "INC-2024-002", "malware_detected", "high",
     "Proceso sospechoso detectado en WS-042: svchost32.exe ejecutándose desde "
     "C:\\Users\\Public\\Downloads. Firma digital no válida. Comunicación C2 detectada.",
     "10.0.1.42"),

    ("EVT-005", "INC-2024-002", "lateral_movement", "medium",
     "Movimiento lateral detectado desde WS-042 hacia servidores internos. "
     "Protocolo SMB utilizado para escaneo de red interna en rango 10.0.1.0/24.",
     "10.0.1.42"),

    # Incidente 3: Fuga de datos — para escenario de revisión manual
    ("EVT-006", "INC-2024-003", "data_leak", "medium",
     "Empleado con acceso a datos sensibles de clientes realizó descarga masiva "
     "de registros fuera de horario laboral (02:34 AM). Volumen: 15,000 registros.",
     "10.0.5.88"),
]


def load():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
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
    """)

    inserted = 0
    skipped = 0
    for event in EVENTS:
        try:
            conn.execute(
                "INSERT INTO security_events "
                "(event_id, incident_id, event_type, severity, description, source_ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                event
            )
            inserted += 1
        except sqlite3.IntegrityError:
            skipped += 1

    conn.commit()
    conn.close()

    print(f"Eventos insertados: {inserted}")
    print(f"Eventos ya existentes (omitidos): {skipped}")
    print(f"Base de datos: {DB_PATH}")
    print()
    print("Incidentes disponibles para probar el agente:")
    print("  INC-2024-001 — Acceso no autorizado + exfiltración (severity: CRITICAL)")
    print("  INC-2024-002 — Malware + movimiento lateral (severity: HIGH)")
    print("  INC-2024-003 — Fuga de datos interna (severity: MEDIUM)")
    print()
    print("Sugerencia de demo:")
    print("  1. Escribe: 'tengo un incidente de acceso no autorizado'")
    print("  2. Cuando pida el ID, escribe: 'INC-2024-001'")
    print("  3. El agente debería encontrar 3 eventos y proponer aislar el servidor DB-01")
    print("  4. Aparecerá el gate de aprobación humana para aprobar/rechazar la acción")


if __name__ == "__main__":
    load()