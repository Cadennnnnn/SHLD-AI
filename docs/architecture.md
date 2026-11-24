# Arquitectura de SHLD AI

```mermaid
flowchart TD
    U[Usuario / Streamlit] --> I[Intake node]
    I -->|saludo| G[Respuesta de saludo]
    I -->|comando de terminal pegado en chat| CMD[Ayuda de ejecución]
    I -->|consulta| E[Evidence retrieval]
    E -->|sin eventos ni memoria| NE[Respuesta segura por falta de evidencia]
    E -->|hay eventos o memoria previa| T[Agente de triage]
    NE --> F[Finalización]
    T --> A[Agente de análisis de evidencia]
    A --> R[Agente coordinador de respuesta]
    R --> D{¿Propuesta sensible?}
    D -->|No| F[Finalización]
    D -->|Sí| H[Human approval: interrupt]
    H --> F
    F --> U
    E <--> SQL[(SQLite: eventos)]
    E <--> RAG[(Chroma: procedimientos)]
    E <--> M[(SQLite: memoria)]
    H --> AUD[(SQLite: auditoría)]
    I -. checkpoints .-> CP[(SQLite: estado LangGraph)]
    T -. skills .-> S[Archivos Markdown de skills]
    A -. skills .-> S
    R -. skills .-> S
```

## Responsabilidades y límites

- **Triage:** caracteriza el incidente sin asumir que un indicador aislado confirma compromiso.
- **Análisis:** correlaciona eventos, procedimientos y memoria, indicando fuentes y brechas.
- **Coordinación:** prioriza la investigación y explica la justificación e impacto de las propuestas.
- **Tools:** conectan el flujo con los almacenes de datos. Text-to-SQL se limita a consultas de lectura.
- **Skills:** instrucciones especializadas versionables en archivos separados.
- **Human approval:** una pausa del grafo que requiere una decisión explícita; la decisión se audita, pero no acciona infraestructura.
- **Persistencia:** el historial de ejecución se conserva con el checkpointer; notas y decisiones tienen tablas separadas.
