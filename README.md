# SHLD AI

Sistema académico multiagente para investigar incidentes de ciberseguridad en un entorno simulado. No se conecta a infraestructura real ni ejecuta acciones de contención.

## Arquitectura

El flujo se implementa con `StateGraph` de LangGraph y un estado compartido `SHLDState` definido como `TypedDict`. El historial de mensajes usa el reductor `add_messages`; los demás campos contienen la evidencia y los resultados de cada etapa.

1. **Intake:** identifica la consulta, idioma e ID de incidente cuando está presente.
2. **Evidence retrieval:** sincroniza el índice de procedimientos con los archivos actuales, consulta eventos en SQLite, recupera procedimientos con RAG y busca notas de memoria. Cuando no se entrega un ID, puede formular una consulta Text-to-SQL de solo lectura.
3. **Control de evidencia:** si no existen eventos ni memoria previa, el grafo genera una respuesta determinista que reconoce la incertidumbre y no propone contención. Los comandos de terminal pegados en el chat se identifican y se explican en vez de tratarse como incidentes.
4. **Agente de triage:** caracteriza el objetivo y los indicadores conocidos.
5. **Agente de análisis de evidencia:** separa hechos, hipótesis, desconocidos y brechas de evidencia.
6. **Agente coordinador de respuesta:** prepara un plan priorizado. Una propuesta sensible solo puede avanzar si el objetivo aparece explícitamente en los eventos recuperados y se verifica un procedimiento local.
7. **Human approval gate:** pausa el grafo con `interrupt()` para registrar una decisión humana antes de continuar con una propuesta sensible.
8. **Finalización:** devuelve el resultado, agrega la decisión de aprobación y guarda observaciones recuperadas, no conclusiones generadas por el modelo.

Las instrucciones especializadas se encuentran en `skills/`. Se mantienen separadas del código para facilitar su actualización. El estado de LangGraph usa SQLite como checkpoint; las notas y decisiones de auditoría también se guardan de forma persistente.

## Requisitos

- Python 3.11 o posterior compatible con las dependencias instaladas.
- Una API key de OpenRouter o Groq para ejecutar los agentes LLM. OpenRouter se configura por defecto y permite seleccionar modelos gratuitos disponibles.
- Acceso a Internet en la primera indexación para descargar el modelo de embeddings de Sentence Transformers.

## Instalación en Windows PowerShell

Desde la raíz del repositorio:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edita `.env` y define `OPENROUTER_API_KEY` (por defecto) y, si corresponde, selecciona un modelo gratuito disponible en `OPENROUTER_MODEL`. Para usar Groq, configura `LLM_PROVIDER=groq` y `GROQ_API_KEY`. No publiques `.env` ni incluyas claves en capturas, logs o el repositorio.

## Ejecutar el flujo desde la terminal

Para una prueba rápida de saludo (no requiere una llamada al modelo):

```powershell
python main.py
```

Para ejecutar una investigación con los agentes LLM:

```powershell
python main.py --query "Investiga el incidente INC-TEST-101"
```

Si el flujo propone contención simulada, la terminal solicitará una decisión humana.

## Preparar procedimientos e iniciar la interfaz

Coloca los archivos `.md` o `.txt` de procedimientos internos en `data/procedures/`. Para indexarlos o actualizar el índice semántico:

```powershell
$env:PYTHONPATH = "src"
python -m shld.rag.ingest
```

Inicia Streamlit desde la raíz:

```powershell
$env:PYTHONPATH = "src"
python -m streamlit run app.py
```

## Pruebas

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests -v
```

Las pruebas de aprobación usan un LLM simulado para comprobar la pausa, reanudación y persistencia de la decisión sin consumir llamadas de API. También hay pruebas para la falta de evidencia, objetivos no confirmados, comandos de terminal pegados en el chat y eliminación de fragmentos RAG obsoletos. La evaluación con un proveedor LLM real debe ejecutarse por separado y documentar modelo, fecha, escenarios y resultados.

## Datos y seguridad

- `data/procedures/`: fuente editable para la recuperación RAG.
- `data/shld.db`: eventos estructurados; la consulta SQL de lenguaje natural está limitada a `SELECT` sobre `security_events`.
- `data/shld_memory.db`: notas persistentes de incidentes.
- `data/shld_audit.db`: decisiones humanas de aprobación o rechazo.
- `data/shld_checkpoints.sqlite`: estado persistente del grafo.
- `data/shld_conversations.db`: registro de conversaciones para volver a abrir hilos guardados desde Streamlit.

Las bases locales y `.env` se excluyen de Git. Usa datos sintéticos claramente identificados para las pruebas. La aprobación nunca ejecuta una acción real.

## Repositorio

Añade aquí el enlace definitivo de GitHub antes de entregar el informe: **pendiente de publicación**.


## Evaluación académica

`evaluation/scenarios.csv` contiene 104 escenarios con comportamiento esperado, fuentes de datos y campos para registrar ejecución y resultado. Se entregan como plan de evaluación; su estado inicial es `not_run`. No deben reportarse como resultados experimentales hasta ejecutarlos y completar las columnas `observed_result` y `passed`.

## Evaluación reproducible de escenarios

`evaluation/scenarios.csv` contiene los 104 casos del plan. Para ejecutarlos y generar resultados fechados, usa PowerShell desde la raíz del proyecto:

```powershell
$env:PYTHONPATH = "src"
python -m evaluation.run_scenarios
```

Para probar primero una categoría o un subconjunto, usa por ejemplo:

```powershell
python -m evaluation.run_scenarios --category greeting
python -m evaluation.run_scenarios --category approval_reject --category approval_accept
python -m evaluation.run_scenarios --limit 10
```

El ejecutor guarda CSV detallado y JSON de resumen en `evaluation/results/`. Las categorías de aprobación usan eventos sintéticos definidos fuera del código en `evaluation/fixtures.csv`; se insertan y eliminan durante cada caso. Las decisiones de aprobación son simuladas por el evaluador para comprobar el registro y nunca ejecutan acciones reales. Las comprobaciones se basan en reglas conservadoras, no en un juez semántico perfecto: los casos `REVIEW` requieren revisión manual y no se incluyen en la tasa de aprobación. El ejecutor usa un checkpoint en memoria para no contaminar los hilos persistentes de la aplicación.

No presentes el número de escenarios como tasa de éxito: incluye en el informe los archivos de resultados generados, la tasa calculada, los casos fallidos y los casos pendientes de revisión.
