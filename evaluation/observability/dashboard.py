"""
Dashboard de observabilidad para SHLD AI (EP3 - ISY0101, IE4).

Ejecutar desde la raíz del proyecto:
    python -m evaluation.observability.metrics evaluation/results/<archivo_de_resultados>.csv
    streamlit run evaluation/observability/dashboard.py

Lee evaluation/results/observability_metrics.json (generado por metrics.py)
y el CSV de resultados correspondiente para mostrar precisión, consistencia,
frecuencia de errores, latencia y uso de recursos estimado.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

RESULTS_DIR = Path(__file__).resolve().parents[2] / "evaluation" / "results"
METRICS_PATH = RESULTS_DIR / "observability_metrics.json"

st.set_page_config(page_title="SHLD AI — Observabilidad", layout="wide")
st.title("📊 SHLD AI — Dashboard de Observabilidad")
st.caption("EP3 ISY0101 · Métricas calculadas sobre ejecuciones reales de evaluation/run_scenarios.py")

if not METRICS_PATH.exists():
    st.error(
        f"No se encontró {METRICS_PATH.name}. Genera las métricas primero:\n\n"
        f"`python -m evaluation.observability.metrics evaluation/results/<archivo>.csv`"
    )
    st.stop()

metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

# --- Fila de métricas principales (IE1 + IE2 de un vistazo) -----------------
col1, col2, col3, col4 = st.columns(4)
col1.metric("Precisión (excl. REVIEW)", f"{metrics['precision']['precision_pct_excl_review']}%")
col2.metric("Tasa de error de ejecución", f"{metrics['error_rate']['error_rate_pct']}%")
col3.metric("Latencia media", f"{metrics['latency_seconds']['overall']['mean']}s")
col4.metric("Latencia mediana", f"{metrics['latency_seconds']['overall']['median']}s")

st.divider()

tab1, tab2, tab3, tab4 = st.tabs([
    "Precisión y consistencia (IE1)",
    "Latencia y recursos (IE2)",
    "Trazabilidad de fallas (IE3)",
    "Datos crudos",
])

# --- TAB 1: Precisión y consistencia -----------------------------------------
with tab1:
    st.subheader("Resultado global")
    p = metrics["precision"]
    st.write(
        f"De **{metrics['total_scenarios']} escenarios**, {p['assessed_cases']} fueron evaluables "
        f"automáticamente: **{p['passed']} PASS**, **{p['failed']} FAIL**, "
        f"**{p['review_required']} requieren revisión manual** (excluidos del cálculo de precisión)."
    )

    st.subheader("Consistencia por categoría")
    st.caption(
        "Una categoría es 'consistente' si el agente se comporta igual (100% pass o 100% fail) "
        "ante todos los escenarios de ese tipo. Mezcla de PASS/FAIL en la misma categoría = inconsistencia."
    )
    cons_df = pd.DataFrame.from_dict(metrics["consistency"]["by_category"], orient="index")
    cons_df = cons_df.sort_values("pass_rate_within_category")
    st.dataframe(cons_df, width='stretch')

    inconsistent = metrics["consistency"]["inconsistent_categories"]
    if inconsistent:
        st.warning(f"Categorías inconsistentes detectadas: {', '.join(inconsistent)}")

# --- TAB 2: Latencia y recursos -----------------------------------------------
with tab2:
    st.subheader("Latencia media por categoría (segundos)")
    lat_df = pd.DataFrame.from_dict(metrics["latency_seconds"]["by_category"], orient="index")
    st.bar_chart(lat_df["mean"])
    st.caption(
        "Las categorías con aprobación humana (approval_accept / approval_reject) son el cuello "
        "de botella principal: ~50s frente a <2s de las rutas resueltas por reglas."
    )
    st.dataframe(lat_df, width='stretch')

    st.subheader("Uso de recursos estimado (llamadas al LLM por categoría)")
    st.caption(metrics["resource_usage_proxy"]["method"])
    res_df = pd.DataFrame.from_dict(
        metrics["resource_usage_proxy"]["by_category"], orient="index"
    )
    st.bar_chart(res_df["estimated_llm_calls_total"])
    st.metric("Llamadas al LLM estimadas (total, 104 escenarios)",
              metrics["resource_usage_proxy"]["total_estimated_llm_calls"])

# --- TAB 3: Trazabilidad de fallas -------------------------------------------
with tab3:
    st.subheader("Escenarios fallidos o con error de ejecución")
    if metrics["failures"]:
        fail_df = pd.DataFrame(metrics["failures"])
        st.dataframe(fail_df, width='stretch')
    else:
        st.success("No se registraron fallas en esta corrida.")

    st.subheader("Lectura de las fallas (para el informe / presentación)")
    st.markdown(
        """
- **greeting (SHLD-003, 009, 010):** el detector de saludo por regex no cubrió todas las variantes
  de entrada — falla de cobertura, no de razonamiento del LLM.
- **approval_accept (SHLD-085):** el grafo no pausó para aprobación cuando debía — posible falla de
  lógica en la verificación de evidencia/objetivo antes de abrir el `approval_gate`. Prioridad alta
  para revisión de código.
- **language (SHLD-094):** el LLM no respondió en el idioma solicitado — riesgo de consistencia del
  modelo, no de la arquitectura del grafo.
- **target_validation (SHLD-102):** `RateLimitError 429` — límite diario de tokens del modelo gratuito
  agotado. Es una falla de infraestructura/cuota, no del diseño del agente.
        """
    )

# --- TAB 4: Datos crudos ------------------------------------------------------
with tab4:
    st.json(metrics)