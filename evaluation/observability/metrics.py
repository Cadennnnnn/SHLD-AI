"""
Módulo de métricas de observabilidad para SHLD AI (EP3 - ISY0101).

Calcula, a partir de los CSV generados por evaluation/run_scenarios.py:
  - IE1: precisión (tasa de aprobación), consistencia por categoría, frecuencia de errores.
  - IE2: latencia (global y por categoría), uso de recursos (proxy: nº de llamadas al LLM).

El proxy de "uso de recursos" se basa en el recorrido real del grafo
(src/shld/agents/graph.py): solo los nodos triage_agent, analysis_agent y
response_agent invocan al LLM (_invoke_specialist). greeting, command_help y
no_evidence son puramente basados en reglas (0 llamadas). response_agent solo
llama al LLM si hay eventos registrados; si no, responde con una plantilla fija.

Uso:
    python -m evaluation.observability.metrics evaluation/results/scenario_results_20261021_202731.csv
"""
from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# --- Proxy de llamadas al LLM por categoría de escenario ---------------------
# Derivado directamente del enrutamiento de graph.py (route_after_intake,
# route_after_evidence, route_after_response). No es una medición de tokens
# real: se documenta como limitación conocida y mejora propuesta (ver informe,
# sección de recomendaciones / IE7).
LLM_CALLS_BY_PATH = {
    "greeting": 0,            # intake -> greeting (plantilla fija)
    "terminal_command": 0,    # intake -> command_help (plantilla fija)
    "unknown_incident": 0,    # intake -> evidence -> no_evidence (sin LLM)
    "missing_id": 0,          # idem: sin evidencia -> no_evidence
    "insufficient_evidence": 0,
    "memory": 3,              # ruta completa: triage + analysis + response
    "sql_query": 3,
    "procedure_lookup": 3,
    "evidence_gaps": 3,
    "approval_accept": 3,
    "approval_reject": 3,
    "data_integrity": 3,
    "persistence": 3,
    "language": 3,
    "safety": 3,
    "target_validation": 3,
    "rag_freshness": 3,
}
DEFAULT_LLM_CALLS = 3  # categorías no listadas: se asume ruta completa (peor caso)


def load_results(csv_path: Path) -> list[dict[str, Any]]:
    with csv_path.open(encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _llm_calls_for(category: str) -> int:
    return LLM_CALLS_BY_PATH.get(category, DEFAULT_LLM_CALLS)


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)

    # --- IE1.a Precisión (tasa de aprobación, excluyendo REVIEW) ---
    assessed = [r for r in rows if r["assessment_status"] in ("PASS", "FAIL")]
    passed = [r for r in assessed if r["assessment_status"] == "PASS"]
    precision_pct = round(100 * len(passed) / len(assessed), 2) if assessed else None

    # --- IE1.b Consistencia por categoría ---
    by_cat_status: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        by_cat_status[r["category"]][r["assessment_status"]] += 1

    consistency = {}
    for cat, counts in by_cat_status.items():
        n_assessed = counts["PASS"] + counts["FAIL"]
        if n_assessed == 0:
            continue
        pass_rate = counts["PASS"] / n_assessed
        # Una categoría es "inconsistente" si no es 0% ni 100% pass dentro de sí misma.
        is_consistent = pass_rate in (0.0, 1.0)
        consistency[cat] = {
            "pass": counts["PASS"],
            "fail": counts["FAIL"],
            "review": counts["REVIEW"],
            "pass_rate_within_category": round(pass_rate * 100, 1),
            "consistent": is_consistent,
        }

    inconsistent_categories = [c for c, v in consistency.items() if not v["consistent"]]

    # --- IE1.c Frecuencia de errores ---
    exec_errors = [r for r in rows if r["execution_status"] == "error"]
    error_rate_pct = round(100 * len(exec_errors) / total, 2) if total else None

    # --- IE2.a Latencia ---
    times = [float(r["elapsed_seconds"]) for r in rows if r["elapsed_seconds"]]
    latency_overall = {
        "min": round(min(times), 3),
        "max": round(max(times), 3),
        "mean": round(statistics.mean(times), 3),
        "median": round(statistics.median(times), 3),
        "p90": round(statistics.quantiles(times, n=10)[8], 3) if len(times) >= 10 else None,
    }

    latency_by_cat = {}
    times_by_cat = defaultdict(list)
    for r in rows:
        if r["elapsed_seconds"]:
            times_by_cat[r["category"]].append(float(r["elapsed_seconds"]))
    for cat, vals in times_by_cat.items():
        latency_by_cat[cat] = {
            "mean": round(statistics.mean(vals), 3),
            "max": round(max(vals), 3),
            "n": len(vals),
        }
    # Ordenar por latencia media descendente para destacar cuellos de botella.
    latency_by_cat = dict(
        sorted(latency_by_cat.items(), key=lambda kv: -kv[1]["mean"])
    )

    # --- IE2.b Uso de recursos (proxy: llamadas estimadas al LLM) ---
    resource_rows = [
        {"category": r["category"], "llm_calls": _llm_calls_for(r["category"])}
        for r in rows
    ]
    total_llm_calls = sum(x["llm_calls"] for x in resource_rows)
    calls_by_cat = defaultdict(int)
    count_by_cat = Counter()
    for x in resource_rows:
        calls_by_cat[x["category"]] += x["llm_calls"]
        count_by_cat[x["category"]] += 1
    resource_by_cat = {
        cat: {
            "estimated_llm_calls_total": calls_by_cat[cat],
            "scenarios": count_by_cat[cat],
            "estimated_llm_calls_per_scenario": round(calls_by_cat[cat] / count_by_cat[cat], 2),
        }
        for cat in calls_by_cat
    }

    # --- Fallas detectadas (insumo directo para IE3 / informe) ---
    failures = [
        {
            "scenario_id": r["scenario_id"],
            "category": r["category"],
            "status": r["assessment_status"] if r["execution_status"] != "error" else "ERROR",
            "detail": (r["error"] or r["assessment_notes"])[:200],
        }
        for r in rows
        if r["assessment_status"] == "FAIL" or r["execution_status"] == "error"
    ]

    return {
        "total_scenarios": total,
        "precision": {
            "assessed_cases": len(assessed),
            "passed": len(passed),
            "failed": len(assessed) - len(passed),
            "precision_pct_excl_review": precision_pct,
            "review_required": sum(1 for r in rows if r["assessment_status"] == "REVIEW"),
        },
        "consistency": {
            "by_category": consistency,
            "inconsistent_categories": inconsistent_categories,
        },
        "error_rate": {
            "execution_errors": len(exec_errors),
            "error_rate_pct": error_rate_pct,
        },
        "latency_seconds": {
            "overall": latency_overall,
            "by_category": latency_by_cat,
        },
        "resource_usage_proxy": {
            "method": "Conteo de llamadas al LLM por ruta del grafo (ver graph.py); "
                      "no es consumo de tokens real. Mejora propuesta: instrumentar "
                      "usage_metadata de cada respuesta del LLM en una corrida futura.",
            "total_estimated_llm_calls": total_llm_calls,
            "by_category": resource_by_cat,
        },
        "failures": failures,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print("Uso: python -m evaluation.observability.metrics <ruta_al_csv_de_resultados>")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    rows = load_results(csv_path)
    metrics = compute_metrics(rows)

    out_path = csv_path.parent / "observability_metrics.json"
    out_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Métricas calculadas sobre {metrics['total_scenarios']} escenarios.")
    print(f"Precisión (excl. REVIEW): {metrics['precision']['precision_pct_excl_review']}%")
    print(f"Tasa de error de ejecución: {metrics['error_rate']['error_rate_pct']}%")
    print(f"Categorías inconsistentes: {metrics['consistency']['inconsistent_categories']}")
    print(f"Latencia media: {metrics['latency_seconds']['overall']['mean']}s "
          f"(mediana {metrics['latency_seconds']['overall']['median']}s)")
    print(f"Guardado en: {out_path}")


if __name__ == "__main__":
    main()
