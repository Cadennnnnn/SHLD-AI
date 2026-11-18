from __future__ import annotations

import re
from contextlib import ExitStack
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.config import get_config
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import interrupt

from shld.database.audit import record_approval_decision
from shld.llm import create_llm
from shld.rag.ingest import ingest_procedures
from shld.tools.event_tools import query_security_events_nl, search_security_events
from shld.tools.memory_tools import save_incident_memory, search_incident_memory
from shld.tools.rag_tools import search_security_procedures


class SHLDState(TypedDict, total=False):
    """Typed state shared by every specialist node in the SHLD AI graph."""
    messages: Annotated[list[AnyMessage], add_messages]
    thread_id: str
    user_request: str
    language: str
    incident_id: str
    objective: str
    is_greeting: bool
    is_terminal_command: bool
    event_evidence: str
    procedure_evidence: str
    memory_evidence: str
    triage_assessment: str
    evidence_analysis: str
    response_plan: str
    approval_request: dict[str, Any] | None
    approval_decision: str
    final_response: str
    errors: list[str]

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CHECKPOINT_PATH = PROJECT_ROOT / "data" / "shld_checkpoints.sqlite"
SKILLS_DIR = PROJECT_ROOT / "skills"


SYSTEM_RULES = """
You are a defensive cybersecurity investigation specialist for SHLD AI.
All data and actions are simulated. Never claim real systems were modified.
Respond in the user's language. Distinguish observed facts, hypotheses, and
unknowns. Never invent logs, IPs, policies, timestamps, affected assets, or
outcomes. Cite the supplied evidence sources by name when possible. If evidence
is missing, say so. Do not recommend sensitive containment without explaining
the evidence and impact. Approval records a simulation only; it never executes
a real action.
"""

def _skill(name: str) -> str:
    path = SKILLS_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return "Use a cautious, evidence-based defensive cybersecurity workflow."

def _latest_user_text(messages: list[AnyMessage] | None) -> str:
    for message in reversed(messages or []):
        if isinstance(message, HumanMessage):
            content = message.content
            return content if isinstance(content, str) else str(content)
    return ""

def _language(text: str) -> str:
    spanish_markers = (" el ", " la ", " de ", " que ", " incidente", " revisar", " necesito", " hola", " por favor")
    normalized = f" {text.lower()} "
    return "Spanish" if any(marker in normalized for marker in spanish_markers) or any(c in text.lower() for c in ("¿", "¡", "ñ")) else "English"

def _is_greeting_only(text: str) -> bool:
    normalized = re.sub(r"[^\wáéíóúüñ ]", "", text.lower()).strip()
    greetings = {
        "hola", "hola shld", "buenas", "buenos dias", "buenas tardes",
        "buenas noches", "hello", "hi", "hey", "hello shld", "good morning",
        "good afternoon", "good evening", "gracias", "muchas gracias",
    }
    return normalized in greetings

def _is_terminal_command(text: str) -> bool:
    """Detect shell commands accidentally pasted into the chat interface."""
    normalized = text.strip().lower()
    return bool(
        re.match(r"^(?:\$env:pythonpath|python(?:\.exe)?\s+main\.py|python\s+-m\s+(?:streamlit|pytest))\b", normalized)
        or "python main.py --query" in normalized
    )


def _has_recorded_events(evidence: str) -> bool:
    """Return true only when the tool output contains actual event rows."""
    text = (evidence or "").strip().lower()
    if not text:
        return False
    negative_markers = (
        "no security events found", "no recorded security events",
        "no security event database exists", "could not be executed safely",
        "event lookup failed", "error:",
    )
    if any(marker in text for marker in negative_markers):
        return False
    return "event:" in text or "matching recorded events:" in text


def _has_previous_memory(memory: str) -> bool:
    text = (memory or "").strip().lower()
    return bool(text) and "no previous memory found" not in text and "no previous notes" not in text


def _verified_procedure_sources(procedure_evidence: str) -> list[str]:
    """Keep only retrieved source names that still exist under data/procedures."""
    procedure_dir = PROJECT_ROOT / "data" / "procedures"
    verified: list[str] = []
    for source in re.findall(r"(?im)^Source:\s*(.+?)\s*$", procedure_evidence or ""):
        candidate = (procedure_dir / source).resolve()
        try:
            candidate.relative_to(procedure_dir.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            relative = candidate.relative_to(procedure_dir.resolve()).as_posix()
            if relative not in verified:
                verified.append(relative)
    return verified


def _safe_no_evidence_response(state: SHLDState) -> str:
    incident_id = state.get("incident_id") or "no proporcionado"
    language = state.get("language", "English")
    sources = _verified_procedure_sources(state.get("procedure_evidence", ""))
    if language == "Spanish":
        lines = [
            f"## Resultado de la investigación: {incident_id}",
            "### Hechos verificados",
            "- La consulta no devolvió eventos de seguridad registrados para este incidente.",
            "- Con la evidencia disponible no se puede confirmar ni descartar un compromiso.",
            "### Hipótesis no confirmadas",
            "- El identificador podría ser incorrecto o no corresponder a registros cargados.",
            "- Las fuentes consultadas podrían tener un alcance temporal o técnico incompleto.",
            "Estas posibilidades no se consideran hechos y requieren verificación.",
            "### Próximas verificaciones seguras",
            "1. Confirmar el ID del incidente y el rango temporal de la consulta.",
            "2. Verificar qué fuentes de eventos están cargadas y disponibles.",
            "3. Repetir la consulta con el identificador y el alcance confirmados.",
            "No se recomienda aislar, bloquear ni modificar activos sin evidencia que identifique el objetivo y justifique la acción.",
            "No se han supuesto scripts, activos, responsables ni acciones ejecutadas.",
        ]
        if sources:
            lines.append("Procedimientos recuperados y verificados: " + ", ".join(sources) + ".")
        else:
            lines.append("No se verificó ningún archivo de procedimiento recuperado para esta consulta.")
        if _has_previous_memory(state.get("memory_evidence", "")):
            lines.append("Existen notas previas; deben contrastarse con registros actuales antes de tratarlas como evidencia confirmada.")
        return "\n\n".join(lines)

    lines = [
        f"## Investigation result: {incident_id}",
        "### Verified facts",
        "- The query returned no recorded security events for this incident.",
        "- The available evidence neither confirms nor rules out compromise.",
        "### Unconfirmed hypotheses",
        "- The incident identifier may be incorrect or may not match loaded records.",
        "- The queried sources may have incomplete time or technical coverage.",
        "These possibilities are not facts and require verification.",
        "### Safe next checks",
        "1. Confirm the incident ID and query time range.",
        "2. Verify which event sources are loaded and available.",
        "3. Repeat the query with the confirmed identifier and scope.",
        "Do not isolate, block, or modify assets without evidence identifying the target and justifying the action.",
        "No scripts, assets, owners, or executed actions have been assumed.",
    ]
    if sources:
        lines.append("Retrieved and verified procedures: " + ", ".join(sources) + ".")
    else:
        lines.append("No retrieved procedure file was verified for this query.")
    if _has_previous_memory(state.get("memory_evidence", "")):
        lines.append("Prior notes exist; verify them against current records before treating them as confirmed evidence.")
    return "\n\n".join(lines)


def _extract_incident_id(text: str) -> str:
    # Primero busca el patrón INC-XXXX-XXX directamente (más específico)
    direct = re.search(r"\bINC[-_][A-Z0-9]+[-_][A-Z0-9]+\b", text, re.IGNORECASE)
    if direct:
        return direct.group(0).upper()
    # Luego busca INC-XXXX simple
    simple = re.search(r"\bINC[-_][A-Z0-9]+\b", text, re.IGNORECASE)
    if simple:
        return simple.group(0).upper()
    # Finalmente busca "incidente/incident + ID"
    contextual = re.search(
        r"(?i)\b(?:incident|incidente)\s*(?:id|identificador)?\s*[:#=]?\s*([A-Z0-9][A-Z0-9_-]{2,})",
        text,
    )
    if contextual:
        return contextual.group(1).upper()
    return ""

def _invoke_specialist(role: str, skill_file: str, task: str, state: SHLDState) -> str:
    llm = create_llm()
    prompt = (
        f"{SYSTEM_RULES}\n\nSPECIALIST ROLE: {role}\n\n"
        f"SKILL INSTRUCTIONS:\n{_skill(skill_file)}\n\n"
        f"USER REQUEST:\n{state.get('user_request', '')}\n\n"
        f"INCIDENT ID: {state.get('incident_id') or 'not provided'}\n"
        f"OBJECTIVE: {state.get('objective') or state.get('user_request', '')}\n\n"
        f"RECORDED EVENT EVIDENCE:\n{state.get('event_evidence') or 'No event evidence retrieved.'}\n\n"
        f"INTERNAL PROCEDURE EVIDENCE:\n{state.get('procedure_evidence') or 'No procedure evidence retrieved.'}\n\n"
        f"PREVIOUS INCIDENT MEMORY:\n{state.get('memory_evidence') or 'No previous notes retrieved.'}\n\n"
        f"TRIAGE ASSESSMENT FROM THE PREVIOUS AGENT:\n{state.get('triage_assessment') or 'No triage assessment has been produced yet.'}\n\n"
        f"EVIDENCE ANALYSIS FROM THE PREVIOUS AGENT:\n{state.get('evidence_analysis') or 'No evidence analysis has been produced yet.'}\n\n"
        f"PREVIOUS SPECIALIST OUTPUT / TASK CONTEXT:\n{task}\n\n"
        f"Write a concise, evidence-grounded response in {state.get('language', 'English')}."
    )
    result = llm.invoke(prompt)
    content = getattr(result, "content", result)
    return content if isinstance(content, str) else str(content)

def intake_node(state: SHLDState) -> dict[str, Any]:
    text = _latest_user_text(state.get("messages"))
    runtime_config = get_config()
    thread_id = str(runtime_config.get("configurable", {}).get("thread_id", "unknown"))

    # Extrae el ID del mensaje actual; si no hay, busca en TODOS los mensajes previos
    incident_id = _extract_incident_id(text)
    if not incident_id:
        for msg in reversed(state.get("messages", []) or []):
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            incident_id = _extract_incident_id(content)
            if incident_id:
                break
    # Último fallback: conservar el ID que ya tenía el estado
    incident_id = incident_id or state.get("incident_id", "")

    objective = text.strip()
    return {
        "user_request": text,
        "thread_id": thread_id,
        "language": _language(text),
        "incident_id": incident_id,
        "objective": objective,
        "is_greeting": _is_greeting_only(text),
        "is_terminal_command": _is_terminal_command(text),
        "approval_request": None,
        "approval_decision": "",
        "errors": [],
    }

def greeting_node(state: SHLDState) -> dict[str, Any]:
    if state.get("language") == "Spanish":
        response = (
            "Hola. Soy SHLD AI, un sistema de investigación defensiva de "
            "ciberseguridad en modo simulado. Puedo revisar eventos registrados, "
            "consultar procedimientos y organizar un plan de investigación. "
            "¿Qué incidente o problema quieres analizar?"
        )
    else:
        response = (
            "Hello. I’m SHLD AI, a defensive cybersecurity investigation system "
            "running in simulation mode. I can review recorded events, consult "
            "procedures, and organize an investigation plan. What would you like "
            "to investigate?"
        )
    return {"final_response": response, "messages": [AIMessage(content=response)]}

def terminal_command_help_node(state: SHLDState) -> dict[str, Any]:
    if state.get("language") == "Spanish":
        response = (
            "Ese texto parece ser un comando de PowerShell, no una solicitud de investigación. "
            "Ejecútalo en la terminal situada en la carpeta raíz del proyecto, no en el cuadro de chat.\n\n"
            "Ejemplo: `python main.py --query \"Investiga el incidente INC-TEST-101\"`\n\n"
            "También puedes escribir aquí directamente: `Investiga el incidente INC-TEST-101`."
        )
    else:
        response = (
            "That looks like a PowerShell command, not an investigation request. "
            "Run it in the terminal from the project root, not in the chat input.\n\n"
            "Example: `python main.py --query \"Investigate incident INC-TEST-101\"`\n\n"
            "You can also type directly here: `Investigate incident INC-TEST-101`."
        )
    return {"final_response": response, "messages": [AIMessage(content=response)]}


def evidence_node(state: SHLDState) -> dict[str, Any]:
    incident_id = state.get("incident_id", "")
    objective = state.get("objective", "")
    errors: list[str] = []
    event_evidence = ""
    procedure_evidence = ""
    memory_evidence = ""

    try:
        # Synchronize the index before retrieval so edits and deletions are reflected.
        ingest_procedures()
    except Exception as exc:
        errors.append(f"Procedure index synchronization failed: {type(exc).__name__}: {exc}")

    try:
        if incident_id:
            event_evidence = search_security_events.invoke({"incident_id": incident_id})
        elif objective:
            event_evidence = query_security_events_nl.invoke({"question": objective})
    except Exception as exc:
        errors.append(f"Event lookup failed: {type(exc).__name__}: {exc}")

    try:
        procedure_evidence = search_security_procedures.invoke({"query": objective})
    except Exception as exc:
        errors.append(f"Procedure retrieval failed: {type(exc).__name__}: {exc}")

    try:
        if incident_id:
            memory_evidence = search_incident_memory.invoke({"incident_id": incident_id})
    except Exception as exc:
        errors.append(f"Memory lookup failed: {type(exc).__name__}: {exc}")

    return {
        "event_evidence": event_evidence,
        "procedure_evidence": procedure_evidence,
        "memory_evidence": memory_evidence,
        "errors": errors,
    }

def triage_agent_node(state: SHLDState) -> dict[str, Any]:
    result = _invoke_specialist(
        "Incident triage specialist",
        "incident_triage.md",
        "Classify the current investigative objective, identify known indicators, "
        "and state what is and is not established by the evidence.",
        state,
    )
    return {"triage_assessment": result}

def analysis_agent_node(state: SHLDState) -> dict[str, Any]:
    result = _invoke_specialist(
        "Evidence analysis specialist",
        "evidence_analysis.md",
        "Compare recorded events with internal procedures and previous notes. "
        "Separate facts from hypotheses, identify evidence gaps, and cite sources.",
        state,
    )
    return {"evidence_analysis": result}

def response_agent_node(state: SHLDState) -> dict[str, Any]:
    # A missing event record is a hard evidence gate: do not let an LLM invent
    # operational steps, scripts, targets, or a containment proposal.
    if not _has_recorded_events(state.get("event_evidence", "")):
        return {
            "response_plan": _safe_no_evidence_response(state),
            "approval_request": None,
        }

    combined = (
        f"TRIAGE:\n{state.get('triage_assessment', '')}\n\n"
        f"EVIDENCE ANALYSIS:\n{state.get('evidence_analysis', '')}"
    )
    result = _invoke_specialist(
        "Response coordination specialist",
        "response_coordination.md",
        "Prepare a prioritized investigation plan. Any sensitive containment proposal must name a target explicitly present in recorded event evidence, cite the evidence, and explain impact. If evidence does not support an action, recommend verification instead. Never invent scripts or claim execution.",
        {**state, "response_plan": combined},
    )

    result_lower = result.lower()
    response_has_proposal = any(
        marker in result_lower
        for marker in (
            "proposed containment", "recommend isolating", "recommend blocking",
            "recommend disabling", "recommend quarantining", "se recomienda aislar",
            "se recomienda bloquear", "propuesta de contención", "aislar el equipo",
            "bloquear la dirección", "proponer aislamiento", "propuesta de aislamiento",
        )
    )
    target = _extract_target(state.get("user_request", ""))
    event_evidence = state.get("event_evidence", "")
    target_supported = bool(target) and target.casefold() in event_evidence.casefold()
    procedure_sources = _verified_procedure_sources(state.get("procedure_evidence", ""))

    approval_request = None
    if response_has_proposal:
        if not target_supported or not procedure_sources:
            language = state.get("language", "English")
            if language == "Spanish":
                safe_result = (
                    "No se presenta una propuesta de contención para aprobación. "
                    "El objetivo no está confirmado explícitamente en los eventos registrados "
                    "o no se verificó un procedimiento interno aplicable. Verifica el activo, "
                    "la evidencia asociada y el procedimiento antes de considerar una acción sensible."
                )
            else:
                safe_result = (
                    "The containment proposal is not being submitted for approval. The target is not "
                    "explicitly confirmed in recorded events, or no applicable internal procedure "
                    "was verified. Verify the asset, supporting evidence, and procedure before "
                    "considering a sensitive action."
                )
            return {"response_plan": safe_result, "approval_request": None}

        approval_request = {
            "type": "simulated_containment_approval",
            "thread_id": state.get("thread_id", "unknown"),
            "incident_id": state.get("incident_id") or "UNSPECIFIED",
            "target": target,
            "proposed_action": result[:1200],
            "justification": (
                "The proposal names a target found in recorded event evidence and an internal "
                "procedure source was verified. Human review is still required."
            ),
            "notice": "Simulation only. No real system action will be executed.",
            "allowed_decisions": ["approve", "reject"],
        }
    return {"response_plan": result, "approval_request": approval_request}

def _extract_target(text: str) -> str:
    patterns = (
        # Captura DB-01, WS-042, SRV-PROD, SERVER-01, etc.
        r"\b(?:DB|WS|SRV|PC|SERVER|SERVIDOR|HOST)[-_][A-Za-z0-9_.-]+\b",
        r"\b(?:host|srv|pc|server|servidor)[-_][A-Za-z0-9_.-]+\b",
        r"(?i)\b(?:target|host|asset|equipo|activo|servidor)\s*[:=]?\s*([A-Za-z0-9_.-]+)",
        # IPs
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1) if match.lastindex else match.group(0)
    return ""

def approval_gate_node(state: SHLDState) -> dict[str, Any]:
    proposal = state.get("approval_request") or {}
    decision = interrupt(proposal)
    approved = isinstance(decision, dict) and decision.get("approved") is True
    record_approval_decision(
        thread_id=str(proposal.get("thread_id", "unknown")),
        incident_id=str(proposal.get("incident_id", "UNSPECIFIED")),
        target=str(proposal.get("target", "Target not confirmed")),
        proposed_action=str(proposal.get("proposed_action", "")),
        justification=str(proposal.get("justification", "")),
        approved=approved,
    )
    result = "approved" if approved else "rejected"
    return {"approval_decision": result, "approval_request": None}

def finalize_node(state: SHLDState) -> dict[str, Any]:
    response = state.get("response_plan", "").strip()
    if state.get("approval_decision") == "approved":
        response += (
            "\n\nHuman decision: the simulated proposal was APPROVED and recorded. "
            "No real system action was executed."
        )
    elif state.get("approval_decision") == "rejected":
        response += (
            "\n\nHuman decision: the simulated proposal was REJECTED and recorded. "
            "No action was executed."
        )

    errors = state.get("errors") or []
    if errors:
        response += "\n\nData-source limitations:\n- " + "\n- ".join(errors)

    incident_id = state.get("incident_id", "")
    event_evidence = state.get("event_evidence", "")
    if incident_id and _has_recorded_events(event_evidence):
        sources = ", ".join(_verified_procedure_sources(state.get("procedure_evidence", ""))) or "none verified"
        # Persist only retrieved observations, never model-generated conclusions.
        note = (
            f"Recorded event evidence for {incident_id}:\n{event_evidence[:3000]}\n"
            f"Verified procedure sources consulted: {sources}."
        )
        try:
            save_incident_memory.invoke({"incident_id": incident_id, "content": note})
        except Exception as exc:
            response += f"\n\nMemory persistence warning: {type(exc).__name__}: {exc}"

    return {"final_response": response, "messages": [AIMessage(content=response)]}

def route_after_intake(state: SHLDState) -> str:
    if state.get("is_greeting"):
        return "greeting"
    if state.get("is_terminal_command"):
        return "command_help"
    return "evidence"


def route_after_evidence(state: SHLDState) -> str:
    if not _has_recorded_events(state.get("event_evidence", "")) and not _has_previous_memory(state.get("memory_evidence", "")):
        return "no_evidence"
    return "triage_agent"


def no_evidence_node(state: SHLDState) -> dict[str, Any]:
    return {"response_plan": _safe_no_evidence_response(state), "approval_request": None}

def route_after_response(state: SHLDState) -> str:
    return "approval" if state.get("approval_request") else "finalize"

def build_agent(checkpointer=None):
    """Compile the persistent multi-agent SHLD AI workflow."""
    workflow = StateGraph(SHLDState)
    workflow.add_node("intake", intake_node)
    workflow.add_node("greeting", greeting_node)
    workflow.add_node("command_help", terminal_command_help_node)
    workflow.add_node("evidence", evidence_node)
    workflow.add_node("no_evidence", no_evidence_node)
    workflow.add_node("triage_agent", triage_agent_node)
    workflow.add_node("analysis_agent", analysis_agent_node)
    workflow.add_node("response_agent", response_agent_node)
    workflow.add_node("approval_gate", approval_gate_node)
    workflow.add_node("finalize", finalize_node)

    workflow.add_edge(START, "intake")
    workflow.add_conditional_edges(
        "intake",
        route_after_intake,
        {"greeting": "greeting", "command_help": "command_help", "evidence": "evidence"},
    )
    workflow.add_edge("greeting", END)
    workflow.add_edge("command_help", END)
    workflow.add_conditional_edges(
        "evidence",
        route_after_evidence,
        {"no_evidence": "no_evidence", "triage_agent": "triage_agent"},
    )
    workflow.add_edge("no_evidence", "finalize")
    workflow.add_edge("triage_agent", "analysis_agent")
    workflow.add_edge("analysis_agent", "response_agent")
    workflow.add_conditional_edges(
        "response_agent",
        route_after_response,
        {"approval": "approval_gate", "finalize": "finalize"},
    )
    workflow.add_edge("approval_gate", "finalize")
    workflow.add_edge("finalize", END)

    if checkpointer is not None:
        return workflow.compile(checkpointer=checkpointer)

    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    stack = ExitStack()
    saver = stack.enter_context(SqliteSaver.from_conn_string(str(CHECKPOINT_PATH)))
    # Keep the saver alive for the lifetime of the compiled graph.
    graph = workflow.compile(checkpointer=saver)
    graph._shld_resource_stack = stack
    return graph

def close_agent_resources() -> None:
    """Release the graph's SQLite checkpoint resource if it is open."""
    # Streamlit caches the graph for the application's lifetime; process shutdown
    # closes SQLite resources. This function remains for explicit cleanup hooks.
    return None