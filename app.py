from __future__ import annotations

import uuid
from typing import Any

import streamlit as st
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.types import Command

from shld.agents.graph import build_agent
from shld.database.audit import get_approval_audit
from shld.database.conversations import (
    create_conversation,
    list_conversations,
    touch_conversation,
)

st.set_page_config(page_title="SHLD AI", page_icon="🛡️", layout="wide")
st.title("SHLD AI")
st.caption("Sistema multiagente de investigación defensiva de ciberseguridad")
st.warning(
    "Entorno de simulación. No se modifican sistemas reales. "
    "Las aprobaciones registran decisiones simuladas y no ejecutan acciones."
)

@st.cache_resource
def get_agent():
    return build_agent()

agent = get_agent()

def get_snapshot(thread_id: str):
    return agent.get_state({"configurable": {"thread_id": thread_id}})

def find_pending_approval(snapshot) -> dict[str, Any] | None:
    for task in getattr(snapshot, "tasks", ()) or ():
        for interruption in getattr(task, "interrupts", ()) or ():
            value = getattr(interruption, "value", None)
            if isinstance(value, dict) and value.get("type") == "simulated_containment_approval":
                return value
    values = getattr(snapshot, "values", {}) or {}
    candidate = values.get("approval_request")
    if isinstance(candidate, dict) and candidate.get("type") == "simulated_containment_approval":
        # Only display it as pending when the graph is actually interrupted.
        if any(getattr(task, "interrupts", ()) for task in getattr(snapshot, "tasks", ()) or ()):
            return candidate
    return None

def text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        blocks = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        return "\n".join(item for item in blocks if item)
    return str(content) if content is not None else ""

with st.sidebar:
    st.subheader("Investigaciones guardadas")
    conversations = list_conversations()
    conversation_ids = [item["thread_id"] for item in conversations]

    if "thread_id" not in st.session_state or st.session_state.thread_id not in conversation_ids:
        st.session_state.thread_id = create_conversation()
        conversations = list_conversations()
        conversation_ids = [item["thread_id"] for item in conversations]

    if st.button("Nueva conversación", use_container_width=True):
        st.session_state.thread_id = create_conversation()
        st.session_state.selected_conversation = st.session_state.thread_id
        st.rerun()

    if (
        "selected_conversation" not in st.session_state
        or st.session_state.selected_conversation not in conversation_ids
    ):
        st.session_state.selected_conversation = st.session_state.thread_id

    titles = {item["thread_id"]: item["title"] for item in conversations}
    selected_thread = st.selectbox(
        "Conversación",
        options=conversation_ids,
        key="selected_conversation",
        format_func=lambda value: f"{titles.get(value, 'Investigación nueva')} · {value[:8]}",
    )
    if selected_thread != st.session_state.thread_id:
        st.session_state.thread_id = selected_thread
        st.rerun()

    thread_id = st.session_state.thread_id
    st.caption("Identificador de conversación")
    st.code(thread_id, language=None)
    st.divider()
    st.subheader("Últimas decisiones de aprobación")
    try:
        audit_records = get_approval_audit()
        if audit_records:
            for record in audit_records[:10]:
                st.write(
                    f"**{record['decision'].upper()}** — "
                    f"{record['incident_id']} / {record['proposed_action'][:90]}"
                )
                st.caption(record["created_at"])
        else:
            st.caption("Todavía no hay decisiones registradas.")
    except Exception as exc:
        st.error(f"No se pudo consultar la auditoría: {exc}")

config = {"configurable": {"thread_id": thread_id}}
try:
    snapshot = get_snapshot(thread_id)
    values = getattr(snapshot, "values", {}) or {}
except Exception as exc:
    values = {}
    snapshot = None
    st.error(f"No se pudo recuperar el estado persistente: {exc}")

# Render conversation history from LangGraph checkpoints, not transient UI state.
for message in values.get("messages", []) or []:
    if isinstance(message, HumanMessage):
        role = "user"
    elif isinstance(message, AIMessage):
        role = "assistant"
    else:
        continue
    content = text_content(message.content)
    if content.strip():
        with st.chat_message(role):
            st.markdown(content)

pending = find_pending_approval(snapshot) if snapshot is not None else None
if pending:
    st.subheader("Se requiere aprobación humana")
    st.write(f"**Incidente:** {pending.get('incident_id', 'No especificado')}")
    st.write(f"**Objetivo:** {pending.get('target', 'No confirmado')}")
    st.write("**Propuesta:**")
    st.markdown(pending.get("proposed_action", "No hay descripción disponible."))
    st.write(f"**Justificación:** {pending.get('justification', '')}")
    st.info(
        "La decisión se registrará en la auditoría. Incluso si se aprueba, "
        "no se ejecutará ninguna acción sobre sistemas reales."
    )
    approve_col, reject_col = st.columns(2)
    with approve_col:
        approve_clicked = st.button(
            "Aprobar simulación", type="primary", use_container_width=True
        )
    with reject_col:
        reject_clicked = st.button("Rechazar", use_container_width=True)

    if approve_clicked or reject_clicked:
        try:
            agent.invoke(
                Command(resume={"approved": bool(approve_clicked)}),
                config,
            )
            st.rerun()
        except Exception as exc:
            st.error(f"No se pudo reanudar el flujo: {exc}")

user_input = st.chat_input(
    "Describe el incidente o formula una consulta...",
    disabled=pending is not None,
)

if user_input:
    try:
        touch_conversation(thread_id, first_message=user_input)
        agent.invoke(
            {"messages": [HumanMessage(content=user_input)]},
            config,
        )
        touch_conversation(thread_id)
        st.rerun()
    except Exception as exc:
        st.error(f"La investigación no pudo completarse: {type(exc).__name__}: {exc}")
