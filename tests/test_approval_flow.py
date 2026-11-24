from types import SimpleNamespace
from uuid import uuid4

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

import shld.agents.graph as graph_module
from shld.database.audit import get_approval_audit


class FakeLLM:
    def invoke(self, prompt):
        if "Response coordination specialist" in prompt:
            text = (
                "Evidence is insufficient to claim compromise. Proposed containment: "
                "isolate host host-test-01 only after validating ownership and impact. "
                "This is a simulation proposal; no action has been executed."
            )
        elif "Evidence analysis specialist" in prompt:
            text = (
                "Facts: no verified event records were supplied by this test. "
                "Unknown: whether the host is compromised. Source: test fixture."
            )
        else:
            text = (
                "Triage: the request concerns a simulated incident. "
                "No compromise is confirmed by the supplied evidence."
            )
        return SimpleNamespace(content=text)


class FakeTool:
    def __init__(self, value):
        self.value = value

    def invoke(self, _args):
        return self.value


def configure_fakes(monkeypatch):
    monkeypatch.setattr(graph_module, "create_llm", lambda: FakeLLM())
    monkeypatch.setattr(
        graph_module, "search_security_events",
        FakeTool(
            "Event: EVT-TEST-001 | Incident: INC-TEST-001 | Type: suspicious_login | "
            "Severity: high | Description: repeated login failures involving host-test-01 | "
            "Source IP: 192.0.2.10 | Created at: 2026-10-21 10:00:00"
        ),
    )
    monkeypatch.setattr(
        graph_module, "query_security_events_nl",
        FakeTool("No recorded security events matched the question."),
    )
    monkeypatch.setattr(
        graph_module, "search_security_procedures",
        FakeTool("Source: incident_response.md\nEvidence: validate before containment."),
    )
    monkeypatch.setattr(
        graph_module, "search_incident_memory",
        FakeTool("No previous memory found."),
    )
    monkeypatch.setattr(
        graph_module, "save_incident_memory",
        FakeTool("Memory saved."),
    )
    monkeypatch.setattr(graph_module, "ingest_procedures", lambda: {})


def run_to_approval(monkeypatch, decision):
    configure_fakes(monkeypatch)
    graph = graph_module.build_agent(checkpointer=MemorySaver())
    thread_id = f"test-{decision}-{uuid4()}"
    config = {"configurable": {"thread_id": thread_id}}
    result = graph.invoke(
        {
            "messages": [
                HumanMessage(
                    content=(
                        "For incident INC-TEST-001, consider isolating "
                        "host-test-01. Prepare a simulated proposal."
                    )
                )
            ]
        },
        config,
    )
    assert result.get("__interrupt__"), "Graph did not pause for human approval."
    graph.invoke(Command(resume={"approved": decision == "approved"}), config)
    records = get_approval_audit("INC-TEST-001")
    assert any(
        row["thread_id"] == thread_id and row["decision"] == decision
        for row in records
    ), f"{decision} decision was not recorded."
    return graph


def test_approval_is_recorded(monkeypatch):
    run_to_approval(monkeypatch, "approved")


def test_rejection_is_recorded(monkeypatch):
    run_to_approval(monkeypatch, "rejected")


def test_greeting_uses_fast_path(monkeypatch):
    configure_fakes(monkeypatch)
    graph = graph_module.build_agent(checkpointer=MemorySaver())
    result = graph.invoke(
        {"messages": [HumanMessage(content="hola")]},
        {"configurable": {"thread_id": f"greeting-{uuid4()}"}},
    )
    assert "Hola" in result["final_response"]
    assert not result.get("__interrupt__")


def test_missing_events_uses_safe_response_without_calling_llm(monkeypatch):
    configure_fakes(monkeypatch)
    monkeypatch.setattr(
        graph_module, "search_security_events",
        FakeTool("No security events found for incident INC-TEST-404."),
    )
    monkeypatch.setattr(
        graph_module, "search_incident_memory",
        FakeTool("No previous memory found for incident INC-TEST-404."),
    )

    def forbidden_llm():
        raise AssertionError("LLM should not run when no events or prior memory exist")

    monkeypatch.setattr(graph_module, "create_llm", forbidden_llm)
    graph = graph_module.build_agent(checkpointer=MemorySaver())
    result = graph.invoke(
        {"messages": [HumanMessage(content="Investiga el incidente INC-TEST-404")]},
        {"configurable": {"thread_id": f"no-evidence-{uuid4()}"}},
    )
    response = result["final_response"].lower()
    assert "no devolvió eventos" in response
    assert "forensic_copy.sh" not in response
    assert "no se recomienda aislar" in response
    assert not result.get("__interrupt__")


def test_unconfirmed_target_does_not_trigger_approval(monkeypatch):
    configure_fakes(monkeypatch)
    monkeypatch.setattr(
        graph_module, "search_security_events",
        FakeTool(
            "Event: EVT-TEST-002 | Incident: INC-TEST-001 | Type: alert | "
            "Severity: medium | Description: activity on host-confirmed-02 | "
            "Source IP: 192.0.2.11 | Created at: 2026-10-21 10:05:00"
        ),
    )
    graph = graph_module.build_agent(checkpointer=MemorySaver())
    result = graph.invoke(
        {"messages": [HumanMessage(content=(
            "For incident INC-TEST-001, consider isolating host-test-01. "
            "Prepare a simulated proposal."
        ))]},
        {"configurable": {"thread_id": f"target-check-{uuid4()}"}},
    )
    assert not result.get("__interrupt__")
    assert "not being submitted" in result["final_response"].lower() or "no se presenta" in result["final_response"].lower()


def test_terminal_command_pasted_into_chat_gets_help(monkeypatch):
    configure_fakes(monkeypatch)
    graph = graph_module.build_agent(checkpointer=MemorySaver())
    result = graph.invoke(
        {"messages": [HumanMessage(content='python main.py --query "Investiga el incidente INC-TEST-101"')]},
        {"configurable": {"thread_id": f"command-help-{uuid4()}"}},
    )
    assert "terminal" in result["final_response"].lower()
    assert not result.get("__interrupt__")
