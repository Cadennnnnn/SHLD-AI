from types import SimpleNamespace
from uuid import uuid4

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import MemorySaver

from shld.agents import graph as graph_module


class FakeTool:
    def __init__(self, value="saved"):
        self.value = value

    def invoke(self, args):
        return self.value


def test_multiagent_handoff_passes_prior_outputs_to_next_specialist(monkeypatch):
    prompts = []

    class FakeLLM:
        def invoke(self, prompt):
            prompts.append(prompt)
            if "SPECIALIST ROLE: Incident triage specialist" in prompt:
                answer = "TRIAGE_SENTINEL: recorded event is medium severity."
            elif "SPECIALIST ROLE: Evidence analysis specialist" in prompt:
                answer = "ANALYSIS_SENTINEL: one event requires verification."
            else:
                answer = "PLAN_SENTINEL: verify the event source before deciding."
            return SimpleNamespace(content=answer)

    monkeypatch.setattr(graph_module, "create_llm", lambda: FakeLLM())
    monkeypatch.setattr(
        graph_module,
        "evidence_node",
        lambda state: {
            "event_evidence": (
                "Event: EVT-TEST-777 | Incident: INC-TEST-777 | Type: alert | "
                "Severity: medium | Description: suspicious login | "
                "Source IP: 192.0.2.77 | Created at: 2026-10-21 10:05:00"
            ),
            "procedure_evidence": "Source: incident_response.md\nProcedure text available.",
            "memory_evidence": "No previous memory found.",
            "errors": [],
        },
    )
    monkeypatch.setattr(
        graph_module,
        "_verified_procedure_sources",
        lambda _evidence: ["incident_response.md"],
    )
    monkeypatch.setattr(graph_module, "save_incident_memory", FakeTool())

    agent = graph_module.build_agent(checkpointer=MemorySaver())
    result = agent.invoke(
        {
            "messages": [
                HumanMessage(
                    content="Investigate incident INC-TEST-777 and summarize evidence."
                )
            ]
        },
        {"configurable": {"thread_id": f"handoff-{uuid4()}"}},
    )

    analysis_prompt = next(
        prompt for prompt in prompts
        if "SPECIALIST ROLE: Evidence analysis specialist" in prompt
    )
    response_prompt = next(
        prompt for prompt in prompts
        if "SPECIALIST ROLE: Response coordination specialist" in prompt
    )

    assert "TRIAGE_SENTINEL" in analysis_prompt
    assert "TRIAGE_SENTINEL" in response_prompt
    assert "ANALYSIS_SENTINEL" in response_prompt
    assert "PLAN_SENTINEL" in result["final_response"]
