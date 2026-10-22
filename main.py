from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from langchain_core.messages import HumanMessage
from langgraph.types import Command

from shld.agents.graph import build_agent

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the SHLD AI multi-agent workflow in simulation mode."
    )
    parser.add_argument(
        "--query",
        default="hola",
        help="User request to investigate. Defaults to a greeting smoke test.",
    )
    parser.add_argument(
        "--thread-id",
        default=None,
        help="Optional persistent LangGraph thread ID.",
    )
    args = parser.parse_args()

    thread_id = args.thread_id or str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    graph = build_agent()

    print(f"SHLD AI | thread_id={thread_id}")
    print("Simulation only. No real systems will be modified.\n")

    result = graph.invoke(
        {"messages": [HumanMessage(content=args.query)]},
        config,
    )

    while result.get("__interrupt__"):
        interruption = result["__interrupt__"][0]
        proposal = getattr(interruption, "value", {}) or {}
        print("\nHUMAN APPROVAL REQUIRED")
        print(f"Incident: {proposal.get('incident_id', 'unspecified')}")
        print(f"Target: {proposal.get('target', 'unconfirmed')}")
        print(f"Proposal: {proposal.get('proposed_action', '')}")
        print(f"Justification: {proposal.get('justification', '')}")
        answer = input("Approve this simulation? [y/N]: ").strip().lower()
        approved = answer in {"y", "yes", "s", "si", "sí"}
        result = graph.invoke(Command(resume={"approved": approved}), config)

    print("\nRESULT\n")
    print(result.get("final_response", "The graph finished without a final response."))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
