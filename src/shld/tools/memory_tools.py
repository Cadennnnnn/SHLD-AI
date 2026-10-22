
from langchain.tools import tool

from shld.memory.store import get_memories, save_memory


@tool
def search_incident_memory(incident_id: str) -> str:
    """Retrieve previously saved investigation notes for an incident ID."""
    memories = get_memories(incident_id)

    if not memories:
        return f"No previous memory found for incident {incident_id}."

    return "\n".join(
        f"- [{item['created_at']}] {item['content']}"
        for item in memories
    )


@tool
def save_incident_memory(incident_id: str, content: str) -> str:
    """Save a factual investigation note for future reference."""
    if not incident_id.strip() or not content.strip():
        return "Error: incident_id and content are required."

    save_memory(incident_id, content)
    return f"Memory saved for incident {incident_id}."
