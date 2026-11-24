
from langchain.tools import tool

from shld.rag.retriever import search_procedures


@tool
def search_security_procedures(query: str) -> str:
    """Search internal security procedures for evidence relevant to an incident."""
    if not query.strip():
        return "A search query is required."

    documents = search_procedures(query, k=4)

    if not documents:
        return "No relevant procedure evidence was found."

    from pathlib import Path
    from shld.rag.ingest import PROCEDURES_DIR

    results = []
    root = PROCEDURES_DIR.resolve()
    for document in documents:
        source = str(document.metadata.get("source", "")).strip()
        candidate = (root / source).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not source or not candidate.is_file():
            continue
        results.append(
            f"Source: {candidate.relative_to(root).as_posix()}\n"
            f"Evidence: {document.page_content}"
        )

    if not results:
        return "No relevant current procedure evidence was found."

    return "\n\n".join(results)
