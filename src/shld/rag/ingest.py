from __future__ import annotations

from pathlib import Path

from shld.rag.retriever import get_vector_store, index_procedure

PROJECT_ROOT = Path(__file__).resolve().parents[3]
PROCEDURES_DIR = PROJECT_ROOT / "data" / "procedures"
SUPPORTED_EXTENSIONS = {".txt", ".md"}


def ingest_procedures() -> dict[str, int]:
    """Synchronize the vector index with current procedure files.

    Changed files are re-indexed by content hash. Chunks belonging to deleted
    files are removed so retrieval cannot cite stale or renamed procedures.
    """
    PROCEDURES_DIR.mkdir(parents=True, exist_ok=True)
    files = [
        path for path in sorted(PROCEDURES_DIR.rglob("*"))
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    current_sources = {path.relative_to(PROCEDURES_DIR).as_posix() for path in files}
    store = get_vector_store()

    indexed = store.get(include=["metadatas"])
    metadata_rows = indexed.get("metadatas") or []
    ids = indexed.get("ids") or []
    stale_ids: list[str] = []
    for vector_id, metadata in zip(ids, metadata_rows):
        source = (metadata or {}).get("source", "")
        if source and source not in current_sources:
            stale_ids.append(vector_id)
    if stale_ids:
        store.delete(ids=stale_ids)

    results: dict[str, int] = {}
    for path in files:
        text = path.read_text(encoding="utf-8-sig")
        source = path.relative_to(PROCEDURES_DIR).as_posix()
        results[source] = index_procedure(text, source)

    return results


if __name__ == "__main__":
    summary = ingest_procedures()
    if not summary:
        print(f"No .txt or .md procedures found in {PROCEDURES_DIR}")
    else:
        for source, chunks in summary.items():
            status = "unchanged" if chunks == 0 else f"{chunks} chunks indexed"
            print(f"{source}: {status}")
