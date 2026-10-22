from pathlib import Path

from shld.rag import ingest


class FakeVectorStore:
    def __init__(self):
        self.deleted = []

    def get(self, include=None):
        return {
            "ids": ["old-chunk", "current-chunk"],
            "metadatas": [
                {"source": "incident_responde.md", "content_hash": "old"},
                {"source": "incident_response.md", "content_hash": "current"},
            ],
        }

    def delete(self, ids):
        self.deleted.extend(ids)


def test_ingestion_removes_chunks_for_deleted_or_renamed_procedures(tmp_path, monkeypatch):
    procedure_dir = tmp_path / "procedures"
    procedure_dir.mkdir()
    (procedure_dir / "incident_response.md").write_text(
        "Current procedure content.", encoding="utf-8"
    )
    store = FakeVectorStore()
    indexed = []

    monkeypatch.setattr(ingest, "PROCEDURES_DIR", procedure_dir)
    monkeypatch.setattr(ingest, "get_vector_store", lambda: store)
    monkeypatch.setattr(
        ingest,
        "index_procedure",
        lambda text, source: indexed.append((text, source)) or 1,
    )

    result = ingest.ingest_procedures()

    assert store.deleted == ["old-chunk"]
    assert indexed == [("Current procedure content.", "incident_response.md")]
    assert result == {"incident_response.md": 1}
