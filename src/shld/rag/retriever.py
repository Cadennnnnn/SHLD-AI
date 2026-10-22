
import hashlib
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

PROJECT_ROOT = Path(__file__).resolve().parents[3]
VECTOR_DIR = PROJECT_ROOT / "data" / "chroma_db"
COLLECTION_NAME = "shld_procedures"

_embeddings = None
_vector_store = None


def get_vector_store() -> Chroma:
    """Load the persistent vector database."""
    global _embeddings, _vector_store

    if _vector_store is None:
        _embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
        _vector_store = Chroma(
            collection_name=COLLECTION_NAME,
            embedding_function=_embeddings,
            persist_directory=str(VECTOR_DIR),
        )

    return _vector_store


def index_procedure(text: str, source: str) -> int:
    """Index a procedure, replacing outdated chunks when its content changes."""
    if not text.strip() or not source.strip():
        raise ValueError("Procedure text and source are required.")

    store = get_vector_store()
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    existing = store.get(
        where={"source": source},
        include=["metadatas"],
    )
    old_ids = existing["ids"]
    old_metadata = existing.get("metadatas") or []

    if old_ids and all(
        metadata and metadata.get("content_hash") == content_hash
        for metadata in old_metadata
    ):
        return 0

    if old_ids:
        store.delete(ids=old_ids)

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=120,
    )
    chunks = splitter.split_text(text)

    documents = [
        Document(
            page_content=chunk,
            metadata={
                "source": source,
                "chunk": index,
                "content_hash": content_hash,
            },
        )
        for index, chunk in enumerate(chunks)
    ]

    ids = [
        hashlib.sha256(
            f"{source}:{index}:{content_hash}".encode("utf-8")
        ).hexdigest()
        for index in range(len(chunks))
    ]

    if documents:
        store.add_documents(documents=documents, ids=ids)

    return len(documents)


def search_procedures(query: str, k: int = 4) -> list[Document]:
    """Retrieve relevant procedure fragments."""
    if not query.strip():
        return []

    return get_vector_store().similarity_search(query, k=k)
