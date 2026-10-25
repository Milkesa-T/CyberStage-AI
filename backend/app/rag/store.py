"""
CyberSage AI — ChromaDB Vector Store Manager

Handles collection initialization, playbook chunk ingestion, and semantic 
similarity retrieval using ChromaDB with the sentence-transformers embedding function.

DESIGN DECISIONS:
- Uses ChromaDB's built-in `SentenceTransformerEmbeddingFunction` for simplicity
  and reproducibility — no separate embedding server required.
- Model: `all-MiniLM-L6-v2` — lightweight, fast, well-tested for English semantic 
  similarity, and compatible with ChromaDB's documented embedding functions.
- Persistence: ChromaDB's PersistentClient saves to disk in CHROMA_PERSIST_DIRECTORY.
  On Render, this directory is ephemeral — the ingestion script must be rerun on 
  container startup (documented in deployment guide).
- Prompt injection defense: retrieved documents and submitted logs are treated as 
  untrusted data; they are wrapped in explicit delimiters when passed to Gemini prompts.
"""

import logging
from typing import Optional
import chromadb
from app.rag.parser import PlaybookChunk

logger = logging.getLogger("cybersage.rag.store")

COLLECTION_NAME = "cybersage_playbooks_v2"


class PlaybookVectorStore:
    """
    Manages the ChromaDB persistent collection for security playbook passages.
    """

    def __init__(self, persist_directory: str, embedding_model: str = "all-MiniLM-L6-v2"):
        self._persist_directory = persist_directory
        self._embedding_model = embedding_model
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None

    def _get_embedding_function(self):
        """
        Loads lightweight ONNX-based embedding function (under 80MB RAM)
        to prevent Out-Of-Memory errors on cloud containers (e.g. Render 512MB tier).
        Falls back to SentenceTransformer if explicitly requested and available.
        """
        try:
            from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
            logger.info("Using ChromaDB DefaultEmbeddingFunction (ONNX MiniLM-L6-V2, low-memory).")
            return DefaultEmbeddingFunction()
        except Exception:
            try:
                from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
                logger.info(f"Falling back to SentenceTransformerEmbeddingFunction with {self._embedding_model}.")
                return SentenceTransformerEmbeddingFunction(model_name=self._embedding_model)
            except Exception as e:
                logger.warning(f"Embedding function fallback to Chroma internal default: {e}")
                return None

    def initialize(self):
        """
        Open or create the ChromaDB persistent client and collection.
        Safe to call multiple times — idempotent.
        """
        logger.info(f"Initializing ChromaDB at '{self._persist_directory}'")
        self._client = chromadb.PersistentClient(path=self._persist_directory)
        ef = self._get_embedding_function()
        kwargs = {"name": COLLECTION_NAME, "metadata": {"hnsw:space": "cosine"}}
        if ef is not None:
            kwargs["embedding_function"] = ef
        self._collection = self._client.get_or_create_collection(**kwargs)
        count = self._collection.count()
        logger.info(f"Collection '{COLLECTION_NAME}' ready — {count} chunks indexed.")
        return self

    def is_empty(self) -> bool:
        """Returns True if the collection has no indexed documents."""
        if self._collection is None:
            raise RuntimeError("Store not initialized. Call initialize() first.")
        return self._collection.count() == 0

    def ingest(self, chunks: list[PlaybookChunk]) -> int:
        """
        Upsert playbook chunks into ChromaDB.
        Returns the number of chunks successfully upserted.
        """
        if self._collection is None:
            raise RuntimeError("Store not initialized. Call initialize() first.")

        if not chunks:
            logger.warning("No chunks provided for ingestion.")
            return 0

        ids = [chunk.chunk_id for chunk in chunks]
        documents = [chunk.text for chunk in chunks]
        metadatas = [
            {
                "playbook_id": chunk.playbook_id,
                "playbook_title": chunk.playbook_title,
                "section": chunk.section,
            }
            for chunk in chunks
        ]

        logger.info(f"Upserting {len(chunks)} chunks into '{COLLECTION_NAME}'...")
        self._collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        count = self._collection.count()
        logger.info(f"Ingestion complete — {count} total chunks in collection.")
        return len(chunks)

    def query(self, query_text: str, n_results: int = 5) -> list[dict]:
        """
        Retrieve the top-n most semantically similar chunks for the query.
        Returns a list of dicts with: chunk_id, playbook_id, playbook_title, 
        section, excerpt, and similarity_score.
        
        Note: Raw query_text is treated as untrusted input here — it is used only for 
        vector similarity search, never injected into SQL or system prompts raw.
        """
        if self._collection is None:
            raise RuntimeError("Store not initialized. Call initialize() first.")

        results = self._collection.query(
            query_texts=[query_text],
            n_results=min(n_results, self._collection.count() or 1),
            include=["documents", "metadatas", "distances"],
        )

        retrieved = []
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for doc, meta, dist in zip(documents, metadatas, distances):
            # ChromaDB cosine distance: 0 = identical, 2 = opposite. Convert to similarity.
            similarity = round(max(0.0, 1.0 - dist), 4)
            retrieved.append({
                "chunk_id": meta.get("playbook_id", "") + "__chunk",
                "playbook_id": meta.get("playbook_id", ""),
                "playbook_title": meta.get("playbook_title", ""),
                "section": meta.get("section", ""),
                "excerpt": doc[:600],  # Truncate long sections for prompt safety
                "similarity_score": similarity,
            })

        return retrieved


# Module-level singleton — initialized once on application startup
_store: Optional[PlaybookVectorStore] = None


def get_store() -> PlaybookVectorStore:
    """Return the initialized singleton PlaybookVectorStore."""
    if _store is None:
        raise RuntimeError(
            "PlaybookVectorStore not initialized. "
            "Ensure initialize_store() is called at application startup."
        )
    return _store


def initialize_store(persist_directory: str, embedding_model: str = "all-MiniLM-L6-v2") -> PlaybookVectorStore:
    """Initialize the global store singleton. Call this at app startup."""
    global _store
    _store = PlaybookVectorStore(
        persist_directory=persist_directory,
        embedding_model=embedding_model,
    )
    _store.initialize()
    return _store
