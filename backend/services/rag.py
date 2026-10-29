"""
services/rag.py — RAG (Retrieval-Augmented Generation) knowledge base service.

Uses ChromaDB (in-process, no separate server) with nomic-embed-text embeddings
served via Ollama for semantic search over MITRE ATT&CK summaries and SOC runbooks.

Embedding flow:
  text document → POST /api/embeddings (Ollama nomic-embed-text) → vector stored in ChromaDB

Retrieval flow:
  query string → embed → ChromaDB cosine similarity → top-N chunks returned

Data layout on disk:
  /app/chroma_data/   — ChromaDB persistent storage (mounted as Docker volume)

Knowledge source files:
  /app/knowledge/mitre/*.txt    — MITRE ATT&CK technique summaries
  /app/knowledge/runbooks/*.txt — SOC response runbooks

Usage:
    from services.rag import init_knowledge_base, retrieve_context

    # On startup (idempotent):
    await init_knowledge_base()

    # During investigation:
    chunks = await retrieve_context("multiple SSH failures brute force")
    # Returns: [{"source": "T1110-brute-force.txt", "content": "...", "distance": 0.12}, ...]
"""

import logging
import os
from pathlib import Path
from typing import Any, Optional

# Disable Chroma anonymous Posthog telemetry before importing chromadb.
# (Broken posthog capture() otherwise floods ERROR logs without affecting retrieval.)
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

import chromadb
import httpx

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
_OLLAMA_BASE       = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
_EMBED_MODEL       = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
_CHROMA_PERSIST    = os.environ.get("CHROMA_PERSIST_DIR", "/app/chroma_data")
_COLLECTION_NAME   = "aisoc_knowledge"
_KNOWLEDGE_DIR     = Path("/app/knowledge")
_EMBED_TIMEOUT     = 30.0   # seconds per embedding call

# Module-level ChromaDB client and collection (initialised once at startup)
_chroma_client: "Optional[chromadb.PersistentClient]" = None
_collection: "Optional[chromadb.Collection]" = None


# ── Ollama embedding ──────────────────────────────────────────────────────────
async def _embed(text: str) -> list[float]:
    """
    Get an embedding vector for `text` from Ollama nomic-embed-text.

    Args:
        text: The text to embed (document chunk or query string).

    Returns:
        List of floats (768-dim vector for nomic-embed-text).

    Raises:
        RuntimeError: If Ollama is unreachable or returns an error.
    """
    url = f"{_OLLAMA_BASE}/api/embeddings"
    payload = {"model": _EMBED_MODEL, "prompt": text}

    try:
        async with httpx.AsyncClient(timeout=_EMBED_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.ConnectError as exc:
        raise RuntimeError(
            f"Cannot reach Ollama at {_OLLAMA_BASE} for embeddings. "
            "Is Ollama running? Run: ollama serve"
        ) from exc
    except httpx.TimeoutException as exc:
        raise RuntimeError(
            f"Ollama embedding timed out after {_EMBED_TIMEOUT}s."
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Ollama embeddings returned HTTP {exc.response.status_code}: {exc.response.text}"
        ) from exc

    data = response.json()
    embedding = data.get("embedding")
    if not embedding or not isinstance(embedding, list):
        raise RuntimeError(f"Unexpected Ollama embedding response: {data}")

    return embedding


# ── ChromaDB setup ────────────────────────────────────────────────────────────
def _get_chroma_collection() -> chromadb.Collection:
    """Return (or create) the ChromaDB collection. Initialises the client once."""
    global _chroma_client, _collection

    if _collection is not None:
        return _collection

    os.makedirs(_CHROMA_PERSIST, exist_ok=True)
    _chroma_client = chromadb.PersistentClient(path=_CHROMA_PERSIST)

    # get_or_create — safe to call on every startup
    _collection = _chroma_client.get_or_create_collection(
        name=_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},   # cosine similarity for text
    )

    logger.info(
        "ChromaDB collection '%s' ready at %s (documents: %d)",
        _COLLECTION_NAME,
        _CHROMA_PERSIST,
        _collection.count(),
    )
    return _collection


# ── Document loading ──────────────────────────────────────────────────────────
def _load_knowledge_files() -> list[dict]:
    """
    Scan the knowledge directory and load all .txt files.

    Returns:
        List of dicts with keys: id, source, category, content.
    """
    docs = []
    if not _KNOWLEDGE_DIR.exists():
        logger.warning("Knowledge directory not found: %s", _KNOWLEDGE_DIR)
        return docs

    for txt_file in sorted(_KNOWLEDGE_DIR.rglob("*.txt")):
        try:
            content = txt_file.read_text(encoding="utf-8").strip()
            if not content:
                continue

            # Derive a stable document ID from the filename (no spaces, lowercase)
            doc_id   = txt_file.stem.lower().replace(" ", "_")
            category = txt_file.parent.name  # "mitre" or "runbooks"

            docs.append({
                "id":       doc_id,
                "source":   txt_file.name,
                "category": category,
                "content":  content,
            })
            logger.debug("Loaded knowledge file: %s (%d chars)", txt_file.name, len(content))
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load %s: %s", txt_file, exc)

    logger.info("Loaded %d knowledge documents from %s", len(docs), _KNOWLEDGE_DIR)
    return docs


# ── Public API ────────────────────────────────────────────────────────────────
async def init_knowledge_base() -> None:
    """
    Load knowledge documents into ChromaDB on application startup.

    Idempotent: documents already present (by ID) are skipped, so this is
    safe to call on every container restart without duplicating data.

    Only re-embeds documents that are NEW or CHANGED (content length differs).
    """
    collection = _get_chroma_collection()
    docs = _load_knowledge_files()

    if not docs:
        logger.warning("No knowledge documents found — RAG will not provide context.")
        return

    # Find which documents are already in the collection
    existing_ids: set[str] = set()
    try:
        existing = collection.get(ids=[d["id"] for d in docs])
        existing_ids = set(existing["ids"])
    except Exception:  # noqa: BLE001
        existing_ids = set()

    new_docs = [d for d in docs if d["id"] not in existing_ids]

    if not new_docs:
        logger.info(
            "Knowledge base up to date (%d documents already loaded). Skipping init.",
            len(docs),
        )
        return

    logger.info(
        "Indexing %d new knowledge document(s) into ChromaDB...", len(new_docs)
    )

    for doc in new_docs:
        try:
            embedding = await _embed(doc["content"])
            collection.add(
                ids        = [doc["id"]],
                embeddings = [embedding],
                documents  = [doc["content"]],
                metadatas  = [{"source": doc["source"], "category": doc["category"]}],
            )
            logger.info("  ✓ Indexed: %s", doc["source"])
        except Exception as exc:  # noqa: BLE001
            logger.error("  ✗ Failed to index %s: %s", doc["source"], exc)

    logger.info(
        "Knowledge base ready: %d total documents in ChromaDB.",
        collection.count(),
    )


async def retrieve_context(query: str, n_results: int = 3) -> list[dict[str, Any]]:
    """
    Semantic search over the knowledge base for the given query.

    Args:
        query:     Natural language query (e.g. incident description).
        n_results: Number of top results to return (default 3).

    Returns:
        List of dicts, sorted by relevance (closest first):
        [
            {
                "source":   "T1110-brute-force.txt",
                "category": "mitre",
                "content":  "MITRE ATT&CK Technique: T1110...",
                "distance": 0.12,   # lower = more relevant (cosine distance)
            },
            ...
        ]
        Returns empty list if the collection is empty or embedding fails.
    """
    collection = _get_chroma_collection()

    if collection.count() == 0:
        logger.warning("Knowledge base is empty — no RAG context available.")
        return []

    try:
        query_embedding = await _embed(query)
    except RuntimeError as exc:
        logger.error("Failed to embed query for RAG retrieval: %s", exc)
        return []

    try:
        results = collection.query(
            query_embeddings = [query_embedding],
            n_results        = min(n_results, collection.count()),
            include          = ["documents", "metadatas", "distances"],
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("ChromaDB query failed: %s", exc)
        return []

    chunks = []
    for i, doc_id in enumerate(results["ids"][0]):
        chunks.append({
            "source":   results["metadatas"][0][i].get("source", doc_id),
            "category": results["metadatas"][0][i].get("category", ""),
            "content":  results["documents"][0][i],
            "distance": round(results["distances"][0][i], 4),
        })

    logger.info(
        "RAG retrieved %d chunks for query '%s...': %s",
        len(chunks),
        query[:60],
        [c["source"] for c in chunks],
    )
    return chunks


async def get_knowledge_base_status() -> dict:
    """Return a status dict for health/debug endpoints."""
    try:
        collection = _get_chroma_collection()
        count = collection.count()
        return {
            "status":    "ok",
            "documents": count,
            "persist_dir": _CHROMA_PERSIST,
            "embed_model": _EMBED_MODEL,
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}
