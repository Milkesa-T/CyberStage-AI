#!/usr/bin/env python
"""
CyberSage AI — Playbook Ingestion Script

Run this script to parse all Markdown playbooks from knowledge_base/playbooks/
and upsert them into the ChromaDB vector store at the configured persist directory.

Usage (from repo root):
    $env:PYTHONPATH="backend"
    backend\\.venv\\Scripts\\python.exe backend/scripts/ingest_playbooks.py

This script is safe to run multiple times — ChromaDB will upsert (not duplicate).
It must be run once after deployment (or on container startup on Render).
"""

import sys
import os
import logging
import time

# Ensure backend app is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import settings
from app.rag.parser import parse_all_playbooks
from app.rag.store import PlaybookVectorStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ingest")


def main():
    playbooks_dir = os.path.abspath(settings.PLAYBOOKS_DIRECTORY)
    persist_dir = os.path.abspath(settings.CHROMA_PERSIST_DIRECTORY)

    logger.info(f"Playbooks directory : {playbooks_dir}")
    logger.info(f"ChromaDB persist dir: {persist_dir}")
    logger.info(f"Embedding model     : {settings.EMBEDDING_MODEL_NAME}")

    # 1. Parse all playbooks into chunks
    start = time.perf_counter()
    chunks = parse_all_playbooks(playbooks_dir)
    if not chunks:
        logger.error("No chunks to ingest. Verify playbooks directory path and .md file contents.")
        sys.exit(1)

    logger.info(f"Parsed {len(chunks)} chunks in {round(time.perf_counter()-start, 2)}s")

    # 2. Initialize store and ingest
    store = PlaybookVectorStore(
        persist_directory=persist_dir,
        embedding_model=settings.EMBEDDING_MODEL_NAME,
    )
    store.initialize()

    n = store.ingest(chunks)
    logger.info(f"Successfully upserted {n} chunks into ChromaDB.")

    # 3. Verify with a sample query
    logger.info("Running verification query: 'SSH brute force authentication failures' ...")
    results = store.query("SSH brute force authentication failures", n_results=3)
    for r in results:
        logger.info(
            f"  [{r['similarity_score']:.4f}] {r['playbook_title']} — {r['section']}"
        )
    logger.info("Ingestion complete ✓")


if __name__ == "__main__":
    main()
