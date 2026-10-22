# ==============================================================================
# CyberSage AI - Backend Dockerfile
# Multi-stage production container for FastAPI + ChromaDB + SentenceTransformers
# ==============================================================================

FROM python:3.11-slim as base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend

WORKDIR /app

# Install system dependencies needed for compiling native extensions if necessary
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy knowledge base playbooks and backend source code
COPY knowledge_base /app/knowledge_base
COPY backend /app/backend

# Create data directory for ChromaDB persistence
RUN mkdir -p /app/backend/data/chroma

# Pre-ingest playbooks into ChromaDB during build so container starts ready
ENV CHROMA_PERSIST_DIRECTORY=/app/backend/data/chroma \
    PLAYBOOKS_DIRECTORY=/app/knowledge_base/playbooks \
    EMBEDDING_MODEL_NAME=all-MiniLM-L6-v2

RUN python /app/backend/scripts/ingest_playbooks.py || true

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
