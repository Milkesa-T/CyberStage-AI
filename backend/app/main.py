from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.logging import RequestLoggingMiddleware
from app.core.errors import register_error_handlers
from app.api.v1.incidents import router as incidents_router
from app.rag.store import initialize_store
from app.rag.parser import parse_all_playbooks

logger = logging.getLogger("cybersage.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle management.
    Initializes ChromaDB vector store and auto-ingests playbooks if collection is empty.
    """
    logger.info("Initializing CyberSage AI application lifecycle...")
    try:
        store = initialize_store(
            persist_directory=settings.resolved_chroma_dir,
            embedding_model=settings.EMBEDDING_MODEL_NAME,
        )
        if store.is_empty():
            logger.info(f"Vector store is empty. Auto-ingesting playbooks from '{settings.resolved_playbooks_dir}'...")
            chunks = parse_all_playbooks(settings.resolved_playbooks_dir)
            if chunks:
                store.ingest(chunks)
                logger.info(f"Successfully auto-ingested {len(chunks)} playbook chunks into ChromaDB.")
            else:
                logger.warning("No playbook files found to ingest on startup.")
    except Exception as e:
        logger.warning(f"Vector store initialization deferred or encountered issue: {e}")

    yield

    logger.info("CyberSage AI application shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Defensive Cybersecurity Incident Triage Assistant API",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# 1. Logging and Correlation Middleware
app.add_middleware(RequestLoggingMiddleware)

# 2. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Centralized Exception Handlers
register_error_handlers(app)

# 4. API Routers
app.include_router(incidents_router)


@app.get("/api/v1/health", tags=["Health"])
def get_health():
    """
    Health check endpoint for container orchestrators, uptime checks, and UI connectivity.
    """
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
