from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.logging import RequestLoggingMiddleware
from app.core.errors import register_error_handlers
from app.api.v1.incidents import router as incidents_router

app = FastAPI(
    title=settings.APP_NAME,
    description="Defensive Cybersecurity Incident Triage Assistant API",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
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
