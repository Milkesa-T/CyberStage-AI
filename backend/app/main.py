from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="CyberSage AI API",
    description="Defensive Cybersecurity Incident Triage Assistant API",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS Middleware (Configurable for local React dev and cloud deployment)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrictable via configuration in later stages
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", tags=["Health"])
def get_health():
    """
    Health check endpoint for container orchestrators, uptime checks, and UI connectivity.
    """
    return {
        "status": "ok",
        "app": "CyberSage AI",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
