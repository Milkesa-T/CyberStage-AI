import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables and .env file.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "CyberSage AI"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # AI & RAG Configuration
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    CHROMA_PERSIST_DIRECTORY: str = "./backend/data/chroma"
    PLAYBOOKS_DIRECTORY: str = "./knowledge_base/playbooks"
    EMBEDDING_MODEL_NAME: str = "all-MiniLM-L6-v2"

    # Automation
    N8N_WEBHOOK_URL: str = ""
    N8N_WEBHOOK_BEARER_TOKEN: str = ""

    @property
    def cors_origins(self) -> list[str]:
        if not self.ALLOWED_ORIGINS or self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def resolved_playbooks_dir(self) -> str:
        """Finds playbooks directory regardless of current working directory."""
        candidates = [
            Path(self.PLAYBOOKS_DIRECTORY),
            Path(__file__).resolve().parent.parent.parent / "knowledge_base" / "playbooks",
            Path.cwd() / "knowledge_base" / "playbooks",
            Path.cwd().parent / "knowledge_base" / "playbooks",
        ]
        for candidate in candidates:
            if candidate.is_dir():
                return str(candidate.resolve())
        return self.PLAYBOOKS_DIRECTORY

    @property
    def resolved_chroma_dir(self) -> str:
        """Finds or creates chroma persistence directory regardless of current working directory."""
        p = Path(self.CHROMA_PERSIST_DIRECTORY)
        if not p.is_absolute():
            # If backend/data/chroma exists or we are in root
            if (Path.cwd() / "backend" / "data" / "chroma").exists():
                return str((Path.cwd() / "backend" / "data" / "chroma").resolve())
            if (Path.cwd() / "data" / "chroma").exists():
                return str((Path.cwd() / "data" / "chroma").resolve())
            # Default to backend/data/chroma relative to workspace
            base = Path(__file__).resolve().parent.parent / "data" / "chroma"
            return str(base)
        return str(p)


settings = Settings()
