import logging
from typing import Any
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("cybersage.errors")


class CyberSageException(Exception):
    """
    Base exception for all domain-specific CyberSage errors.
    """
    def __init__(
        self,
        message: str,
        error_code: str = "CYBERSAGE_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Any = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


class PlaybookNotFoundError(CyberSageException):
    def __init__(self, message: str = "Requested playbook not found in knowledge base"):
        super().__init__(
            message=message,
            error_code="PLAYBOOK_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class AIAnalysisError(CyberSageException):
    def __init__(self, message: str = "AI inference provider failed or returned invalid response"):
        super().__init__(
            message=message,
            error_code="AI_ANALYSIS_ERROR",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class KnowledgeBaseError(CyberSageException):
    def __init__(self, message: str = "Vector database retrieval or indexing failure"):
        super().__init__(
            message=message,
            error_code="KNOWLEDGE_BASE_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


def register_error_handlers(app):
    """
    Register centralized exception handlers for FastAPI app.
    """
    @app.exception_handler(CyberSageException)
    async def cybersage_exception_handler(request: Request, exc: CyberSageException):
        request_id = getattr(request.state, "request_id", "unknown")
        logger.warning(
            f"Handled domain exception [id={request_id}] {exc.error_code}: {exc.message}"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "detail": exc.message,
                "request_id": request_id,
                "data": exc.details,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        request_id = getattr(request.state, "request_id", "unknown")
        errors = []
        for err in exc.errors():
            loc = " -> ".join([str(l) for l in err.get("loc", []) if l != "body"])
            errors.append({
                "field": loc or "payload",
                "message": err.get("msg", "Validation error"),
                "type": err.get("type", "value_error"),
            })

        logger.info(f"Validation failure [id={request_id}]: {errors}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "VALIDATION_ERROR",
                "detail": "Input validation failed. Please check field requirements.",
                "request_id": request_id,
                "errors": errors,
            },
        )

    @app.exception_handler(Exception)
    async def global_unhandled_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "unknown")
        logger.error(f"Unhandled server error [id={request_id}]: {type(exc).__name__} - {str(exc)}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "detail": "An unexpected server error occurred. Please contact the administrator.",
                "request_id": request_id,
            },
        )
