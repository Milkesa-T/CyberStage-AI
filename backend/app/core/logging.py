import logging
import sys
import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configure standard root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("cybersage")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that attaches a unique X-Request-ID to each incoming request,
    logs request completion with latency, and prevents sensitive log leaks.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        start_time = time.perf_counter()

        logger.info(
            f"REQUEST START [id={request_id}] {request.method} {request.url.path}"
        )

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Request-ID"] = request_id
            
            logger.info(
                f"REQUEST END   [id={request_id}] {request.method} {request.url.path} "
                f"status={response.status_code} duration={duration_ms}ms"
            )
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                f"REQUEST FAIL  [id={request_id}] {request.method} {request.url.path} "
                f"duration={duration_ms}ms error={type(exc).__name__}: {str(exc)}"
            )
            raise
