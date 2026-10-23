import time
import uuid
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.observability.metrics import REQUEST_COUNT

logger = logging.getLogger("ai_gateway.access")


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Correlation ID propagation
        corr_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = corr_id

        start_time = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Attach correlation header
        response.headers["X-Correlation-ID"] = corr_id

        # Prometheus metrics update
        endpoint = request.url.path
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            status_code=str(response.status_code)
        ).inc()

        logger.info(
            "HTTP %s %s -> %d (%0.2fms) [corr_id=%s]",
            request.method,
            endpoint,
            response.status_code,
            duration_ms,
            corr_id
        )

        return response
