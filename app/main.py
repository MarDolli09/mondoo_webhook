"""FastAPI-Anwendung: Correlation-ID, Fehlerbehandlung und Health-Check."""

import json
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from app.api import lifespan, webhook_router
from app.core.config import settings
from app.core.exceptions import WebhookError
from app.core.logging import (
    bind_correlation_id,
    logger,
    mask_secrets,
    reset_correlation_id,
)

__all__ = ["app"]

CORRELATION_ID_HEADER = "X-Correlation-ID"

app = FastAPI(title="Mondoo Webhook Receiver", lifespan=lifespan)


@app.middleware("http")
async def correlation_id_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Uebernimmt oder erzeugt die Correlation-ID und misst die Laufzeit."""
    correlation_id = request.headers.get(CORRELATION_ID_HEADER, str(uuid.uuid4()))
    token = bind_correlation_id(correlation_id)
    try:
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers[CORRELATION_ID_HEADER] = correlation_id
        logger.info(
            json.dumps(
                {
                    "event": "request_completed",
                    "correlation_id": correlation_id,
                    "duration_ms": duration_ms,
                }
            )
        )
        return response
    finally:
        reset_correlation_id(token)


@app.exception_handler(WebhookError)
async def webhook_error_handler(request: Request, exc: WebhookError) -> JSONResponse:
    """Bekannte Fehler: Statuscode und Meldung aus der Ausnahme."""
    safe_path = mask_secrets(request.url.path, settings.secret_values())
    logger.warning(
        f"Handled Exception [{exc.status_code}] auf {safe_path}: {exc.message}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "detail": exc.message},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Unerwartete Fehler: vollstaendig loggen, generisch antworten."""
    safe_path = mask_secrets(request.url.path, settings.secret_values())
    logger.error(f"UNERWARTETER SERVERFEHLER auf {safe_path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "detail": "Interner Serverfehler bei der Verarbeitung.",
        },
    )


app.include_router(webhook_router)


@app.get("/", status_code=status.HTTP_200_OK)
async def health_check() -> dict[str, str]:
    """Erreichbarkeitspruefung fuer den App Service."""
    return {"status": "online", "service": "Mondoo Webhook Receiver"}
