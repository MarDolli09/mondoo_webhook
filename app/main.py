import uuid
import time
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.api.webhook import router as webhook_router
from app.core.config import settings
from app.core.exceptions import MondooBaseException
from app.core.lifespan import lifespan
from app.core.logging import logger, mask_secrets

app = FastAPI(
    title="Mondoo Webhook Receiver",
    lifespan=lifespan
)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id

    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Correlation-ID"] = correlation_id
    logger.info(
        f'{{"event": "request_completed", "correlation_id": "{correlation_id}", "duration_ms": {duration_ms}}}'
    )
    return response

@app.exception_handler(MondooBaseException)
async def custom_exception_handler(request: Request, exc: MondooBaseException):
    safe_path = mask_secrets(request.url.path, settings.secret_values())
    logger.warning(
        f"Handled Exception [{exc.status_code}] auf {safe_path}: {exc.message}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "detail": exc.message,
        },
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    safe_path = mask_secrets(request.url.path, settings.secret_values())
    logger.error(
        f"UNERWARTETER SERVERFEHLER auf {safe_path}: {str(exc)}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "detail": "Interner Serverfehler bei der Verarbeitung.",
        },
    )

app.include_router(webhook_router)


@app.get("/", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "online", "service": "Mondoo Webhook Receiver"}