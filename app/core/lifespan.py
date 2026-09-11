from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI
from app.core.config import settings
from app.core.logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    timeout_config = httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout_config) as client:
        app.state.http_client = client
        yield
    logger.info("Gemeinsamer HTTP-Client erfolgreich geschlossen.")