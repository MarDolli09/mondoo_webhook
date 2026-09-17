"""Teilsystem HTTP-API: Webhook-Router und Lebenszyklus der Anwendung."""

from app.api.dependencies import lifespan
from app.api.webhook import router as webhook_router

__all__ = ["lifespan", "webhook_router"]
