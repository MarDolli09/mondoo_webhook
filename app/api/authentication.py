"""Authentifizierung eingehender Mondoo-Zustellungen: Auth-Header und Signatur.

Beide Pruefungen laufen, bevor der Body gelesen bzw. verarbeitet wird. Die
Antwort ist in jedem Fehlerfall ein generisches 401; der Grund steht im Log.
"""

import hmac
import time
from dataclasses import dataclass
from typing import NoReturn

from fastapi import Depends, Request

from app.api.dependencies import AppResources, get_resources
from app.core.config import settings
from app.core.exceptions import WebhookAuthenticationError
from app.core.logging import logger
from app.core.webhook_signature import SignatureVerificationError

__all__ = ["AuthenticatedDelivery", "authenticate_delivery"]


@dataclass(frozen=True)
class AuthenticatedDelivery:
    """Nachweislich von Mondoo stammende Zustellung mit unveraendertem Body."""

    webhook_id: str
    body: bytes


async def authenticate_delivery(
    request: Request, resources: AppResources = Depends(get_resources)
) -> AuthenticatedDelivery:
    """FastAPI-Abhaengigkeit: prueft Auth-Header und Standard-Webhooks-Signatur.

    Raises:
        WebhookAuthenticationError: Header fehlt oder stimmt nicht, oder die
            Signatur ist ungueltig bzw. veraltet.
    """
    header_name = settings.MONDOO_WEBHOOK_AUTH_HEADER
    received = request.headers.get(header_name, "")
    expected = settings.MONDOO_WEBHOOK_AUTH_HEADER_VALUE.get_secret_value()
    if not hmac.compare_digest(received.encode(), expected.encode()):
        _reject(f"Header '{header_name}' fehlt oder stimmt nicht.")

    body = await request.body()
    try:
        webhook_id = resources.webhook_verifier.verify(
            request.headers, body, now=time.time()
        )
    except SignatureVerificationError as exc:
        _reject(str(exc))

    return AuthenticatedDelivery(webhook_id=webhook_id, body=body)


def _reject(reason: str) -> NoReturn:
    logger.warning(f"Webhook abgewiesen: {reason}")
    raise WebhookAuthenticationError()
