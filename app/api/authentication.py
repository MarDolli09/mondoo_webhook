"""Authentifizierung eingehender Mondoo-Zustellungen: Auth-Header und Signatur.

Beide Pruefungen laufen immer vollstaendig, bevor der Body verarbeitet wird.
So zeigt das Log bei einer Abweisung, ob die Zustellung gueltig von Mondoo
signiert war und woran der Header scheiterte. Die Antwort ist in jedem
Fehlerfall ein generisches 401; Secret-Werte werden nie protokolliert.
"""

import hmac
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Request

from app.api.dependencies import AppResources, get_resources
from app.core.config import settings
from app.core.exceptions import WebhookAuthenticationError
from app.core.logging import logger
from app.core.webhook_signature import SignatureVerificationError

__all__ = ["AuthenticatedDelivery", "authenticate_delivery"]

BEARER_PREFIX = "Bearer "
LOGGED_HEADER_MAX = 120


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
    header_problem = _diagnose_auth_header(
        request.headers.get(header_name),
        settings.MONDOO_WEBHOOK_AUTH_HEADER_VALUE.get_secret_value(),
    )

    body = await request.body()
    webhook_id: Optional[str] = None
    try:
        webhook_id = resources.webhook_verifier.verify(
            request.headers, body, now=time.time()
        )
        signature_result = f"gueltig (webhook-id {webhook_id})"
    except SignatureVerificationError as exc:
        signature_result = f"ungueltig: {exc}"

    if header_problem is None and webhook_id is not None:
        return AuthenticatedDelivery(webhook_id=webhook_id, body=body)

    logger.warning(
        f"Webhook abgewiesen | Header '{header_name}': {header_problem or 'ok'} "
        f"| Signatur: {signature_result} "
        f"| User-Agent: {_header_for_log(request, 'user-agent')} "
        f"| X-Forwarded-For: {_header_for_log(request, 'x-forwarded-for')}"
    )
    raise WebhookAuthenticationError()


def _diagnose_auth_header(received: Optional[str], expected: str) -> Optional[str]:
    """Beschreibt die Abweichung ohne Werte; ``None`` bei Uebereinstimmung."""
    if received is None:
        return "fehlt"
    if hmac.compare_digest(received.encode(), expected.encode()):
        return None
    return (
        f"Wert stimmt nicht (Laenge empfangen {len(received)}, erwartet "
        f"{len(expected)}; '{BEARER_PREFIX.strip()}'-Praefix empfangen "
        f"{_yes_no(received.startswith(BEARER_PREFIX))}, erwartet "
        f"{_yes_no(expected.startswith(BEARER_PREFIX))})"
    )


def _header_for_log(request: Request, name: str) -> str:
    value = request.headers.get(name)
    return repr(value[:LOGGED_HEADER_MAX]) if value is not None else "-"


def _yes_no(flag: bool) -> str:
    return "ja" if flag else "nein"
