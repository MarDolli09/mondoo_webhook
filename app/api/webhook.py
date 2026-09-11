import json
import secrets
from datetime import datetime, timezone
from typing import Any, Dict
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, Depends, Request, status

from app.core.config import settings
from app.core.exceptions import InvalidSecretKeyError, MondooBaseException
from app.core.logging import logger
from app.services.mondoo_client import MondooGraphQLClient
from app.services.servicenow_client import ServiceNowClient
from app.services.ticket_parser import TicketParserService

router = APIRouter(prefix="/webhook/mondoo", tags=["Webhook"])


def get_http_client(request: Request) -> httpx.AsyncClient:
    return request.app.state.http_client


def get_servicenow_client(
    http_client: httpx.AsyncClient = Depends(get_http_client),
) -> ServiceNowClient:
    return ServiceNowClient(http_client)


def get_ticket_parser_service(
    http_client: httpx.AsyncClient = Depends(get_http_client),
) -> TicketParserService:
    mondoo_client = MondooGraphQLClient(http_client=http_client)
    return TicketParserService(mondoo_client)


def verify_secret_key(secret_key: str) -> None:
    if not settings.WEBHOOK_SECRET_KEY:
        raise MondooBaseException("Konfigurationsfehler: Secret Key fehlt!", status_code=500)

    if not secrets.compare_digest(secret_key, settings.WEBHOOK_SECRET_KEY):
        raise InvalidSecretKeyError()


@router.post("/{secret_key}", status_code=status.HTTP_200_OK)
async def receive_mondoo_webhook(
    secret_key: str,
    payload: Dict[str, Any],
    parser_service: TicketParserService = Depends(get_ticket_parser_service),
    snow_client: ServiceNowClient = Depends(get_servicenow_client),
) -> Dict[str, Any]:
    verify_secret_key(secret_key)
    received_at = datetime.now(timezone.utc)
    logger.info("=== WEBHOOK EMPFANGEN ===")

    normalized = parser_service.normalize_payload(payload)
    mondoo_created_at = normalized.get("case", {}).get("createdAt")

    detected_type = parser_service.classify_ticket_type(normalized)
    logger.info(f"Typ '{detected_type}' erkannt. Starte Parsing...")

    # 1. Parsing, Bereinigung und optionale GraphQL-Anreicherung
    parsed_result, cvss_found_on_page = await parser_service.process_payload(
        normalized, detected_type
    )

    # 2. Übergabe an ServiceNow (Lookup via correlation_id -> Order Now RITM oder Update)
    snow_record = await snow_client.process_payload(parsed_result)

    # 3. Latenzmessung & Performance-Logging
    latency_s = None
    if mondoo_created_at and isinstance(mondoo_created_at, str):
        try:
            created = datetime.fromisoformat(mondoo_created_at.replace("Z", "+00:00"))
            latency_s = round((received_at - created).total_seconds(), 2)
        except (ValueError, TypeError):
            latency_s = None

    logger.info(
        json.dumps({
            "event": "mondoo_to_servicenow_processed",
            "ticket_type": detected_type,
            "cvss_found_on_page": cvss_found_on_page,
            "servicenow_ritm": snow_record.get("number"),
            "servicenow_sys_id": snow_record.get("sys_id"),
            "mondoo_created_at": mondoo_created_at,
            "webhook_received_at_utc": received_at.isoformat(),
            "webhook_received_at_local": received_at.astimezone(
                ZoneInfo("Europe/Berlin")
            ).isoformat(),
            "latency_seconds": latency_s,
        })
    )

    return {
        "status": "success",
        "ticket_type": detected_type,
        "servicenow_number": snow_record.get("number"),
        "servicenow_sys_id": snow_record.get("sys_id"),
    }