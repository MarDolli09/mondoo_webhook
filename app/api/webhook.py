import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, Depends, Request, status

from app.core.config import settings
from app.core.exceptions import InvalidSecretKeyError, MondooBaseException
from app.core.logging import logger
from app.services.mondoo_client import MondooGraphQLClient
from app.services.servicenow import ServiceNowClient
from app.services.ticket_parser import TicketParserService

router = APIRouter(prefix="/webhook/mondoo", tags=["Webhook"])

# Header, die niemals protokolliert werden
_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}

# Die Header werden einmal pro Prozesslebensdauer protokolliert. Zweck: pruefen,
# ob Mondoo einen Trigger-Header mitsendet (z. B. X-Mondoo-Trigger), ueber den
# sich Drift-Tickets von manuell eroeffneten unterscheiden liessen. Sobald das
# geklaert ist, kann der Block entfallen.
_headers_logged = False


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


def _log_headers_once(request: Request) -> None:
    global _headers_logged
    if _headers_logged:
        return
    _headers_logged = True
    safe = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in _SENSITIVE_HEADERS
    }
    logger.info(json.dumps({"event": "inbound_headers_sample", "headers": safe}))


def _compute_latency(mondoo_created_at: Any, received_at: datetime):
    if not mondoo_created_at or not isinstance(mondoo_created_at, str):
        return None
    try:
        created = datetime.fromisoformat(mondoo_created_at.replace("Z", "+00:00"))
        return round((received_at - created).total_seconds(), 2)
    except (ValueError, TypeError):
        return None


@router.post("/{secret_key}", status_code=status.HTTP_200_OK)
async def receive_mondoo_webhook(
    secret_key: str,
    payload: Dict[str, Any],
    request: Request,
    parser_service: TicketParserService = Depends(get_ticket_parser_service),
    snow_client: ServiceNowClient = Depends(get_servicenow_client),
) -> Dict[str, Any]:
    verify_secret_key(secret_key)

    received_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    logger.info("=== WEBHOOK EMPFANGEN ===")
    _log_headers_once(request)

    normalized = parser_service.normalize_payload(payload)
    case_raw = normalized.get("case", {})
    mondoo_created_at = case_raw.get("createdAt")

    detected_type = parser_service.classify_ticket_type(normalized)
    logger.info(
        f"Typ '{detected_type}' erkannt, Ereignis '{normalized.get('type', '-')}', "
        f"{case_raw.get('assetsCount', 0)} Assets. Starte Parsing..."
    )

    # 1. Parsing, Bereinigung und optionale GraphQL-Anreicherung
    parsed_result, cvss_found_on_page = await parser_service.process_payload(
        normalized, detected_type
    )
    parse_ms = round((time.perf_counter() - started) * 1000, 2)

    # 2. Uebergabe an ServiceNow (Lookup via correlation_id -> order_now oder Update)
    snow_started = time.perf_counter()
    snow_record = await snow_client.process_payload(parsed_result)
    snow_ms = round((time.perf_counter() - snow_started) * 1000, 2)

    case = parsed_result.case

    # 3. Telemetrie
    logger.info(
        json.dumps(
            {
                "event": "mondoo_to_servicenow_processed",
                "ticket_type": detected_type,
                "mondoo_event": case.ticketState,
                "mapped_event": case.eventType.value,
                "snow_action": snow_record.get("action"),
                "servicenow_ritm": snow_record.get("number"),
                "servicenow_sys_id": snow_record.get("sys_id"),
                "attachment_stored": snow_record.get("attachment"),
                "priority_source": case.prioritySource,
                "urgency": case.urgency,
                "impact": case.impact,
                "cvss_score": case.cvssScore or None,
                "cvss_rating": case.cvssRiskRating or None,
                "risk_rating": case.riskRating or None,
                "risk_score": case.riskScore or None,
                "cvss_found_on_page": cvss_found_on_page,
                "assets_reported": case.assetsCount,
                "assets_resolved": len(case.remediations.table),
                "is_automated": case.isAutomated,
                "parse_duration_ms": parse_ms,
                "servicenow_duration_ms": snow_ms,
                "mondoo_created_at": mondoo_created_at,
                "webhook_received_at_utc": received_at.isoformat(),
                "webhook_received_at_local": received_at.astimezone(
                    ZoneInfo("Europe/Berlin")
                ).isoformat(),
                "latency_seconds": _compute_latency(mondoo_created_at, received_at),
            },
            ensure_ascii=False,
        )
    )

    return {
        "status": "success",
        "action": snow_record.get("action"),
        "ticket_type": detected_type,
        "servicenow_number": snow_record.get("number"),
        "servicenow_sys_id": snow_record.get("sys_id"),
    }