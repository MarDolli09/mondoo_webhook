"""Webhook-Endpunkt: nimmt Mondoo-Ereignisse an und synchronisiert ServiceNow."""

import json
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request, status

from app.api.authentication import AuthenticatedDelivery, authenticate_delivery
from app.api.dependencies import (
    AppResources,
    get_case_parser,
    get_resources,
    get_ticket_synchronizer,
)
from app.api.telemetry import build_telemetry_record
from app.core.exceptions import PayloadParsingError
from app.core.logging import current_correlation_id, logger
from app.domain.ports import TicketSynchronizer
from app.models.mondoo import MondooWebhookEvent
from app.services.parsing import CaseParser

__all__ = ["router"]

router = APIRouter(prefix="/webhook/mondoo", tags=["Webhook"])


@router.post("", status_code=status.HTTP_200_OK)
async def receive_mondoo_webhook(
    request: Request,
    delivery: AuthenticatedDelivery = Depends(authenticate_delivery),
    resources: AppResources = Depends(get_resources),
    case_parser: CaseParser = Depends(get_case_parser),
    ticket_synchronizer: TicketSynchronizer = Depends(get_ticket_synchronizer),
) -> dict[str, Any]:
    """Verarbeitet eine authentifizierte Mondoo-Zustellung.

    Ablauf: normalisieren, mit CVSS anreichern, mit ServiceNow synchronisieren.
    """
    received_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    logger.info(f"=== WEBHOOK EMPFANGEN (webhook-id {delivery.webhook_id}) ===")
    resources.header_sampler.log_once(request)

    event = MondooWebhookEvent.from_payload(_decode_json_object(delivery.body))
    finding_type = case_parser.classify_finding_type(event)
    logger.info(
        f"Typ '{finding_type}' erkannt, Ereignis '{event.raw_type or '-'}', "
        f"{event.case.assets_count} Assets. Starte Parsing..."
    )

    # 1. Parsing, Bereinigung und optionale CVSS-Anreicherung
    case = await case_parser.parse(event, finding_type)
    parse_ms = _elapsed_ms(started)

    # 2. Uebergabe an ServiceNow (Lookup via correlation_id -> order_now oder Update)
    servicenow_started = time.perf_counter()
    servicenow_record = await ticket_synchronizer.synchronize(case)
    servicenow_ms = _elapsed_ms(servicenow_started)

    # 3. Strukturierte Telemetrie
    telemetry = build_telemetry_record(
        finding_type=finding_type,
        event=event,
        case=case,
        servicenow_record=servicenow_record,
        parse_ms=parse_ms,
        servicenow_ms=servicenow_ms,
        received_at=received_at,
        correlation_id=current_correlation_id(),
        webhook_id=delivery.webhook_id,
    )
    logger.info(json.dumps(telemetry, ensure_ascii=False))

    return {
        "status": "success",
        "action": servicenow_record.get("action"),
        "ticket_type": finding_type,
        "servicenow_number": servicenow_record.get("number"),
        "servicenow_sys_id": servicenow_record.get("sys_id"),
    }


def _decode_json_object(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise PayloadParsingError("Body ist kein gueltiges JSON.") from exc
    if not isinstance(payload, dict):
        raise PayloadParsingError("Body ist kein JSON-Objekt.")
    return payload


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)
