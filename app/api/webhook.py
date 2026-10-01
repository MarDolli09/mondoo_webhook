"""Webhook-Endpunkt: nimmt Mondoo-Ereignisse an und uebergibt sie der Verarbeitung."""

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request, status

from app.api.authentication import AuthenticatedDelivery, authenticate_delivery
from app.api.dependencies import AppResources, get_resources, get_webhook_processor
from app.api.telemetry import DeliveryContext, build_telemetry_record
from app.core.exceptions import PayloadParsingError
from app.core.logging import current_correlation_id, logger
from app.models.mondoo import MondooWebhookEvent
from app.services.processing import ProcessingResult, WebhookProcessor

__all__ = ["router"]

router = APIRouter(prefix="/webhook/mondoo", tags=["Webhook"])


@router.post("", status_code=status.HTTP_200_OK)
async def receive_mondoo_webhook(
    request: Request,
    delivery: AuthenticatedDelivery = Depends(authenticate_delivery),
    resources: AppResources = Depends(get_resources),
    processor: WebhookProcessor = Depends(get_webhook_processor),
) -> dict[str, Any]:

    received_at = datetime.now(timezone.utc)
    logger.info(f"=== WEBHOOK EMPFANGEN (webhook-id {delivery.webhook_id}) ===")
    resources.header_sampler.log_once(request)

    event = MondooWebhookEvent.from_payload(_decode_json_object(delivery.body))
    result = await processor.process(event)

    context = DeliveryContext(
        webhook_id=delivery.webhook_id,
        correlation_id=current_correlation_id(),
        received_at=received_at,
    )
    telemetry = build_telemetry_record(result, event, context)
    logger.info(json.dumps(telemetry, ensure_ascii=False))
    return _response(result)


def _decode_json_object(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise PayloadParsingError("Body ist kein gueltiges JSON.") from exc
    if not isinstance(payload, dict):
        raise PayloadParsingError("Body ist kein JSON-Objekt.")
    return payload


def _response(result: ProcessingResult) -> dict[str, Any]:
    outcome = result.outcome
    return {
        "status": "success",
        "action": outcome.action.value,
        "ticket_type": result.finding_type,
        "servicenow_number": outcome.ticket_number,
        "servicenow_sys_id": outcome.ticket_id,
    }
