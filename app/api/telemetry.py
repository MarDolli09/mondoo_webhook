"""Telemetrie: strukturierter Verarbeitungsdatensatz und Header-Stichprobe."""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from zoneinfo import ZoneInfo

from fastapi import Request

from app.core.logging import logger
from app.models.mondoo import MondooWebhookEvent
from app.services.processing import ProcessingResult

__all__ = ["DeliveryContext", "InboundHeaderSampler", "build_telemetry_record"]

TELEMETRY_EVENT = "mondoo_to_servicenow_processed"
LOCAL_TIMEZONE = ZoneInfo("Europe/Berlin")
SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key"}
)


class InboundHeaderSampler:
    """Protokolliert einmalig die Header eines eingehenden Requests (DEBUG).

    Sensible Header werden ausgelassen, darunter der konfigurierte Auth-Header.
    Eine Instanz lebt im Lifespan.
    """

    def __init__(self, extra_sensitive_headers: Iterable[str] = ()) -> None:
        self._logged = False
        self._sensitive = SENSITIVE_HEADERS | {
            name.lower() for name in extra_sensitive_headers
        }

    def log_once(self, request: Request) -> None:
        """Schreibt die Stichprobe beim ersten Aufruf, danach nichts mehr."""
        if self._logged:
            return
        self._logged = True
        safe = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in self._sensitive
        }
        logger.debug(json.dumps({"event": "inbound_headers_sample", "headers": safe}))


@dataclass(frozen=True)
class DeliveryContext:
    """Angaben zur Zustellung, die nicht aus der Verarbeitung stammen."""

    webhook_id: str
    correlation_id: Optional[str]
    received_at: datetime


def build_telemetry_record(
    result: ProcessingResult, event: MondooWebhookEvent, context: DeliveryContext
) -> dict[str, Any]:
    """Ein JSON-Datensatz je verarbeitetem Webhook fuer die Auswertung.

    Die Feldnamen werden in Log Analytics ausgewertet und bleiben stabil.
    """
    case = result.case
    outcome = result.outcome
    received_at = context.received_at
    mondoo_created_at = event.case.created_at
    return {
        "event": TELEMETRY_EVENT,
        "ticket_type": result.finding_type,
        "mondoo_event": case.raw_event_type,
        "mapped_event": case.event_type.value,
        "case_status": case.case_status or None,
        "creator": case.created_by or None,
        "snow_action": outcome.action.value,
        "servicenow_ritm": outcome.ticket_number,
        "servicenow_sys_id": outcome.ticket_id,
        "priority_source": case.priority_source.value,
        "urgency": case.urgency,
        "impact": case.impact,
        "cvss_score": case.cvss_score or None,
        "cvss_rating": case.cvss_rating or None,
        "risk_rating": case.risk_rating or None,
        "risk_score": case.risk_score or None,
        "assets_reported": event.case.assets_count,
        "is_automated": case.is_automated,
        "parse_duration_ms": result.parse_ms,
        "servicenow_duration_ms": result.servicenow_ms,
        "mondoo_created_at": mondoo_created_at,
        "webhook_received_at_utc": received_at.isoformat(),
        "webhook_received_at_local": received_at.astimezone(LOCAL_TIMEZONE).isoformat(),
        "latency_seconds": _latency_seconds(mondoo_created_at, received_at),
        "case_mrn": case.mrn,
        "correlation_id": context.correlation_id,
        "webhook_id": context.webhook_id,
    }


def _latency_seconds(
    mondoo_created_at: Optional[str], received_at: datetime
) -> Optional[float]:
    if not mondoo_created_at:
        return None
    try:
        created = datetime.fromisoformat(mondoo_created_at.replace("Z", "+00:00"))
        return round((received_at - created).total_seconds(), 2)
    except (ValueError, TypeError):
        return None
