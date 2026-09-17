"""Telemetrie: strukturierter Verarbeitungsdatensatz und Header-Stichprobe."""

import json
from datetime import datetime
from typing import Any, Optional
from zoneinfo import ZoneInfo

from fastapi import Request

from app.core.logging import logger
from app.models.case import NormalizedCase
from app.models.mondoo import MondooWebhookEvent

__all__ = ["InboundHeaderSampler", "build_telemetry_record"]

TELEMETRY_EVENT = "mondoo_to_servicenow_processed"
LOCAL_TIMEZONE = ZoneInfo("Europe/Berlin")
SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key"}
)


class InboundHeaderSampler:
    """Protokolliert einmalig die Header eines eingehenden Requests.

    Sensible Header werden ausgelassen. Eine Instanz lebt im Lifespan.
    """

    def __init__(self) -> None:
        self._logged = False

    def log_once(self, request: Request) -> None:
        """Schreibt die Stichprobe beim ersten Aufruf, danach nichts mehr."""
        if self._logged:
            return
        self._logged = True
        safe = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in SENSITIVE_HEADERS
        }
        logger.info(json.dumps({"event": "inbound_headers_sample", "headers": safe}))


def build_telemetry_record(
    *,
    finding_type: str,
    event: MondooWebhookEvent,
    case: NormalizedCase,
    servicenow_record: dict[str, Any],
    parse_ms: float,
    servicenow_ms: float,
    received_at: datetime,
    correlation_id: Optional[str],
) -> dict[str, Any]:
    """Ein JSON-Datensatz je verarbeitetem Webhook fuer die Auswertung."""
    mondoo_created_at = event.case.created_at
    return {
        "event": TELEMETRY_EVENT,
        "ticket_type": finding_type,
        "mondoo_event": case.raw_event_type,
        "mapped_event": case.event_type.value,
        "case_status": case.case_status or None,
        "creator": case.created_by or None,
        "snow_action": servicenow_record.get("action"),
        "servicenow_ritm": servicenow_record.get("number"),
        "servicenow_sys_id": servicenow_record.get("sys_id"),
        "priority_source": case.priority_source,
        "urgency": case.urgency,
        "impact": case.impact,
        "cvss_score": case.cvss_score or None,
        "cvss_rating": case.cvss_rating or None,
        "risk_rating": case.risk_rating or None,
        "risk_score": case.risk_score or None,
        "cvss_found_on_page": case.cvss_found_on_page,
        "assets_reported": event.case.assets_count,
        "is_automated": case.is_automated,
        "parse_duration_ms": parse_ms,
        "servicenow_duration_ms": servicenow_ms,
        "mondoo_created_at": mondoo_created_at,
        "webhook_received_at_utc": received_at.isoformat(),
        "webhook_received_at_local": received_at.astimezone(LOCAL_TIMEZONE).isoformat(),
        "latency_seconds": _latency_seconds(mondoo_created_at, received_at),
        "case_mrn": case.mrn,
        "correlation_id": correlation_id,
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
