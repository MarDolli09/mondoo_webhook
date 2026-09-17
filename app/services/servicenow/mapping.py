"""Abbildung eines NormalizedCase auf Katalogvariablen und RITM-Felder.

Reine Funktionen ohne I/O; die aufgeloesten sys_ids liefert der Client.
"""

from typing import Any, Optional

from app.core.logging import logger
from app.core.master_data import AUTOMATED_CREATOR_LABEL, FIXED_WATCHERS, master_data
from app.domain.case_text import strip_severity_prefix
from app.domain.priority import PRIORITY_SOURCE_DEFAULT
from app.models.case import NormalizedCase
from app.models.mondoo import MondooEventType
from app.services.servicenow.constants import (
    CORRELATION_ID_MAX,
    SHORT_DESCRIPTION_MAX,
    STATE_CLOSED_COMPLETE,
    STATE_CLOSED_SKIPPED,
    STATE_OPEN,
)

__all__ = [
    "build_catalog_variables",
    "build_create_fields",
    "build_update_fields",
    "correlation_id",
    "creator_display_name",
    "ticket_title",
    "watcher_identifiers",
]

TICKET_TITLE_PREFIX = "Mondoo - "
ELLIPSIS = "…"
WATCH_LIST_SEPARATOR = ","


def correlation_id(case: NormalizedCase) -> str:
    """Schluessel, ueber den ein RITM dem Mondoo-Case zugeordnet wird."""
    return _truncate(case.mrn, CORRELATION_ID_MAX)


def ticket_title(case: NormalizedCase) -> str:
    """Tickettitel ``Mondoo - <Mondoo-Titel ohne Schweregrad-Tag>``."""
    title = f"{TICKET_TITLE_PREFIX}{strip_severity_prefix(case.title)}"
    return _truncate(title, SHORT_DESCRIPTION_MAX)


def watcher_identifiers(case: NormalizedCase) -> list[str]:
    """Feste Beobachter und, bei menschlichem Ersteller, dessen Name."""
    watchers = list(FIXED_WATCHERS)

    if not case.is_automated and case.created_by:
        creator_name = master_data.USER_MAP.get(case.created_by.strip())
        if creator_name:
            known = {watcher.strip().lower() for watcher in watchers}
            if creator_name.strip().lower() not in known:
                watchers.append(creator_name.strip())

    return watchers


def creator_display_name(case: NormalizedCase) -> str:
    """Name des Erstellers laut USER_MAP, sonst dessen MRN."""
    if case.is_automated or not case.created_by:
        return AUTOMATED_CREATOR_LABEL

    creator_mrn = case.created_by.strip()
    return master_data.USER_MAP.get(creator_mrn, creator_mrn)


def build_catalog_variables(case: NormalizedCase) -> dict[str, str]:
    """Variablen des Katalogformulars "Mondoo Vulnerability" fuer ``order_now``.

    Reihenfolge wie im Formular. ``mondoo_mrn`` wird in ServiceNow per
    "Map to field" nach ``correlation_id`` uebernommen.
    """
    return {
        "mondoo_title": ticket_title(case),
        "mondoo_cve": case.finding_cve,
        "cvss_score": case.cvss_score,
        "cvss_rating": case.cvss_rating,
        "risk_rating": case.risk_rating,
        "risk_score": case.risk_score,
        "urgency": case.urgency,
        "impact": case.impact,
        "mondoo_space": case.mondoo_space,
        "finding_type": case.finding_type,
        "ticket_url": case.ticket_url,
        "assets_count": str(case.assets_count),
        "mondoo_created_by": creator_display_name(case),
        "mondoo_mrn": correlation_id(case),
    }


def build_create_fields(
    case: NormalizedCase,
    *,
    opened_by_sys_id: Optional[str],
    watcher_sys_ids: list[str],
) -> dict[str, Any]:
    """RITM-Felder direkt nach der Bestellung eines neuen Requests.

    Urgency und Impact uebernimmt ServiceNow aus den Katalogvariablen.
    """
    body: dict[str, Any] = {
        "work_notes": (
            f"Automatisch angelegt aus Mondoo-Ticket.\n"
            f"Mondoo createdAt: {case.created_at}"
        ),
        "state": STATE_OPEN,
        "correlation_id": correlation_id(case),
        "short_description": ticket_title(case),
    }
    if opened_by_sys_id:
        body["opened_by"] = opened_by_sys_id
    if watcher_sys_ids:
        # GlideList erwartet kommagetrennte sys_ids
        body["watch_list"] = WATCH_LIST_SEPARATOR.join(watcher_sys_ids)
    return body


def build_update_fields(case: NormalizedCase) -> dict[str, Any]:
    """RITM-Felder fuer ein Folgeereignis, inklusive Abschluss bei Close/Delete."""
    body: dict[str, Any] = {
        "work_notes": (
            f"Mondoo-Update ({case.raw_event_type}) vom {case.updated_at}\n"
            f"CVSS: {case.cvss_score or '-'} ({case.cvss_rating or '-'}) | "
            f"Betroffene Assets: {case.assets_count}"
        ),
    }

    if case.priority_source != PRIORITY_SOURCE_DEFAULT:
        body["urgency"] = case.urgency
        body["impact"] = case.impact
    else:
        logger.info(
            "Prioritaet nicht ermittelbar (Quelle 'default'). urgency/impact "
            "bleiben unveraendert."
        )

    body.update(_closing_fields(case.event_type))
    return body


def _closing_fields(event_type: MondooEventType) -> dict[str, Any]:
    if event_type is MondooEventType.CLOSED:
        return {
            "state": STATE_CLOSED_COMPLETE,
            "close_notes": (
                "Automatisierter Abschluss: Das zugehoerige Mondoo-Ticket wurde "
                "geschlossen. Der Befund gilt als behoben oder es wurde eine "
                "formale Ausnahme genehmigt."
            ),
        }
    if event_type is MondooEventType.DELETED:
        return {
            "state": STATE_CLOSED_SKIPPED,
            "close_notes": (
                "Das zugehoerige Mondoo-Ticket wurde geloescht. Der Befund wurde "
                "nicht nachweislich behoben. Bitte fachlich pruefen, bevor der "
                "Vorgang endgueltig abgelegt wird."
            ),
        }
    return {}


def _truncate(value: str, limit: int) -> str:
    if not value:
        return ""
    return value if len(value) <= limit else value[: limit - 1] + ELLIPSIS
