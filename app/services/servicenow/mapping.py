"""Abbildung eines NormalizedCase auf Katalogvariablen und RITM-Felder.

Reine Funktionen ohne I/O; die aufgeloesten sys_ids liefert der Client.
"""

from collections.abc import Mapping
from typing import Any, Optional

from app.core.logging import logger
from app.domain.case_text import strip_asset_suffix, strip_mitigate_phrase
from app.domain.identifiers import extract_space_id
from app.domain.priority import PrioritySource
from app.models.case import NormalizedCase
from app.models.mondoo import MondooEventType
from app.services.servicenow.constants import (
    AUTOMATED_CREATOR_LABEL,
    CORRELATION_ID_MAX,
    FIXED_WATCHERS,
    SHORT_DESCRIPTION_MAX,
    STATE_OPEN,
)

__all__ = [
    "build_catalog_variables",
    "build_create_fields",
    "build_update_fields",
    "closing_note",
    "correlation_id",
    "creator_display_name",
    "space_choice",
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
    """Tickettitel ``Mondoo - [SCHWEREGRAD] <Finding>``.

    Ohne "Mitigate vulnerability/advisory" und ohne das Asset ("on …") am Ende.
    """
    finding = strip_asset_suffix(strip_mitigate_phrase(case.title))
    title = f"{TICKET_TITLE_PREFIX}{finding}"
    return _truncate(title, SHORT_DESCRIPTION_MAX)


def watcher_identifiers(
    case: NormalizedCase, user_names: Mapping[str, str]
) -> list[str]:
    """Feste Beobachter und, bei menschlichem Ersteller, dessen Name.

    ``user_names`` ordnet Mondoo-Benutzer-MRNs den Namen in ServiceNow zu.
    """
    watchers = list(FIXED_WATCHERS)

    if not case.is_automated and case.created_by:
        creator_name = user_names.get(case.created_by.strip())
        if creator_name:
            known = {watcher.strip().lower() for watcher in watchers}
            if creator_name.strip().lower() not in known:
                watchers.append(creator_name.strip())

    return watchers


def creator_display_name(case: NormalizedCase, user_names: Mapping[str, str]) -> str:
    """Name des Erstellers laut ``user_names``, sonst dessen MRN."""
    if case.is_automated or not case.created_by:
        return AUTOMATED_CREATOR_LABEL

    creator_mrn = case.created_by.strip()
    return user_names.get(creator_mrn, creator_mrn)


def space_choice(case: NormalizedCase, space_choices: Mapping[str, str]) -> str:
    """Auswahlwert der Variable ``mondoo_space``, z. B. ``space_server``.

    ``space_choices`` ordnet Mondoo-Space-IDs den Auswahlwerten des Formulars
    zu. Fehlt der Space, geht der Anzeigename an ServiceNow; der Workflow
    ordnet ihn dann keiner Gruppe zu, deshalb ERROR und Alarm.
    """
    space_id = extract_space_id(case.owner_mrn) or ""
    choice = space_choices.get(space_id)
    if choice:
        return choice
    logger.error(
        f"Kein Auswahlwert fuer Space '{case.mondoo_space or space_id}' in "
        f"SPACE_CHOICE_MAP. Der Workflow kann den SCTASK keiner Gruppe zuordnen."
    )
    return case.mondoo_space


def build_catalog_variables(
    case: NormalizedCase,
    user_names: Mapping[str, str],
    space_choices: Mapping[str, str],
) -> dict[str, str]:
    """Variablen des Katalogformulars "Mondoo Vulnerability" fuer ``order_now``.

    Reihenfolge wie im Formular. ``mondoo_mrn`` wird in ServiceNow per
    "Map to field" nach ``correlation_id`` uebernommen.
    """
    return {
        "cve": case.finding_cve,
        "cvss_score": case.cvss_score,
        "cvss_risk_rating": case.cvss_rating,
        "mondoo_risk_rating": case.risk_rating,
        "mondoo_risk_score": case.risk_score,
        "mondoo_space": space_choice(case, space_choices),
        "finding_type": case.finding_type,
        "mondoo_ticket_url": case.ticket_url,
        "number_of_affected_assets": str(case.assets_count),
        "created_by": creator_display_name(case, user_names),
        "urgency": case.urgency,
        "impact": case.impact,
        "mondoo_mrn": correlation_id(case),
    }


def build_create_fields(
    case: NormalizedCase,
    *,
    opened_by_sys_id: Optional[str],
    watcher_sys_ids: list[str],
) -> dict[str, Any]:
    """RITM-Felder direkt nach der Bestellung eines neuen Requests.

    Urgency und Impact werden wie die Katalogvariablen gesetzt: Ohne "Map to
    field" am Formular stuende das RITM sonst auf dem Standard 3 - Low, bis ein
    Update-Ereignis kommt.
    """
    body: dict[str, Any] = {
        "work_notes": (
            f"Automatisch angelegt aus Mondoo-Ticket.\n"
            f"Mondoo createdAt: {case.created_at}"
        ),
        "state": STATE_OPEN,
        "correlation_id": correlation_id(case),
        "short_description": ticket_title(case),
        "urgency": case.urgency,
        "impact": case.impact,
    }
    if opened_by_sys_id:
        body["opened_by"] = opened_by_sys_id
    if watcher_sys_ids:
        # GlideList erwartet kommagetrennte sys_ids
        body["watch_list"] = WATCH_LIST_SEPARATOR.join(watcher_sys_ids)
    return body


def build_update_fields(case: NormalizedCase) -> dict[str, Any]:
    """RITM-Felder fuer ein Folgeereignis; bei Close/Delete mit Hinweis.

    Der Status bleibt unveraendert: Tasks schliessen nur Bearbeiter mit
    Zeitbuchung, das RITM schliesst der Workflow nach dem Pruef-SCTASK.
    """
    work_notes = (
        f"Mondoo-Update ({case.raw_event_type}) vom {case.updated_at}\n"
        f"CVSS: {case.cvss_score or '-'} ({case.cvss_rating or '-'}) | "
        f"Betroffene Assets: {case.assets_count}"
    )
    note = closing_note(case.event_type)
    if note:
        work_notes = f"{work_notes}\n{note}"
    body: dict[str, Any] = {"work_notes": work_notes}

    if case.priority_source is not PrioritySource.DEFAULT:
        body["urgency"] = case.urgency
        body["impact"] = case.impact
    else:
        logger.info(
            "Prioritaet nicht ermittelbar (Quelle 'default'). urgency/impact "
            "bleiben unveraendert."
        )
    return body


def closing_note(event_type: MondooEventType) -> Optional[str]:
    """Hinweis an RITM und offene SCTASKs, wenn Mondoo das Ticket beendet."""
    if event_type is MondooEventType.CLOSED:
        return (
            "Mondoo hat das Ticket geschlossen: Befund behoben oder per Ausnahme "
            "erledigt. Bitte Zeit buchen und den offenen SCTASK schliessen; das "
            "RITM schliesst der Workflow nach dem Pruef-SCTASK."
        )
    if event_type is MondooEventType.DELETED:
        return (
            "Das zugehoerige Mondoo-Ticket wurde geloescht. Der Befund wurde "
            "nicht nachweislich behoben. Bitte fachlich pruefen, bevor der "
            "Vorgang abgeschlossen wird."
        )
    return None


def _truncate(value: str, limit: int) -> str:
    if not value:
        return ""
    return value if len(value) <= limit else value[: limit - 1] + ELLIPSIS
