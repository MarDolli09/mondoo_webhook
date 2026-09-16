import json
import re
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.core.logging import logger
from app.models.schemas import (
    MondooEventType,
    ServiceNowCase,
    ServiceNowPayload,
)
from app.utils.text_cleaner import sanitize_url

from .constants import (
    CORRELATION_ID_MAX,
    FIXED_WATCHERS,
    SHORT_DESCRIPTION_MAX,
    STATE_CLOSED_COMPLETE,
    STATE_CLOSED_SKIPPED,
    STATE_OPEN,
)

SPACE_ID_PATTERN = re.compile(r"/spaces/([^/]+)")

FALLBACK_ASSIGNMENT_GROUP = "Mosca IT - Security"


# ---------------------------------------------------------------------- #
# Helfer
# ---------------------------------------------------------------------- #

def truncate(value: str, limit: int) -> str:
    if not value:
        return ""
    return value if len(value) <= limit else value[: limit - 1] + "\u2026"


def extract_space_id(owner_mrn: str) -> str:
    match = SPACE_ID_PATTERN.search(owner_mrn or "")
    return match.group(1) if match else ""


def correlation_id(payload: ServiceNowPayload) -> str:
    return truncate(payload.case.mrn, CORRELATION_ID_MAX)


def assignment_group_name(payload: ServiceNowPayload) -> str:
    space_id = extract_space_id(payload.case.ownerMrn)
    group_name = settings.ASSIGNMENTGROUP_MAP.get(space_id)
    if not group_name:
        logger.warning(
            f"Keine Assignment Group fuer Space '{space_id}' hinterlegt. "
            f"Fallback auf '{FALLBACK_ASSIGNMENT_GROUP}'."
        )
        return FALLBACK_ASSIGNMENT_GROUP
    return group_name


def watcher_names(payload: ServiceNowPayload) -> List[str]:
    case = payload.case
    watchers = list(FIXED_WATCHERS)

    # Wenn menschlicher Ersteller vorhanden: Namen über USER_MAP auflösen
    if not case.isAutomated and case.createdBy:
        creator_name = settings.USER_MAP.get(case.createdBy.strip())
        if creator_name and creator_name not in watchers:
            watchers.append(creator_name)

    return watchers

def resolve_creator_name(case: ServiceNowCase) -> str:
    if case.isAutomated or not case.createdBy:
        return "Mondoo-Drift"
    
    mrn = case.createdBy.strip()
    return settings.USER_MAP.get(mrn, mrn)


# ---------------------------------------------------------------------- #
# Katalogvariablen
# ---------------------------------------------------------------------- #

def build_variables(payload: ServiceNowPayload) -> Dict[str, str]:
    case = payload.case

    mrvs_rows: List[Dict[str, str]] = [
        {
            "asset_name": asset.asset_name_name,
            "asset_url": sanitize_url(asset.asset_name_url),
            "platform": asset.platform,
        }
        for asset in case.remediations.table
    ]

    return {
        "mondoo_mrn": correlation_id(payload),
        "mondoo_title": truncate(case.title, SHORT_DESCRIPTION_MAX),
        "mondoo_cve": case.findingCVE or "",
        "cvss_score": case.cvssScore or "",
        "cvss_rating": case.cvssRiskRating or "",
        "risk_rating": case.riskRating or "",
        "risk_score": case.riskScore or "",
        "mondoo_space": case.mondooSpace or "",
        "finding_type": case.ticketType or "",
        "ticket_url": sanitize_url(case.ticket_url),
        "assets_count": str(case.assetsCount or len(case.remediations.table)),
        "mondoo_created_by": resolve_creator_name(case),
        "mondoo_assets": json.dumps(mrvs_rows, ensure_ascii=False),
    }


# ---------------------------------------------------------------------- #
# Textfelder
# ---------------------------------------------------------------------- #



def build_work_notes(payload: ServiceNowPayload, *, is_initial: bool) -> str:
    case = payload.case
    if is_initial:
        return (
            f"Automatisch angelegt aus Mondoo-Ticket.\n"
            f"Mondoo createdAt: {case.createdAt}"
        )
    return (
        f"Mondoo-Update ({case.ticketState}) vom {case.updatedAt}\n"
        f"CVSS: {case.cvssScore or '-'} ({case.cvssRiskRating or '-'}) | "
        f"Betroffene Assets: {case.assetsCount}"
    )


# ---------------------------------------------------------------------- #
# Task-Felder
# ---------------------------------------------------------------------- #

def _closing_fields(event_type: MondooEventType) -> Dict[str, Any]:
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


def build_task_fields(
    payload: ServiceNowPayload,
    *,
    is_initial: bool,
    group_sys_id: Optional[str] = None,
    opened_by_sys_id: Optional[str] = None,
    watcher_sys_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    case = payload.case

    body: Dict[str, Any] = {
        "work_notes": build_work_notes(payload, is_initial=is_initial),
    }

    if is_initial or case.prioritySource != "default":
        body["urgency"] = case.urgency
        body["impact"] = case.impact
    else:
        logger.info(
            "Prioritaet nicht ermittelbar (Quelle 'default'). urgency/impact "
            "bleiben unveraendert."
        )

    if group_sys_id:
        body["assignment_group"] = group_sys_id

    if is_initial:
        body["state"] = STATE_OPEN
        body["correlation_id"] = correlation_id(payload)
        body["short_description"] = truncate(case.title, SHORT_DESCRIPTION_MAX)
        
        if opened_by_sys_id:
            body["opened_by"] = opened_by_sys_id

        if watcher_sys_ids:
            # GlideList erwartet kommagetrennte Sys-IDs
            body["watch_list"] = ",".join(watcher_sys_ids)

    body.update(_closing_fields(case.eventType))
    return body