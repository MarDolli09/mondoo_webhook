import json
import re
from typing import Any, Dict, List, Optional
 
from app.core.config import settings
from app.core.logging import logger
from app.models.schemas import MondooEventType, ServiceNowPayload
from app.utils.text_cleaner import sanitize_url
 
from .constants import (
    CORRELATION_ID_MAX,
    DESCRIPTION_MAX,
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
 
 
def attachment_file_name(payload: ServiceNowPayload) -> str:
    cve_part = (payload.case.findingCVE or "").replace("/", "-").strip() or "details"
    return f"mondoo_finding_{cve_part}.md"
 
 
def watcher_names(payload: ServiceNowPayload) -> List[str]:
    case = payload.case
    watchers = list(FIXED_WATCHERS)

    # Wenn menschlicher Ersteller vorhanden: Namen über USER_MAP auflösen
    if not case.isAutomated and case.createdBy:
        creator_name = settings.USER_MAP.get(case.createdBy.strip())
        if creator_name and creator_name not in watchers:
            watchers.append(creator_name)

    return watchers

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
        "assets_count": str(case.assetsCount),
        "mondoo_created_by": case.createdBy or "",
        "mondoo_policies": case.policies or "",
        "mondoo_assets": json.dumps(mrvs_rows, ensure_ascii=False),
    }
 
 
# ---------------------------------------------------------------------- #
# Textfelder
# ---------------------------------------------------------------------- #
 
def _risk_line(payload: ServiceNowPayload) -> str:
    case = payload.case
    if case.cvssRiskRating or case.cvssScore:
        return f"CVSS: {case.cvssScore or '-'} ({case.cvssRiskRating or '-'})"
    if case.riskRating:
        suffix = f" ({case.riskScore}/100)" if case.riskScore else ""
        return f"Mondoo Risk: {case.riskRating}{suffix}"
    return "Risikobewertung: nicht ermittelbar"
 
 
def _description_header(payload: ServiceNowPayload) -> str:
    case = payload.case
    lines = [
        f"Mondoo Security Finding | {case.mondooSpace} | {case.ticketType}",
        f"CVE: {case.findingCVE}   {_risk_line(payload)}",
        f"Betroffene Assets: {case.assetsCount}",
        f"Mondoo-Ticket: {sanitize_url(case.ticket_url)}",
    ]
    if case.policies:
        lines.append(f"Policy: {case.policies}")
 
    lines.append("")
 

    shown = case.remediations.table[: settings.DESCRIPTION_ASSET_PREVIEW]
    hidden = len(case.remediations.table) - len(shown)
 
    lines.append("Betroffene Systeme (Auszug):" if hidden else "Betroffene Systeme:")
    lines.extend(f"  - {a.asset_name_name} ({a.platform})" for a in shown)
    if hidden > 0:
        lines.append(f"  ... und {hidden} weitere (siehe Formularvariablen und Anhang)")
 
    lines.extend(["", "-" * 60, ""])
    return "\n".join(lines)
 
 
def build_description(payload: ServiceNowPayload) -> str:
    case = payload.case
    lines = [
        f"Mondoo Security Finding | {case.mondooSpace} | {case.ticketType}",
        f"CVE: {case.findingCVE}   {_risk_line(payload)}",
        f"Betroffene Assets: {case.assetsCount}",
        f"Mondoo-Ticket: {sanitize_url(case.ticket_url)}",
    ]

    lines.append("")
    shown = case.remediations.table[: settings.DESCRIPTION_ASSET_PREVIEW]
    hidden = len(case.remediations.table) - len(shown)

    lines.append("Betroffene Systeme (Auszug):" if hidden else "Betroffene Systeme:")
    lines.extend(f"  - {a.asset_name_name} ({a.platform})" for a in shown)
    if hidden > 0:
        lines.append(f"  ... und {hidden} weitere (siehe Formularvariablen)")

    return "\n".join(lines)[:DESCRIPTION_MAX]
 
 
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
        # Ein Delete in Mondoo bedeutet nicht, dass der Befund behoben wurde.
        # Deshalb Closed Skipped statt Closed Complete.
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
        "urgency": case.urgency,
        "impact": case.impact,
        "work_notes": build_work_notes(payload, is_initial=is_initial),
    }

    if group_sys_id:
        body["assignment_group"] = group_sys_id

    if is_initial:
        body["state"] = STATE_OPEN
        body["description"] = build_description(payload)
        
        if opened_by_sys_id:
            body["opened_by"] = opened_by_sys_id

        if watcher_sys_ids:
            # GlideList erwartet kommagetrennte Sys-IDs
            body["watch_list"] = ",".join(watcher_sys_ids)
    else:
        body["short_description"] = truncate(case.title, SHORT_DESCRIPTION_MAX)

    body.update(_closing_fields(case.eventType))
    return body