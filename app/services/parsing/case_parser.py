"""Ueberfuehrt Mondoo-Webhook-Ereignisse in normalisierte Cases."""

from collections.abc import Sequence
from typing import Optional

from app.core.config import settings
from app.core.logging import logger
from app.core.master_data import master_data
from app.domain.case_text import (
    extract_cve,
    extract_risk_from_summary,
    extract_ticket_url,
    sanitize_url,
)
from app.domain.cvss import NO_CVSS_DETAILS, CvssDetails
from app.domain.finding_types import (
    FindingTypeProfile,
    classify_finding_type,
    profile_for,
)
from app.domain.identifiers import (
    case_app_url,
    count_referenced_assets,
    extract_space_id,
    is_automated_identity,
)
from app.domain.ports import CvssLookup
from app.domain.priority import Priority, determine_priority
from app.models.case import NormalizedCase
from app.models.mondoo import (
    CASE_STATUS_CLOSED,
    FindingRef,
    MondooCase,
    MondooEventType,
    MondooWebhookEvent,
    map_event_type,
)

__all__ = ["CaseParser"]

LOG_BANNER_WIDTH = 16


class CaseParser:
    """Klassifiziert, reichert an und normalisiert Mondoo-Cases.

    Einziger Zustand ist die CVSS-Quelle; alle uebrigen Schritte sind reine
    Funktionen dieses Moduls bzw. von ``app.domain``.
    """

    def __init__(self, cvss_lookup: CvssLookup) -> None:
        self._cvss_lookup = cvss_lookup

    @staticmethod
    def classify_finding_type(event: MondooWebhookEvent) -> str:
        """Finding-Typ anhand der Finding-MRNs, z. B. ``vulnerability``."""
        return classify_finding_type(
            (ref.finding_mrn for ref in event.case.finding_refs),
            master_data.FINDING_TYPE_MAP,
        )

    async def parse(
        self, event: MondooWebhookEvent, finding_type: str
    ) -> NormalizedCase:
        """Erzeugt den normalisierten Case fuer den erkannten Finding-Typ."""
        profile = profile_for(finding_type)
        case = event.case
        description = event.description
        space_id = extract_space_id(case.owner_mrn)

        event_type = _determine_event_type(event.raw_type, case.status)
        cvss = await self._resolve_cvss(case, space_id, profile)
        risk_rating, risk_score = _read_mondoo_risk(description, cvss.rating)
        priority = _determine_priority(case.title, cvss.rating, risk_rating)

        assets_count = case.assets_count or count_referenced_assets(
            ref.scope_mrn for ref in case.finding_refs
        )
        created_by = case.created_by.strip()
        is_automated = is_automated_identity(created_by)
        if is_automated:
            logger.warning(
                f"Ticket ohne Benutzer-MRN in createdBy ('{created_by}'). "
                f"Moeglicherweise automatisch erzeugtes Regressions-Ticket."
            )

        normalized = NormalizedCase(
            raw_event_type=event.raw_type,
            case_status=case.status,
            event_type=event_type,
            mrn=case.mrn,
            owner_mrn=case.owner_mrn,
            mondoo_space=master_data.CATEGORY_MAP.get(space_id or "", space_id or ""),
            finding_type=(
                event.ticket_type
                if event.ticket_type is not None
                else profile.servicenow_type
            ),
            finding_cve=extract_cve(case.title, master_data.DEFAULT_CVE),
            assets_count=assets_count,
            cvss_score=cvss.score or "",
            cvss_rating=cvss.rating or "",
            cvss_found_on_page=cvss.found_on_page,
            risk_rating=risk_rating or "",
            risk_score=risk_score or "",
            priority_source=priority.source,
            urgency=priority.urgency,
            impact=priority.impact,
            title=case.title,
            ticket_url=_ticket_url(description, space_id, case.mrn),
            created_at=case.created_at or "",
            updated_at=case.updated_at,
            created_by=created_by,
            is_automated=is_automated,
            policies=case.tags.policies,
        )

        _log_normalized_case(normalized, profile, description)
        return normalized

    async def _resolve_cvss(
        self,
        case: MondooCase,
        space_id: Optional[str],
        profile: FindingTypeProfile,
    ) -> CvssDetails:
        if not profile.resolves_cvss:
            return NO_CVSS_DETAILS

        for ref in _unique_finding_refs(case.finding_refs):
            details = await self._cvss_lookup.fetch_cvss_details(
                finding_mrn=ref.finding_mrn,
                scope_mrn=ref.scope_mrn or case.owner_mrn,
                space_id=space_id or "",
            )
            if details.score or details.rating:
                return details
        return NO_CVSS_DETAILS


# ---------------------------------------------------------------------- #
# Ereignis
# ---------------------------------------------------------------------- #


def _determine_event_type(raw_type: str, case_status: str) -> MondooEventType:
    event_type = map_event_type(raw_type)
    if event_type is MondooEventType.UNKNOWN and case_status == CASE_STATUS_CLOSED:
        logger.warning(
            f"Unbekannter Ereignistyp '{raw_type}', Case-Status ist "
            f"'{case_status}'. Wird als Abschluss behandelt."
        )
        event_type = MondooEventType.CLOSED
    return event_type


# ---------------------------------------------------------------------- #
# CVSS
# ---------------------------------------------------------------------- #


def _unique_finding_refs(refs: Sequence[FindingRef]) -> list[FindingRef]:
    unique: list[FindingRef] = []
    seen: set[str] = set()

    for ref in refs:
        if not ref.finding_mrn or ref.finding_mrn in seen:
            continue
        seen.add(ref.finding_mrn)
        unique.append(ref)
        if len(unique) >= settings.CVSS_MAX_FINDING_ATTEMPTS:
            break

    if len(refs) > len(unique):
        logger.info(
            f"{len(refs)} Refs auf {len(unique)} eindeutige Findings reduziert."
        )
    return unique


# ---------------------------------------------------------------------- #
# Priorisierung
# ---------------------------------------------------------------------- #


def _read_mondoo_risk(
    description: str, cvss_rating: Optional[str]
) -> tuple[Optional[str], Optional[str]]:
    risk_rating, risk_score = extract_risk_from_summary(description)
    if risk_rating:
        logger.info(
            f"Mondoo Risk Rating aus Befundtext gelesen: "
            f"{risk_rating} ({risk_score or '-'}/100)"
        )
    elif not cvss_rating:
        logger.warning(
            "Weder CVSS-Rating noch Mondoo Risk Rating ermittelbar. "
            "Priorisierung faellt auf Titel-Praefix bzw. Default zurueck."
        )
    return risk_rating, risk_score


def _determine_priority(
    title: str, cvss_rating: Optional[str], risk_rating: Optional[str]
) -> Priority:
    priority = determine_priority(
        title,
        cvss_rating,
        risk_rating,
        master_data.PRIORITY_MAP,
        master_data.DEFAULT_URGENCY_IMPACT,
    )

    if priority.match.kind == "rating":
        logger.info(
            f"Priority Mapping via GraphQL Rating ('{priority.match.value}') "
            f"erfolgreich."
        )
    elif priority.match.kind == "title":
        logger.info(
            f"Priority Mapping via Titel-Fallback ('{priority.match.value}') "
            f"erfolgreich."
        )
    else:
        logger.warning(
            "Kein passendes Priority Mapping gefunden. Verwende Default-Werte."
        )

    logger.info(
        f"Priorisierung ueber '{priority.source}' -> "
        f"urgency={priority.urgency}, impact={priority.impact}"
    )
    return priority


# ---------------------------------------------------------------------- #
# Ausgabe
# ---------------------------------------------------------------------- #


def _ticket_url(description: str, space_id: Optional[str], case_mrn: str) -> str:
    ticket_url = extract_ticket_url(description)
    if not ticket_url and space_id and case_mrn:
        ticket_url = sanitize_url(case_app_url(case_mrn, space_id))
    return ticket_url


def _log_normalized_case(
    normalized: NormalizedCase, profile: FindingTypeProfile, description: str
) -> None:
    rule = "=" * LOG_BANNER_WIDTH
    label = profile.servicenow_type.upper()
    logger.info(f"{rule} [{label}] BEREINIGTER PAYLOAD {rule}")
    logger.info(normalized.model_dump_json(indent=2))
    logger.info(f"description: {len(description)} Zeichen (im Log ausgelassen)")
    logger.info("=" * 71)
