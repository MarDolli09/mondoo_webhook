"""Ueberfuehrt Mondoo-Webhook-Ereignisse in normalisierte Cases."""

from collections.abc import Sequence
from typing import Optional

from app.core.logging import logger
from app.domain.case_text import (
    extract_cve,
    extract_risk_from_summary,
    extract_ticket_url,
    sanitize_url,
)
from app.domain.finding_types import classify_finding_type, reported_finding_type
from app.domain.identifiers import (
    case_app_url,
    count_referenced_assets,
    extract_space_id,
    is_automated_identity,
)
from app.domain.ports import FindingScoresLookup
from app.domain.priority import Priority, determine_priority
from app.domain.scores import NO_FINDING_SCORES, FindingScores
from app.models.case import NormalizedCase
from app.models.mondoo import (
    CASE_STATUS_CLOSED,
    FindingRef,
    MondooCase,
    MondooEventType,
    MondooWebhookEvent,
    map_event_type,
)
from app.services.parsing.config import ParsingConfig

__all__ = ["CaseParser"]

LOG_BANNER_WIDTH = 16


class CaseParser:
    """Klassifiziert, reichert an und normalisiert Mondoo-Cases.

    Zustand sind nur die Bewertungsquelle und die Zuordnungstabellen; alle
    uebrigen Schritte sind reine Funktionen dieses Moduls bzw. von ``app.domain``.
    """

    def __init__(
        self, scores_lookup: FindingScoresLookup, config: ParsingConfig
    ) -> None:
        self._scores_lookup = scores_lookup
        self._config = config

    def classify_finding_type(self, event: MondooWebhookEvent) -> str:
        """Finding-Typ anhand der Finding-MRNs, z. B. ``vulnerability``."""
        return classify_finding_type(
            (ref.finding_mrn for ref in event.case.finding_refs),
            self._config.finding_type_patterns,
        )

    async def parse(
        self, event: MondooWebhookEvent, finding_type: str
    ) -> NormalizedCase:
        """Erzeugt den normalisierten Case fuer den erkannten Finding-Typ."""
        case = event.case
        description = event.description
        space_id = extract_space_id(case.owner_mrn)

        event_type = _determine_event_type(event.raw_type, case.status)
        scores = await self._resolve_scores(case, space_id)
        risk_rating, risk_score = _resolve_mondoo_risk(description, scores)
        priority = self._determine_priority(case.title, scores.cvss_rating, risk_rating)
        created_by, is_automated = _creator(case.created_by)

        normalized = NormalizedCase(
            raw_event_type=event.raw_type,
            case_status=case.status,
            event_type=event_type,
            mrn=case.mrn,
            owner_mrn=case.owner_mrn,
            mondoo_space=self._space_name(space_id),
            finding_type=_ticket_finding_type(event, finding_type),
            finding_cve=extract_cve(case.title, self._config.default_cve),
            assets_count=_assets_count(case),
            cvss_score=scores.cvss_score or "",
            cvss_rating=scores.cvss_rating or "",
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

        _log_normalized_case(
            normalized, reported_finding_type(finding_type), description
        )
        return normalized

    async def _resolve_scores(
        self, case: MondooCase, space_id: Optional[str]
    ) -> FindingScores:
        """Bewertung des ersten Findings, zu dem Mondoo Werte liefert.

        Gefragt wird im Scope des Space, nicht je Asset: Die Abfrage liefert
        dann alle betroffenen Assets des Findings auf einmal.
        """
        refs = _unique_finding_refs(case.finding_refs, self._config.max_finding_lookups)
        for ref in refs:
            scores = await self._scores_lookup.fetch_finding_scores(
                finding_mrn=ref.finding_mrn,
                scope_mrn=case.owner_mrn,
                space_id=space_id or "",
            )
            if any(
                (
                    scores.cvss_score,
                    scores.cvss_rating,
                    scores.risk_score,
                    scores.risk_rating,
                )
            ):
                return scores
        return NO_FINDING_SCORES

    def _space_name(self, space_id: Optional[str]) -> str:
        """Anzeigename des Space; unbekannte Spaces erscheinen mit ihrer ID."""
        key = space_id or ""
        return self._config.space_names.get(key, key)

    def _determine_priority(
        self, title: str, cvss_rating: Optional[str], risk_rating: Optional[str]
    ) -> Priority:
        priority = determine_priority(
            title,
            cvss_rating,
            risk_rating,
            self._config.priority_map,
            self._config.default_urgency_impact,
        )
        _log_priority(priority)
        return priority


# ---------------------------------------------------------------------- #
# Ereignis und Ersteller
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


def _creator(raw_created_by: str) -> tuple[str, bool]:
    """Ersteller-MRN ohne Rand und ob das Ticket automatisch entstanden ist."""
    created_by = raw_created_by.strip()
    is_automated = is_automated_identity(created_by)
    if is_automated:
        logger.warning(
            f"Ticket ohne Benutzer-MRN in createdBy ('{created_by}'). "
            f"Moeglicherweise automatisch erzeugtes Regressions-Ticket."
        )
    return created_by, is_automated


# ---------------------------------------------------------------------- #
# Findings
# ---------------------------------------------------------------------- #


def _ticket_finding_type(event: MondooWebhookEvent, finding_type: str) -> str:
    """Typ im Ticket: ``ticketType`` aus dem Payload, sonst der erkannte Typ."""
    if event.ticket_type is not None:
        return event.ticket_type
    return reported_finding_type(finding_type)


def _assets_count(case: MondooCase) -> int:
    """Anzahl laut Mondoo, sonst die Assets aus den Finding-Refs."""
    return case.assets_count or count_referenced_assets(
        ref.scope_mrn for ref in case.finding_refs
    )


def _unique_finding_refs(
    refs: Sequence[FindingRef], max_lookups: int
) -> list[FindingRef]:
    unique: list[FindingRef] = []
    seen: set[str] = set()

    for ref in refs:
        if not ref.finding_mrn or ref.finding_mrn in seen:
            continue
        seen.add(ref.finding_mrn)
        unique.append(ref)
        if len(unique) >= max_lookups:
            break

    if len(refs) > len(unique):
        logger.info(
            f"{len(refs)} Refs auf {len(unique)} eindeutige Findings reduziert."
        )
    return unique


# ---------------------------------------------------------------------- #
# Priorisierung
# ---------------------------------------------------------------------- #


def _resolve_mondoo_risk(
    description: str, scores: FindingScores
) -> tuple[Optional[str], Optional[str]]:
    """Mondoo Risk Rating und Score, bevorzugt aus der Mondoo-API.

    Der Befundtext ist Fliesstext der KI ("The combined risk is **high**
    because ...") und kann vom Wert der API abweichen. Er gilt nur, wenn die
    API keinen Wert liefert.
    """
    if scores.risk_rating or scores.risk_score:
        logger.info(
            f"Mondoo Risk Rating aus der Mondoo-API: "
            f"{scores.risk_rating or '-'} ({scores.risk_score or '-'}/100)"
        )
        return scores.risk_rating, scores.risk_score

    risk_rating, risk_score = extract_risk_from_summary(description)
    if risk_rating:
        logger.warning(
            f"Mondoo-API ohne Risk-Wert, Rating aus dem Befundtext gelesen: "
            f"{risk_rating} ({risk_score or '-'}/100)"
        )
        return risk_rating, risk_score

    if not scores.cvss_rating:
        logger.warning(
            "Weder CVSS-Rating noch Mondoo Risk Rating ermittelbar. "
            "Priorisierung faellt auf Titel-Praefix bzw. Default zurueck."
        )
    return None, None


def _log_priority(priority: Priority) -> None:
    if priority.match.kind == "rating":
        logger.info(
            f"Priority Mapping via Rating ('{priority.match.value}') erfolgreich."
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
        f"Priorisierung ueber '{priority.source.value}' -> "
        f"urgency={priority.urgency}, impact={priority.impact}"
    )


# ---------------------------------------------------------------------- #
# Ausgabe
# ---------------------------------------------------------------------- #


def _ticket_url(description: str, space_id: Optional[str], case_mrn: str) -> str:
    ticket_url = extract_ticket_url(description)
    if not ticket_url and space_id and case_mrn:
        ticket_url = sanitize_url(case_app_url(case_mrn, space_id))
    return ticket_url


def _log_normalized_case(
    normalized: NormalizedCase, reported_type: str, description: str
) -> None:
    rule = "=" * LOG_BANNER_WIDTH
    label = reported_type.upper()
    logger.info(f"{rule} [{label}] BEREINIGTER PAYLOAD {rule}")
    logger.info(normalized.model_dump_json(indent=2))
    logger.info(f"description: {len(description)} Zeichen (im Log ausgelassen)")
    logger.info("=" * 71)
