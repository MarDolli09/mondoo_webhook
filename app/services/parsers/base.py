import asyncio
from abc import ABC
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.logging import logger
from app.domain.priority import resolve_priority_mapping
from app.models.schemas import (
    AssetRemediation,
    RemediationTable,
    ServiceNowCase,
    ServiceNowPayload,
    map_event_type,
)
from app.services.mondoo import MondooGraphQLClient
from app.utils import text_cleaner


class BaseTicketParser(ABC):
    ticket_type_name: str = "other"

    def __init__(self, mondoo_client: Optional[MondooGraphQLClient] = None):
        self.client = mondoo_client

    # ------------------------------------------------------------------ #
    # Priorisierung
    # ------------------------------------------------------------------ #

    def _resolve_urgency_and_impact(
        self,
        title: str,
        cvss_risk_rating: Optional[str] = None,
        mondoo_risk_rating: Optional[str] = None,
    ) -> Tuple[str, str, str]:
        """
        Ermittelt Urgency/Impact und die Herkunft der Entscheidung.

        Reihenfolge: CVSS-Rating (Vulnerabilities/Advisories), dann Mondoo Risk
        Rating (Fehlkonfigurationen), dann Titel-Praefix, dann Default.
        """
        effective_rating = cvss_risk_rating or mondoo_risk_rating

        if cvss_risk_rating:
            source = "cvss"
        elif mondoo_risk_rating:
            source = "mondoo_risk"
        else:
            source = "title_or_default"

        urgency, impact = resolve_priority_mapping(
            title=title,
            cvss_risk_rating=effective_rating,
            priority_map=settings.PRIORITY_MAP,
            default_urgency_impact=settings.DEFAULT_URGENCY_IMPACT,
        )

        if source == "title_or_default":
            source = (
                "title"
                if (urgency, impact) != settings.DEFAULT_URGENCY_IMPACT
                else "default"
            )

        return urgency, impact, source

    # ------------------------------------------------------------------ #
    # CVSS
    # ------------------------------------------------------------------ #

    @staticmethod
    def _unique_finding_refs(case_raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Ein Case ist bei Mondoo ein Flotten-Rollup: derselbe Befund auf n Assets.
        Alle Refs tragen dann dieselbe findingMrn bei unterschiedlicher scopeMrn.
        Ohne Deduplizierung wuerde bei 97 Assets 97-mal derselbe Befund gesucht,
        jeweils mit bis zu MONDOO_GRAPHQL_MAX_PAGES Seiten Paginierung.
        """
        all_refs = case_raw.get("vulnerabilityRefs", []) + case_raw.get("queryRefs", [])
        unique: List[Dict[str, Any]] = []
        seen = set()

        for ref in all_refs:
            finding_mrn = ref.get("findingMrn", "")
            if not finding_mrn or finding_mrn in seen:
                continue
            seen.add(finding_mrn)
            unique.append(ref)
            if len(unique) >= settings.CVSS_MAX_FINDING_ATTEMPTS:
                break

        if len(all_refs) > len(unique):
            logger.info(
                f"{len(all_refs)} Refs auf {len(unique)} eindeutige Findings reduziert."
            )
        return unique

    async def _resolve_cvss_details(
        self, case_raw: Dict[str, Any], owner_mrn: str, space_id: str
    ) -> Tuple[str, str, Optional[int]]:
        if not self.client:
            return "", "", None

        for ref in self._unique_finding_refs(case_raw):
            finding_mrn = ref.get("findingMrn", "")
            scope_mrn = ref.get("scopeMrn") or owner_mrn
            score, rating, page_count = await self.client.fetch_cvss_details(
                finding_mrn=finding_mrn,
                scope_mrn=scope_mrn,
                space_id=space_id,
            )
            if score or rating:
                return score or "", rating or "", page_count
        return "", "", None

    # ------------------------------------------------------------------ #
    # Assets
    # ------------------------------------------------------------------ #

    async def _fetch_asset_names(
        self, targets: List[Tuple[str, str, str]]
    ) -> Dict[str, str]:
        if not self.client or not targets:
            return {}

        if len(targets) > settings.ASSET_NAME_LOOKUP_LIMIT:
            logger.warning(
                f"{len(targets)} Assets uebersteigen das Lookup-Limit von "
                f"{settings.ASSET_NAME_LOOKUP_LIMIT}. Namensaufloesung wird "
                f"uebersprungen, es werden Asset-IDs verwendet."
            )
            return {}

        semaphore = asyncio.Semaphore(settings.ASSET_NAME_LOOKUP_CONCURRENCY)

        async def fetch_one(space_id: str, asset_id: str, scope_mrn: str):
            async with semaphore:
                try:
                    name = await self.client.fetch_asset_name(space_id, asset_id, scope_mrn)
                    return asset_id, name
                except Exception as exc:
                    logger.warning(f"Namensaufloesung fuer {asset_id} fehlgeschlagen: {exc}")
                    return asset_id, None

        results = await asyncio.gather(*(fetch_one(*t) for t in targets))
        resolved = {asset_id: name for asset_id, name in results if name}

        logger.info(f"{len(resolved)} von {len(targets)} Asset-Namen aufgeloest.")
        return resolved

    async def _resolve_assets(
        self, case_raw: Dict[str, Any], title: str, description: str
    ) -> List[AssetRemediation]:
        table_assets = text_cleaner.extract_asset_table_from_markdown(description)
        if table_assets:
            return [AssetRemediation(**asset) for asset in table_assets]

        all_refs = case_raw.get("vulnerabilityRefs", []) + case_raw.get("queryRefs", [])

        single_name_from_title = (
            text_cleaner.extract_single_asset_from_title(title)
            if len(all_refs) == 1
            else None
        )

        # Schritt 1: eindeutige Assets aus den Refs sammeln
        targets: List[Tuple[str, str, str]] = []
        seen = set()
        for ref in all_refs:
            scope_mrn = ref.get("scopeMrn", "")
            match = text_cleaner.SCOPE_MRN_PATTERN.search(scope_mrn)
            if not match:
                continue
            space_id, asset_id = match.group(1), match.group(2)
            if asset_id in seen:
                continue
            seen.add(asset_id)
            targets.append((space_id, asset_id, scope_mrn))

        # Schritt 2: Namen nebenlaeufig nachladen (entfaellt bei Titel-Treffer)
        name_map: Dict[str, str] = {}
        if not single_name_from_title:
            name_map = await self._fetch_asset_names(targets)

        # Schritt 3: Ergebnisliste bauen
        assets: List[AssetRemediation] = []
        for space_id, asset_id, _scope_mrn in targets:
            asset_url = (
                f"https://app.mondoo.com/space/inventory/{asset_id}"
                f"?region=EU&spaceId={space_id}"
            )
            assets.append(
                AssetRemediation(
                    asset_name_name=single_name_from_title
                    or name_map.get(asset_id)
                    or asset_id,
                    asset_name_url=asset_url,
                    platform=settings.CATEGORY_MAP.get(space_id, "-- unknown --"),
                )
            )

        return assets

    # ------------------------------------------------------------------ #
    # Herkunft
    # ------------------------------------------------------------------ #

    @staticmethod
    def _resolve_origin(case_raw: Dict[str, Any]) -> Tuple[str, bool]:
        created_by = case_raw.get("createdBy") or ""
        is_automated = "/users/" not in created_by
        return created_by, is_automated

    # ------------------------------------------------------------------ #
    # Einstiegspunkt
    # ------------------------------------------------------------------ #

    async def parse(self, raw_payload: Dict[str, Any]) -> Tuple[ServiceNowPayload, Optional[int]]:
        data = raw_payload.get("body", raw_payload) if isinstance(raw_payload.get("body"), dict) else raw_payload
        case_raw = data.get("case", {})
        description = data.get("content", {}).get("description", "")
        title = case_raw.get("title", "")
        owner_mrn = case_raw.get("ownerMrn", "")
        space_id = text_cleaner.extract_space_id(owner_mrn)

        assets = await self._resolve_assets(case_raw, title, description)

        cvss_score, cvss_risk_rating, cvss_found_on_page = await self._resolve_cvss_details(
            case_raw, owner_mrn=owner_mrn, space_id=space_id or ""
        )

        # Fallback fuer Befunde ohne CVSS (insbesondere Fehlkonfigurationen):
        # Mondoos Risk Rating steht im gerenderten Befundtext.
        risk_rating, risk_score = text_cleaner.extract_risk_from_summary(description)
        if risk_rating:
            logger.info(f"Mondoo Risk Rating aus Befundtext gelesen: {risk_rating} ({risk_score or '-'}/100)")
        elif not cvss_risk_rating:
            logger.warning(
                "Weder CVSS-Rating noch Mondoo Risk Rating ermittelbar. "
                "Priorisierung faellt auf Titel-Praefix bzw. Default zurueck."
            )

        urgency, impact, priority_source = self._resolve_urgency_and_impact(
            title, cvss_risk_rating, risk_rating
        )
        logger.info(f"Priorisierung ueber '{priority_source}' -> urgency={urgency}, impact={impact}")

        raw_event_type = data.get("type", "")
        created_by, is_automated = self._resolve_origin(case_raw)
        policies = (case_raw.get("tags") or {}).get("policies", "")

        if is_automated:
            logger.warning(
                f"Ticket ohne Benutzer-MRN in createdBy ('{created_by}'). "
                f"Moeglicherweise automatisch erzeugtes Regressions-Ticket."
            )

        cleaned_payload = ServiceNowPayload(
            case=ServiceNowCase(
                ticketState=raw_event_type,
                eventType=map_event_type(raw_event_type),
                mrn=case_raw.get("mrn", ""),
                ownerMrn=owner_mrn,
                mondooSpace=settings.CATEGORY_MAP.get(space_id, space_id or ""),
                ticketType=data.get("ticketType", self.ticket_type_name),
                findingCVE=text_cleaner.extract_cve(title, settings.DEFAULT_CVE),
                cvssScore=cvss_score,
                cvssRiskRating=cvss_risk_rating,
                riskRating=risk_rating or "",
                riskScore=risk_score or "",
                prioritySource=priority_source,
                urgency=urgency,
                impact=impact,
                title=title,
                ticket_url=text_cleaner.extract_ticket_url(description),
                createdAt=case_raw.get("createdAt", ""),
                updatedAt=case_raw.get("updatedAt", ""),
                assetsCount=case_raw.get("assetsCount", 0),
                description=description,
                createdBy=created_by,
                isAutomated=is_automated,
                policies=policies,
                remediations=RemediationTable(table=assets),
            )
        )

        logger.info(f"================ [{self.ticket_type_name.upper()}] BEREINIGTER PAYLOAD ================")
        # description ist mehrere Tausend Zeichen lang und wuerde das Log fluten.
        logger.info(cleaned_payload.model_dump_json(indent=2, exclude={"case": {"description"}}))
        logger.info(f"description: {len(description)} Zeichen (im Log ausgelassen)")
        logger.info("=======================================================================")

        return cleaned_payload, cvss_found_on_page