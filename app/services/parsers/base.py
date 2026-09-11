from abc import ABC
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.logging import logger
from app.domain.priority import resolve_priority_mapping
from app.models.schemas import AssetRemediation, RemediationTable, ServiceNowCase, ServiceNowPayload
from app.services.mondoo_client import MondooGraphQLClient
from app.utils import text_cleaner


class BaseTicketParser(ABC):
    ticket_type_name: str = "other"

    def __init__(self, mondoo_client: Optional[MondooGraphQLClient] = None):
        self.client = mondoo_client

    def _resolve_urgency_and_impact(self, title: str, cvss_risk_rating: Optional[str] = None) -> Tuple[str, str]:
        return resolve_priority_mapping(
            title=title,
            cvss_risk_rating=cvss_risk_rating,
            priority_map=settings.PRIORITY_MAP,
            default_urgency_impact=settings.DEFAULT_URGENCY_IMPACT
        )

    async def _resolve_cvss_details(self, case_raw: Dict[str, Any], owner_mrn: str, space_id: str) -> Tuple[str, str, Optional[int]]:
        if not self.client:
            return "", "", None

        all_refs = case_raw.get("vulnerabilityRefs", []) + case_raw.get("queryRefs", [])
        for ref in all_refs:
            finding_mrn = ref.get("findingMrn", "")
            scope_mrn = ref.get("scopeMrn") or owner_mrn
            if finding_mrn:
                score, rating, page_count = await self.client.fetch_cvss_details(
                    finding_mrn=finding_mrn,
                    scope_mrn=scope_mrn,
                    space_id=space_id
                )
                if score or rating:
                    return score or "", rating or "", page_count
        return "", "", None

    async def _resolve_assets(self, case_raw: Dict[str, Any], title: str, description: str) -> List[AssetRemediation]:
        table_assets = text_cleaner.extract_asset_table_from_markdown(description)
        if table_assets:
            return [AssetRemediation(**asset) for asset in table_assets]

        assets: List[AssetRemediation] = []
        seen = set()
        all_refs = case_raw.get("vulnerabilityRefs", []) + case_raw.get("queryRefs", [])

        single_name_from_title = (
            text_cleaner.extract_single_asset_from_title(title)
            if len(all_refs) == 1
            else None
        )

        for ref in all_refs:
            scope_mrn = ref.get("scopeMrn", "")
            match = text_cleaner.SCOPE_MRN_PATTERN.search(scope_mrn)
            if not match:
                continue

            space_id, asset_id = match.group(1), match.group(2)
            if asset_id in seen:
                continue

            seen.add(asset_id)
            asset_url = f"https://app.mondoo.com/space/inventory/{asset_id}?region=EU&spaceId={space_id}"
            default_platform = settings.CATEGORY_MAP.get(space_id, "-- unknown --")

            if single_name_from_title:
                asset_name = single_name_from_title
            elif self.client:
                fetched_name = await self.client.fetch_asset_name(space_id, asset_id, scope_mrn)
                asset_name = fetched_name if fetched_name else asset_id
            else:
                asset_name = asset_id

            assets.append(
                AssetRemediation(
                    asset_name_name=asset_name,
                    asset_name_url=asset_url,
                    platform=default_platform,
                )
            )

        return assets

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

        urgency, impact = self._resolve_urgency_and_impact(title, cvss_risk_rating)

        cleaned_payload = ServiceNowPayload(
            case=ServiceNowCase(
                ticketState=data.get("type", ""),
                mrn=case_raw.get("mrn", ""),
                ownerMrn=owner_mrn,
                mondooSpace=settings.CATEGORY_MAP.get(space_id, space_id or ""),
                ticketType=data.get("ticketType", self.ticket_type_name),
                findingCVE=text_cleaner.extract_cve(title, settings.DEFAULT_CVE),
                cvssScore=cvss_score,
                cvssRiskRating=cvss_risk_rating,
                urgency=urgency,
                impact=impact,
                title=title,
                ticket_url=text_cleaner.extract_ticket_url(description),
                createdAt=case_raw.get("createdAt", ""),
                updatedAt=case_raw.get("updatedAt", ""),
                assetsCount=case_raw.get("assetsCount", 0),
                remediations=RemediationTable(table=assets),
            )
        )

        logger.info(f"================ [{self.ticket_type_name.upper()}] BEREINIGTER PAYLOAD ================")
        logger.info(cleaned_payload.model_dump_json(indent=2))
        logger.info("=======================================================================")

        return cleaned_payload, cvss_found_on_page