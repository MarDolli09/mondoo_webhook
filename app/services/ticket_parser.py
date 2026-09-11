from typing import Any, Dict, Optional, Tuple
from app.core.config import settings
from app.models.schemas import ServiceNowPayload
from app.services.mondoo_client import MondooGraphQLClient
from app.services.parsers.advisories import AdvisoriesParser
from app.services.parsers.base import BaseTicketParser
from app.services.parsers.default import DefaultParser
from app.services.parsers.misconfiguration import MisconfigurationParser
from app.services.parsers.vulnerability import VulnerabilityParser


class TicketParserService:
    def __init__(self, mondoo_client: MondooGraphQLClient):
        self.mondoo_client = mondoo_client

    @staticmethod
    def normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        return payload.get("body", payload) if isinstance(payload.get("body"), dict) else payload

    def classify_ticket_type(self, payload: Dict[str, Any]) -> str:
        data = self.normalize_payload(payload)
        case_data = data.get("case", {})
        all_refs = case_data.get("vulnerabilityRefs", []) + case_data.get("queryRefs", [])

        for ref in all_refs:
            finding_mrn = ref.get("findingMrn", "")
            for pattern, mapped_type in settings.FINDING_TYPE_MAP.items():
                if pattern in finding_mrn:
                    return mapped_type

        return "other"

    def _get_parser_strategy(self, ticket_type: str) -> BaseTicketParser:
        if ticket_type == "misconfiguration":
            return MisconfigurationParser(self.mondoo_client)
        elif ticket_type == "vulnerability":
            return VulnerabilityParser(self.mondoo_client)
        elif ticket_type in ["advisories", "end-of-life"]:
            return AdvisoriesParser(self.mondoo_client)
        else:
            return DefaultParser(self.mondoo_client)

    async def process_payload(self, raw_payload: Dict[str, Any], detected_type: str) -> Tuple[ServiceNowPayload, Optional[int]]:
        parser_strategy = self._get_parser_strategy(detected_type)
        return await parser_strategy.parse(raw_payload)