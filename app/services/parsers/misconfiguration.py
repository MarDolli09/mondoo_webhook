from typing import Any, Dict, Optional, Tuple
from app.services.mondoo_client import MondooGraphQLClient
from app.services.parsers.base import BaseTicketParser


class MisconfigurationParser(BaseTicketParser):
    ticket_type_name = "misconfiguration"

    def __init__(self, mondoo_client: MondooGraphQLClient):
        super().__init__(mondoo_client=mondoo_client)

    async def _resolve_cvss_details(self, case_raw: Dict[str, Any], owner_mrn: str, space_id: str) -> Tuple[str, str,  Optional[int]]:
        # Für Fehlkonfigurationen gibt es keinen CVSS-Score
        return "", "", None