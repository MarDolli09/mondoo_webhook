from typing import Any, Dict, List, Optional, Tuple
from app.models.schemas import AssetRemediation
from app.services.mondoo import MondooGraphQLClient
from app.services.parsers.base import BaseTicketParser


class DefaultParser(BaseTicketParser):
    ticket_type_name = "other"

    def __init__(self, mondoo_client: Optional[MondooGraphQLClient] = None):
        super().__init__(mondoo_client=mondoo_client)

    async def _resolve_assets(self, case_raw: Dict[str, Any], title: str, description: str, *, resolve_names: bool = True) -> List[AssetRemediation]:
        return []

    async def _resolve_cvss_details(self, case_raw: Dict[str, Any], owner_mrn: str, space_id: str) -> Tuple[str, str, Optional[int]]:
        return "", "", None