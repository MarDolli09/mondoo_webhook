from typing import Any, Dict, List, Optional, Tuple
 
import httpx
 
from app.core.exceptions import MondooAPIError, MondooGraphQLError
from app.core.logging import logger
 
from .queries import GET_ASSET_QUERY, GET_FINDINGS_PAGINATED_QUERY
 
ENDPOINT_EU = "https://eu.api.mondoo.com/query"
 
FINDINGS_PAGE_SIZE = 100
 
 
def is_eu_scope(space_id: str = "", finding_mrn: str = "", scope_mrn: str = "") -> bool:

    return (
        space_id.startswith("eu-")
        or "eu-" in finding_mrn
        or "eu.api.mondoo" in finding_mrn
        or "eu-" in scope_mrn
    )
 
 
class MondooGraphQLAPI:
    def __init__(self, http_client: httpx.AsyncClient, api_key: str):
        self.http_client = http_client
        self.api_key = api_key
 
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
 
    @staticmethod
    def endpoint(is_eu: bool) -> str:
        return ENDPOINT_EU 
 
    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
 
    # ------------------------------------------------------------------ #
    # Transport
    # ------------------------------------------------------------------ #
 
    async def execute(
        self, query: str, variables: Dict[str, Any], *, is_eu: bool
    ) -> Dict[str, Any]:
        """Fuehrt eine Abfrage aus und gibt den data-Block zurueck."""
        try:
            response = await self.http_client.post(
                self.endpoint(is_eu),
                json={"query": query, "variables": variables},
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise MondooAPIError(f"Verbindungsfehler: {exc}")
 
        if response.status_code != 200:
            raise MondooAPIError(
                f"HTTP {response.status_code}: {response.text[:400]}"
            )
 
        body = response.json()
        if body.get("errors"):
            raise MondooGraphQLError(str(body["errors"])[:400])
 
        return body.get("data") or {}
 
    # ------------------------------------------------------------------ #
    # Abfragen
    # ------------------------------------------------------------------ #
 
    async def fetch_asset_name(self, scope_mrn: str, *, is_eu: bool) -> Optional[str]:
        data = await self.execute(
            GET_ASSET_QUERY, {"mrn": scope_mrn}, is_eu=is_eu
        )
        asset = data.get("asset") or {}
        return asset.get("name")
 
    async def fetch_findings_page(
        self, scope_mrn: str, cursor: Optional[str], *, is_eu: bool
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        data = await self.execute(
            GET_FINDINGS_PAGINATED_QUERY,
            {"scopeMrn": scope_mrn, "cursor": cursor},
            is_eu=is_eu,
        )
        findings = data.get("findings") or {}
 
        if "message" in findings:
            raise MondooGraphQLError(f"Findings-Union: {findings['message']}")
 
        return findings.get("edges") or [], findings.get("pageInfo") or {}
 
 
def scope_mrn_for_space(space_id: str) -> str:
    return f"//captain.api.mondoo.app/spaces/{space_id}"