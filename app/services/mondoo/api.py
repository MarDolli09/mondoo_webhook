"""GraphQL-Transport zur Mondoo-API (EU-Endpunkt)."""

from typing import Any, NamedTuple, Optional

import httpx

from app.core.exceptions import MondooAPIError, MondooGraphQLError
from app.services.mondoo.queries import GET_FINDINGS_PAGINATED_QUERY

__all__ = ["FindingsPage", "MondooGraphQLAPI"]

ENDPOINT = "https://eu.api.mondoo.com/query"
ERROR_TEXT_LIMIT = 400


class FindingsPage(NamedTuple):
    """Eine Seite der Findings-Suche."""

    edges: list[dict[str, Any]]
    page_info: dict[str, Any]


class MondooGraphQLAPI:
    """Fuehrt GraphQL-Abfragen mit API-Key gegen Mondoo aus."""

    def __init__(self, http_client: httpx.AsyncClient, api_key: str) -> None:
        self._http_client = http_client
        self._api_key = api_key

    @property
    def is_configured(self) -> bool:
        """True, wenn ein API-Key vorliegt."""
        return bool(self._api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }

    async def execute(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Fuehrt eine Abfrage aus und gibt den ``data``-Block zurueck.

        Raises:
            MondooAPIError: Netzwerkfehler oder HTTP-Status ungleich 200.
            MondooGraphQLError: Die Antwort enthaelt ``errors``.
        """
        try:
            response = await self._http_client.post(
                ENDPOINT,
                json={"query": query, "variables": variables},
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise MondooAPIError(f"Verbindungsfehler: {exc}") from exc

        if response.status_code != 200:
            raise MondooAPIError(
                f"HTTP {response.status_code}: {response.text[:ERROR_TEXT_LIMIT]}"
            )

        body = response.json()
        if body.get("errors"):
            raise MondooGraphQLError(str(body["errors"])[:ERROR_TEXT_LIMIT])

        data: dict[str, Any] = body.get("data") or {}
        return data

    async def fetch_findings_page(
        self, scope_mrn: str, cursor: Optional[str]
    ) -> FindingsPage:
        """Laedt eine Seite der Findings eines Scope ab ``cursor``."""
        data = await self.execute(
            GET_FINDINGS_PAGINATED_QUERY, {"scopeMrn": scope_mrn, "cursor": cursor}
        )
        findings = data.get("findings") or {}

        if "message" in findings:
            raise MondooGraphQLError(f"Findings-Union: {findings['message']}")

        return FindingsPage(findings.get("edges") or [], findings.get("pageInfo") or {})
