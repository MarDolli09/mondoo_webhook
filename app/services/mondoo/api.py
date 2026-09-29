"""GraphQL-Transport zur Mondoo-API (EU-Endpunkt)."""

from typing import Any, NamedTuple

import httpx

from app.core.exceptions import MondooAPIError, MondooGraphQLError
from app.services.mondoo.queries import GET_FINDING_SCORES_QUERY

__all__ = ["FindingNodes", "MondooGraphQLAPI"]

ENDPOINT = "https://eu.api.mondoo.com/query"
ERROR_TEXT_LIMIT = 400
# GraphQL-Meldungen werden vollstaendig protokolliert, nur als Schutz begrenzt
ERROR_MESSAGES_LIMIT = 2000


class FindingNodes(NamedTuple):
    """Antwort der Findings-Abfrage: ein Knoten je betroffenem Asset."""

    nodes: list[dict[str, Any]]
    total_count: int


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
            # Ungueltige Abfragen beantwortet Mondoo mit 422 und errors-Array.
            raise MondooAPIError(
                f"HTTP {response.status_code}: {_describe_errors(response)}"
            )

        body = response.json()
        if body.get("errors"):
            raise MondooGraphQLError(_error_messages(body["errors"]))

        data: dict[str, Any] = body.get("data") or {}
        return data

    async def fetch_finding_nodes(
        self, scope_mrn: str, finding_mrn: str, limit: int
    ) -> FindingNodes:
        """Laedt ein Finding des Scope; ein Knoten je betroffenem Asset."""
        data = await self.execute(
            GET_FINDING_SCORES_QUERY,
            {"scopeMrn": scope_mrn, "findingMrn": finding_mrn, "first": limit},
        )
        findings = data.get("findings") or {}

        if "message" in findings:
            raise MondooGraphQLError(f"Findings-Union: {findings['message']}")

        nodes = [
            node
            for edge in findings.get("edges") or []
            if (node := (edge or {}).get("node"))
        ]
        return FindingNodes(nodes, int(findings.get("totalCount") or len(nodes)))


def _describe_errors(response: httpx.Response) -> str:
    """GraphQL-Meldungen der Antwort, ersatzweise der Anfang des Rumpfs."""
    try:
        errors = response.json().get("errors")
    except (ValueError, AttributeError):
        errors = None
    if errors:
        return _error_messages(errors)
    return response.text[:ERROR_TEXT_LIMIT]


def _error_messages(errors: Any) -> str:
    """Jede Meldung des errors-Arrays einmal, ohne Positionen und Codes."""
    if not isinstance(errors, list):
        return str(errors)[:ERROR_MESSAGES_LIMIT]
    messages = dict.fromkeys(
        str(error.get("message", error)) if isinstance(error, dict) else str(error)
        for error in errors
    )
    return " | ".join(messages)[:ERROR_MESSAGES_LIMIT]
