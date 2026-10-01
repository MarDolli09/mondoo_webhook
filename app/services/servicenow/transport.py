"""HTTP-Zugriff auf eine ServiceNow-Instanz: Anmeldung, Retry, Fehlerabbildung.

Fachliche Operationen stehen in den Ressourcenmodulen (``request_items``,
``catalog_tasks``, ``catalog``, ``users``); dieses Modul kennt keine Tabellen.
"""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Optional

import httpx

from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
from app.services.servicenow.auth import ServiceNowAuth
from app.services.servicenow.constants import (
    DEFAULT_MAX_RETRIES,
    PATH_TABLE,
    RETRYABLE_STATUS,
)
from app.services.servicenow.http_session import drop_session_cookies

__all__ = ["Record", "ServiceNowTransport", "poll"]

ERROR_TEXT_LIMIT = 400

# Ein Datensatz, wie ihn die Table API liefert
Record = dict[str, Any]


class ServiceNowTransport:
    """Sendet Requests an eine Instanz und liefert JSON-Objekte oder Fehler.

    Jeder Fehler wird zu ``ServiceNowAPIError`` und damit zu HTTP 502.
    """

    def __init__(self, http_client: httpx.AsyncClient, auth: ServiceNowAuth) -> None:
        self._http_client = http_client
        self._auth = auth

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> dict[str, Any]:
        """Fuehrt einen Request aus, mit Wiederholung bei Netz- und Lastfehlern.

        Raises:
            ServiceNowAPIError: Status ab 400, Antwort ohne JSON-Objekt oder
                Netzwerkfehler auch im letzten Versuch.
        """
        url = f"{self._auth.base_url}{path}"
        for attempt in range(1, max_retries + 1):
            is_last_attempt = attempt == max_retries
            response = await self._send(
                method, url, path, json_body, params, attempt, is_last_attempt
            )
            if response is None:
                continue
            if not is_last_attempt and await self._retried(
                method, path, response, attempt, max_retries
            ):
                continue
            return _decode(method, path, response)

        raise ServiceNowAPIError(
            f"{method} {path} nach {max_retries} Versuchen fehlgeschlagen"
        )

    async def query(
        self, table: str, *, query: str, fields: str, limit: int = 1
    ) -> list[Record]:
        """Datensaetze einer Tabelle zu einer encoded query."""
        result = await self.request(
            "GET",
            PATH_TABLE.format(table=table),
            params={
                "sysparm_query": query,
                "sysparm_fields": fields,
                "sysparm_limit": limit,
                "sysparm_exclude_reference_link": "true",
            },
        )
        records: list[Record] = result.get("result") or []
        return records

    async def _send(
        self,
        method: str,
        url: str,
        path: str,
        json_body: Optional[dict[str, Any]],
        params: Optional[dict[str, Any]],
        attempt: int,
        is_last_attempt: bool,
    ) -> Optional[httpx.Response]:
        """Ein Versuch; ``None`` nach einem Netzwerkfehler, der wiederholt wird."""
        headers = await self._auth.headers()
        drop_session_cookies(self._http_client)
        try:
            return await self._http_client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=headers,
                auth=self._auth.basic_auth(),
            )
        except httpx.HTTPError as exc:
            if is_last_attempt:
                raise ServiceNowAPIError(
                    f"Netzwerkfehler bei {method} {path}: {exc}"
                ) from exc
            await asyncio.sleep(2**attempt)
            return None

    async def _retried(
        self,
        method: str,
        path: str,
        response: httpx.Response,
        attempt: int,
        max_retries: int,
    ) -> bool:
        """True, wenn die Antwort einen weiteren Versuch rechtfertigt.

        Ein abgelaufenes OAuth-Token wird verworfen; bei Last (429, 5xx) wird
        vorher gewartet, so lange wie ``Retry-After`` verlangt.
        """
        if response.status_code == 401 and self._auth.uses_oauth:
            self._auth.invalidate()
            logger.warning("ServiceNow lieferte 401. Token wird erneuert.")
            return True
        if response.status_code in RETRYABLE_STATUS:
            # Shared Instances haben haeufig Rate Limit Rules
            delay = float(response.headers.get("Retry-After") or 2**attempt)
            logger.warning(
                f"ServiceNow HTTP {response.status_code} bei {method} {path}. "
                f"Retry {attempt}/{max_retries - 1} in {delay}s."
            )
            await asyncio.sleep(delay)
            return True
        return False


async def poll(
    delays: Sequence[float], fetch: Callable[[], Awaitable[list[Record]]]
) -> list[Record]:
    """Fragt nach jeder Wartezeit erneut ab, bis Datensaetze vorliegen.

    Fuer Datensaetze, die ein Workflow zeitversetzt anlegt (RITM, SCTASK).
    Liefert eine leere Liste, wenn auch nach der letzten Wartezeit nichts da ist.
    """
    for delay in delays:
        if delay:
            await asyncio.sleep(delay)
        records = await fetch()
        if records:
            return records
    return []


def _decode(method: str, path: str, response: httpx.Response) -> dict[str, Any]:
    """Abgelehnte Antworten werden zu Fehlern, alle anderen zu JSON-Objekten."""
    if response.status_code >= 400:
        logger.error(
            f"ServiceNow lehnte {method} {path} ab. Gesendete Header: "
            f"{_loggable_headers(response.request.headers)}"
        )
        raise ServiceNowAPIError(
            f"HTTP {response.status_code} bei {method} {path}: "
            f"{response.text[:ERROR_TEXT_LIMIT]}",
            upstream_status=response.status_code,
        )
    return _json_object(method, path, response)


def _json_object(method: str, path: str, response: httpx.Response) -> dict[str, Any]:
    """Rumpf einer erfolgreichen Antwort als JSON-Objekt.

    Raises:
        ServiceNowAPIError: Der Rumpf ist kein JSON-Objekt, etwa die HTML-Seite
            einer ruhenden Instanz. Ergibt wie jeder ServiceNow-Fehler 502.
    """
    if not response.content:
        return {}
    try:
        payload = response.json()
    except ValueError as exc:
        message = (
            f"Keine JSON-Antwort bei {method} {path} (HTTP {response.status_code}): "
            f"{response.text[:ERROR_TEXT_LIMIT]}"
        )
        logger.error(message)
        raise ServiceNowAPIError(message, upstream_status=response.status_code) from exc
    if not isinstance(payload, dict):
        message = (
            f"Unerwartete JSON-Struktur bei {method} {path}: "
            f"{type(payload).__name__} statt Objekt"
        )
        logger.error(message)
        raise ServiceNowAPIError(message, upstream_status=response.status_code)
    return payload


def _loggable_headers(headers: httpx.Headers) -> dict[str, str]:
    """Gesendete Header fuer das Log; Anmeldedaten werden ersetzt."""
    return {
        name: ("<gesetzt>" if name.lower() == "authorization" else value)
        for name, value in headers.items()
    }
