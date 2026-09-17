"""REST-Zugriffe auf ServiceNow: Tabellen, Service Catalog und Referenzen."""

import asyncio
from typing import Any, Optional

import httpx

from app.core.config import settings
from app.core.exceptions import (
    CatalogOrderError,
    RequestItemNotFoundError,
    ServiceNowAPIError,
)
from app.core.logging import logger
from app.services.servicenow.auth import ServiceNowAuth
from app.services.servicenow.cache import ReferenceCache
from app.services.servicenow.constants import (
    DEFAULT_MAX_RETRIES,
    PATH_ORDER_NOW,
    PATH_SUBMIT_ORDER,
    PATH_TABLE,
    PATH_TABLE_RECORD,
    RETRYABLE_STATUS,
    RITM_RESOLVE_DELAYS,
    TABLE_REQUEST_ITEM,
    TABLE_USER,
)

__all__ = ["ServiceNowAPI"]

ERROR_TEXT_LIMIT = 400


class ServiceNowAPI:
    """Fachlich benannte REST-Operationen mit Retry, Token-Erneuerung und Cache."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        auth: ServiceNowAuth,
        reference_cache: ReferenceCache,
    ) -> None:
        self._http_client = http_client
        self._auth = auth
        self._reference_cache = reference_cache

    # ------------------------------------------------------------------ #
    # Requested Items
    # ------------------------------------------------------------------ #

    async def find_request_item_by_correlation_id(
        self, correlation_id: str
    ) -> Optional[dict[str, Any]]:
        """Neuestes RITM mit dieser correlation_id; warnt bei Duplikaten."""
        records = await self._query_table(
            TABLE_REQUEST_ITEM,
            query=f"correlation_id={correlation_id}^ORDERBYDESCsys_created_on",
            fields="sys_id,number,state,stage,request",
            limit=2,
        )
        if len(records) > 1:
            numbers = [r.get("number", "ohne Nummer") for r in records]
            logger.warning(
                f"Mehrere RITMs ({', '.join(numbers)}) zu correlation_id "
                f"'{correlation_id}' gefunden! Moegliches Duplikat. Verwende das "
                f"neueste Ticket ({records[0].get('number')})."
            )
        return records[0] if records else None

    async def resolve_request_item(self, request_sys_id: str) -> dict[str, Any]:
        """RITM zu einem Request; wartet, bis die Workflow-Engine es erzeugt hat.

        Raises:
            RequestItemNotFoundError: Auch nach allen Wartezeiten kein RITM.
        """
        for delay in RITM_RESOLVE_DELAYS:
            if delay:
                await asyncio.sleep(delay)
            records = await self._query_table(
                TABLE_REQUEST_ITEM,
                query=f"request={request_sys_id}",
                fields="sys_id,number",
            )
            if records:
                return records[0]

        raise RequestItemNotFoundError(
            f"Kein RITM zu Request {request_sys_id} gefunden."
        )

    async def patch_request_item(
        self, ritm_sys_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Aktualisiert Felder eines RITM und liefert Nummer, Status und Stage."""
        result = await self._request(
            "PATCH",
            PATH_TABLE_RECORD.format(table=TABLE_REQUEST_ITEM, sys_id=ritm_sys_id),
            json_body=body,
            params={
                "sysparm_fields": "sys_id,number,state,stage",
                "sysparm_exclude_reference_link": "true",
            },
        )
        record: dict[str, Any] = result.get("result") or {}
        return record

    # ------------------------------------------------------------------ #
    # Service Catalog
    # ------------------------------------------------------------------ #

    async def order_catalog_item(
        self, variables: dict[str, str], requested_for_sys_id: Optional[str]
    ) -> str:
        """Bestellt das Katalogformular und gibt die sys_id des REQ zurueck."""
        body: dict[str, Any] = {"sysparm_quantity": "1", "variables": variables}
        if requested_for_sys_id:
            body["sysparm_requested_for"] = requested_for_sys_id

        response = await self._request(
            "POST",
            PATH_ORDER_NOW.format(item_sys_id=settings.SNOW_CATALOG_ITEM_SYS_ID),
            json_body=body,
        )
        result = response.get("result") or {}

        # Bei aktiviertem Two-Step-Checkout verhaelt sich order_now wie
        # "in den Warenkorb legen" und liefert nur eine cart_id.
        if result.get("cart_id") and not result.get("request_id"):
            logger.info("Two-Step-Checkout erkannt. Sende submit_order nach.")
            response = await self._request("POST", PATH_SUBMIT_ORDER, json_body={})
            result = response.get("result") or {}

        request_sys_id = result.get("request_id") or result.get("sys_id")
        if not request_sys_id:
            raise CatalogOrderError(f"order_now lieferte keine Request-ID: {result}")

        logger.info(
            f"Service Catalog Request "
            f"{result.get('request_number') or request_sys_id} erzeugt."
        )
        return str(request_sys_id)

    # ------------------------------------------------------------------ #
    # Referenzen
    # ------------------------------------------------------------------ #

    async def resolve_user_sys_id(self, identifier: str) -> Optional[str]:
        """sys_id eines aktiven Benutzers ueber die konfigurierten Suchfelder."""
        fields = settings.SNOW_USER_LOOKUP_FIELDS or ["name"]
        query = "^OR".join(f"{field}={identifier}" for field in fields)
        return await self._resolve_reference(
            TABLE_USER,
            query=f"{query}^active=true",
            value=identifier,
            label="Benutzer",
        )

    async def _resolve_reference(
        self, table: str, *, query: str, value: str, label: str
    ) -> Optional[str]:
        async def lookup() -> Optional[str]:
            try:
                records = await self._query_table(
                    table, query=query, fields="sys_id", limit=2
                )
            except ServiceNowAPIError as exc:
                logger.error(
                    f"Aufloesung {label} '{value}' fehlgeschlagen: {exc.message}"
                )
                return None

            if not records:
                logger.error(
                    f"{label} '{value}' existiert nicht in ServiceNow "
                    f"(Tabelle {table}, Abfrage '{query}')."
                )
                return None

            if len(records) > 1:
                # Anzeigenamen sind in sys_user nicht eindeutig. Lieber laut
                # scheitern als stillschweigend den falschen Benutzer eintragen.
                logger.error(
                    f"{label} '{value}' ist in {table} nicht eindeutig. "
                    f"Eindeutiges Merkmal verwenden, etwa email oder user_name."
                )
                return None

            logger.info(f"{label} '{value}' aufgeloest und zwischengespeichert.")
            return str(records[0]["sys_id"])

        return await self._reference_cache.get_or_resolve((table, query, value), lookup)

    # ------------------------------------------------------------------ #
    # Transport
    # ------------------------------------------------------------------ #

    async def _query_table(
        self, table: str, *, query: str, fields: str, limit: int = 1
    ) -> list[dict[str, Any]]:
        result = await self._request(
            "GET",
            PATH_TABLE.format(table=table),
            params={
                "sysparm_query": query,
                "sysparm_fields": fields,
                "sysparm_limit": limit,
                "sysparm_exclude_reference_link": "true",
            },
        )
        records: list[dict[str, Any]] = result.get("result") or []
        return records

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> dict[str, Any]:
        url = f"{self._auth.base_url}{path}"
        last_status: Optional[int] = None

        for attempt in range(1, max_retries + 1):
            headers = await self._auth.headers()
            try:
                response = await self._http_client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=headers,
                    auth=self._auth.basic_auth(),
                )
            except httpx.HTTPError as exc:
                if attempt == max_retries:
                    raise ServiceNowAPIError(
                        f"Netzwerkfehler bei {method} {path}: {exc}"
                    ) from exc
                await asyncio.sleep(2**attempt)
                continue

            if (
                response.status_code == 401
                and self._auth.uses_oauth
                and attempt < max_retries
            ):
                self._auth.invalidate()
                logger.warning("ServiceNow lieferte 401. Token wird erneuert.")
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < max_retries:
                # Shared Instances haben haeufig Rate Limit Rules
                delay = float(response.headers.get("Retry-After") or 2**attempt)
                last_status = response.status_code
                logger.warning(
                    f"ServiceNow HTTP {response.status_code} bei {method} {path}. "
                    f"Retry {attempt}/{max_retries - 1} in {delay}s."
                )
                await asyncio.sleep(delay)
                continue

            if response.status_code >= 400:
                raise ServiceNowAPIError(
                    f"HTTP {response.status_code} bei {method} {path}: "
                    f"{response.text[:ERROR_TEXT_LIMIT]}",
                    upstream_status=response.status_code,
                )

            payload: dict[str, Any] = response.json() if response.content else {}
            return payload

        raise ServiceNowAPIError(
            f"{method} {path} nach {max_retries} Versuchen fehlgeschlagen "
            f"(zuletzt HTTP {last_status})"
        )
