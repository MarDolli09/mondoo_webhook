import asyncio
from typing import Any, Dict, List, Optional, Tuple
 
import httpx
 
from app.core.config import settings
from app.core.exceptions import (
    CatalogOrderError,
    RequestItemNotFoundError,
    ServiceNowAPIError,
)
from app.core.logging import logger
 
from .auth import ServiceNowAuth
from .constants import (
    DEFAULT_MAX_RETRIES,
    PATH_ORDER_NOW,
    PATH_SUBMIT_ORDER,
    PATH_TABLE,
    PATH_TABLE_RECORD,
    RETRYABLE_STATUS,
    RITM_RESOLVE_DELAYS,
    TABLE_REQUEST_ITEM,
    TABLE_USER,
    TABLE_USER_GROUP,
)


class ReferenceCache:
    """Task-sicherer In-Memory-Cache fuer aufgeloeste ServiceNow-Referenzen (sys_id)."""

    def __init__(self) -> None:
        self._cache: Dict[Tuple[str, str, str], str] = {}
        self._lock = asyncio.Lock()

    def get(self, key: Tuple[str, str, str]) -> Optional[str]:
        return self._cache.get(key)

    def set(self, key: Tuple[str, str, str], value: str) -> None:
        self._cache[key] = value

    def clear(self) -> None:
        self._cache.clear()

    @property
    def lock(self) -> asyncio.Lock:
        return self._lock


_global_reference_cache = ReferenceCache()


class ServiceNowAPI:
    def __init__(
        self,
        http_client: httpx.AsyncClient,
        base_url: Optional[str] = None,
        reference_cache: Optional[ReferenceCache] = None,
    ):
        self.http_client = http_client
        self.base_url = (base_url or settings.SNOW_INSTANCE_URL).rstrip("/")
        self.auth = ServiceNowAuth(self.http_client, self.base_url)
        self.cache = reference_cache or _global_reference_cache

    # ------------------------------------------------------------------ #
    # Transport
    # ------------------------------------------------------------------ #
 
    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> Dict[str, Any]:

        url = f"{self.base_url}{path}"
        last_status: Optional[int] = None
 
        for attempt in range(1, max_retries + 1):
            headers = await self.auth.headers()
            try:
                response = await self.http_client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=headers,
                    auth=self.auth.basic_auth(),
                )
            except httpx.HTTPError as exc:
                if attempt == max_retries:
                    raise ServiceNowAPIError(f"Netzwerkfehler bei {method} {path}: {exc}")
                await asyncio.sleep(2 ** attempt)
                continue
 
            if (
                response.status_code == 401
                and self.auth.uses_oauth
                and attempt < max_retries
            ):
                ServiceNowAuth.invalidate()
                logger.warning("ServiceNow lieferte 401. Token wird erneuert.")
                continue
 
            if response.status_code in RETRYABLE_STATUS and attempt < max_retries:
                # Shared Instances haben haeufig Rate Limit Rules
                delay = float(response.headers.get("Retry-After") or 2 ** attempt)
                last_status = response.status_code
                logger.warning(
                    f"ServiceNow HTTP {response.status_code} bei {method} {path}. "
                    f"Retry {attempt}/{max_retries - 1} in {delay}s."
                )
                await asyncio.sleep(delay)
                continue
 
            if response.status_code >= 400:
                raise ServiceNowAPIError(
                    f"HTTP {response.status_code} bei {method} {path}: {response.text[:400]}",
                    status_code=response.status_code,
                )
 
            return response.json() if response.content else {}
 
        raise ServiceNowAPIError(
            f"{method} {path} nach {max_retries} Versuchen fehlgeschlagen "
            f"(zuletzt HTTP {last_status})"
        )
 
    async def _query_table(
        self, table: str, *, query: str, fields: str, limit: int = 1
    ) -> List[Dict[str, Any]]:
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
        return result.get("result") or []
 
    # ------------------------------------------------------------------ #
    # Requested Items
    # ------------------------------------------------------------------ #
 
    async def find_request_item_by_correlation_id(
        self, correlation_id: str
    ) -> Optional[Dict[str, Any]]:

        records = await self._query_table(
            TABLE_REQUEST_ITEM,
            query=f"correlation_id={correlation_id}^ORDERBYDESCsys_created_on",
            fields="sys_id,number,state,stage,request",
            limit=2,
        )
        if len(records) > 1:
            numbers = [r.get("number", "ohne Nummer") for r in records]
            logger.warning(
                f"Mehrere RITMs ({', '.join(numbers)}) zu correlation_id '{correlation_id}' "
                f"gefunden! Mögliches Duplikat. Verwende das neueste Ticket ({records[0].get('number')})."
            )
        return records[0] if records else None
 
    async def resolve_request_item(self, request_sys_id: str) -> Dict[str, Any]:

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
        self, ritm_sys_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        result = await self.request(
            "PATCH",
            PATH_TABLE_RECORD.format(table=TABLE_REQUEST_ITEM, sys_id=ritm_sys_id),
            json_body=body,
            params={
                "sysparm_fields": "sys_id,number,state,stage",
                "sysparm_exclude_reference_link": "true",
            },
        )
        return result.get("result") or {}
 
    # ------------------------------------------------------------------ #
    # Service Catalog
    # ------------------------------------------------------------------ #
 
    async def order_catalog_item(
        self, variables: Dict[str, str], requested_for_sys_id: Optional[str] = None
    ) -> str:
        """Bestellt das Katalogformular und gibt die sys_id des REQ zurueck."""
        body: Dict[str, Any] = {"sysparm_quantity": "1", "variables": variables}
        target_requested_for = requested_for_sys_id or settings.SNOW_REQUESTED_FOR_SYS_ID
        if target_requested_for:
            body["sysparm_requested_for"] = target_requested_for
 
        response = await self.request(
            "POST",
            PATH_ORDER_NOW.format(item_sys_id=settings.SNOW_CATALOG_ITEM_SYS_ID),
            json_body=body,
        )
        result = response.get("result") or {}
 
        # Bei aktiviertem Two-Step-Checkout verhaelt sich order_now wie
        # "in den Warenkorb legen" und liefert nur eine cart_id.
        if result.get("cart_id") and not result.get("request_id"):
            logger.info("Two-Step-Checkout erkannt. Sende submit_order nach.")
            response = await self.request("POST", PATH_SUBMIT_ORDER, json_body={})
            result = response.get("result") or {}
 
        request_sys_id = result.get("request_id") or result.get("sys_id")
        if not request_sys_id:
            raise CatalogOrderError(f"order_now lieferte keine Request-ID: {result}")
 
        logger.info(
            f"Service Catalog Request "
            f"{result.get('request_number') or request_sys_id} erzeugt."
        )
        return request_sys_id
 
    # ------------------------------------------------------------------ #
    # Referenzfelder
    # ------------------------------------------------------------------ #
 
    async def _resolve_reference(
        self, table: str, *, query: str, value: str, label: str
    ) -> Optional[str]:
        cache_key = (table, query, value)
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        async with self.cache.lock:
            cached = self.cache.get(cache_key)
            if cached:
                return cached

            try:
                records = await self._query_table(
                    table, query=query, fields="sys_id", limit=2
                )
            except ServiceNowAPIError as exc:
                logger.error(f"Aufloesung {label} '{value}' fehlgeschlagen: {exc.message}")
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

            sys_id = records[0]["sys_id"]
            self.cache.set(cache_key, sys_id)
            logger.info(f"{label} '{value}' aufgeloest und zwischengespeichert.")
            return sys_id

    async def resolve_group_sys_id(self, group_name: str) -> Optional[str]:
        return await self._resolve_reference(
            TABLE_USER_GROUP,
            query=f"name={group_name}",
            value=group_name,
            label="Assignment Group",
        )

    async def resolve_user_sys_id(self, identifier: str) -> Optional[str]:

        fields = settings.SNOW_USER_LOOKUP_FIELDS or ["name"]
        query = "^OR".join(f"{field}={identifier}" for field in fields)
        return await self._resolve_reference(
            TABLE_USER,
            query=f"{query}^active=true",
            value=identifier,
            label="Benutzer",
        )