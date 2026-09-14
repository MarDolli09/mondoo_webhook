import asyncio
from typing import Any, Dict, List, Optional
 
import httpx
 
from app.core.config import settings
from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
 
from .auth import ServiceNowAuth
from .constants import (
    DEFAULT_MAX_RETRIES,
    PATH_ATTACHMENT,
    PATH_ORDER_NOW,
    PATH_SUBMIT_ORDER,
    PATH_TABLE,
    PATH_TABLE_RECORD,
    RETRYABLE_STATUS,
    RITM_RESOLVE_DELAYS,
    TABLE_REQUEST_ITEM,
    TABLE_USER_GROUP,
)
 
 
class ServiceNowAPI:
    # Aufgeloeste Assignment-Group-sys_ids. Klassenebene, weil der Client pro
    # Request neu instanziiert wird.
    _group_cache: Dict[str, str] = {}
    _group_lock = asyncio.Lock()
 
    def __init__(self, http_client: httpx.AsyncClient, base_url: Optional[str] = None):
        self.http_client = http_client
        self.base_url = (base_url or settings.SNOW_INSTANCE_URL).rstrip("/")
        self.auth = ServiceNowAuth(self.http_client, self.base_url)
 
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
        """Fuehrt einen JSON-Aufruf aus und gibt den geparsten Rumpf zurueck.
 
        Wiederholt bei 429 und 5xx unter Beachtung von Retry-After sowie bei
        401 nach Token-Erneuerung. Alle anderen Fehler ab 400 werfen.
        """
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
        """Lookup fuer den Upsert.
 
        Fehler werden bewusst NICHT geschluckt: ein stillschweigendes None
        wuerde als 'existiert nicht' gelesen und ein Duplikat erzeugen.
        """
        records = await self._query_table(
            TABLE_REQUEST_ITEM,
            query=f"correlation_id={correlation_id}^ORDERBYDESCsys_created_on",
            fields="sys_id,number,state,stage,request",
        )
        return records[0] if records else None
 
    async def resolve_request_item(self, request_sys_id: str) -> Dict[str, Any]:
        """Ermittelt das RITM zum uebergeordneten Request.
 
        ServiceNow erzeugt es ueber die Workflow-Engine, teils verzoegert,
        deshalb mehrere Versuche mit wachsendem Abstand.
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
 
        raise ServiceNowAPIError(
            f"Kein RITM zu Request {request_sys_id} gefunden. "
            f"Moeglicherweise ist am Katalogformular kein Workflow hinterlegt."
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
 
    async def order_catalog_item(self, variables: Dict[str, str]) -> str:
        """Bestellt das Katalogformular und gibt die sys_id des REQ zurueck."""
        body: Dict[str, Any] = {"sysparm_quantity": "1", "variables": variables}
        if settings.SNOW_REQUESTED_FOR_SYS_ID:
            body["sysparm_requested_for"] = settings.SNOW_REQUESTED_FOR_SYS_ID
 
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
            raise ServiceNowAPIError(f"order_now lieferte keine Request-ID: {result}")
 
        logger.info(
            f"Service Catalog Request "
            f"{result.get('request_number') or request_sys_id} erzeugt."
        )
        return request_sys_id
 
    # ------------------------------------------------------------------ #
    # Referenzfelder
    # ------------------------------------------------------------------ #
 
    async def resolve_group_sys_id(self, group_name: str) -> Optional[str]:
        """Loest einen Gruppennamen in eine sys_id auf und merkt sich das Ergebnis.
 
        Notwendig, weil assignment_group ein Referenzfeld ist. Der Umweg ueber
        sysparm_input_display_value scheidet aus: der Parameter wirkt auf alle
        Felder im Rumpf und wuerde auch urgency und impact gegen Anzeigetexte
        aufzuloesen versuchen.
        """
        cls = ServiceNowAPI
        if group_name in cls._group_cache:
            return cls._group_cache[group_name]
 
        async with cls._group_lock:
            if group_name in cls._group_cache:
                return cls._group_cache[group_name]
 
            try:
                records = await self._query_table(
                    TABLE_USER_GROUP,
                    query=f"name={group_name}",
                    fields="sys_id,name",
                )
            except ServiceNowAPIError as exc:
                logger.error(
                    f"Aufloesung der Assignment Group '{group_name}' "
                    f"fehlgeschlagen: {exc.message}"
                )
                return None
 
            if not records:
                logger.error(
                    f"Assignment Group '{group_name}' existiert nicht in ServiceNow. "
                    f"Das RITM wird ohne Gruppenzuweisung angelegt."
                )
                return None
 
            sys_id = records[0]["sys_id"]
            cls._group_cache[group_name] = sys_id
            logger.info(
                f"Assignment Group '{group_name}' aufgeloest und zwischengespeichert."
            )
            return sys_id
 
    # ------------------------------------------------------------------ #
    # Anhaenge
    # ------------------------------------------------------------------ #
 
    async def upload_attachment(
        self,
        *,
        table: str,
        sys_id: str,
        file_name: str,
        content: str,
        content_type: str = "text/markdown",
    ) -> bool:
        """Haengt eine Datei an einen Datensatz.
 
        Bewusst fail-soft: auf einer Shared Instance kann dem Integrations-
        benutzer die Berechtigung fehlen. Das darf den Vorgang nicht abbrechen.
        Umgeht request(), weil hier Rohbytes statt JSON gesendet werden.
        """
        headers = await self.auth.headers(content_type=content_type)
 
        try:
            response = await self.http_client.post(
                f"{self.base_url}{PATH_ATTACHMENT}",
                params={
                    "table_name": table,
                    "table_sys_id": sys_id,
                    "file_name": file_name,
                },
                content=content.encode("utf-8"),
                headers=headers,
                auth=self.auth.basic_auth(),
            )
        except httpx.HTTPError as exc:
            logger.warning(f"Anhang konnte nicht uebertragen werden: {exc}")
            return False
 
        if response.status_code not in (200, 201):
            logger.warning(
                f"Anhang abgelehnt (HTTP {response.status_code}). "
                f"Pruefen, ob der Integrationsbenutzer Anhaenge schreiben darf."
            )
            return False
 
        logger.info(f"Anhang '{file_name}' abgelegt.")
        return True