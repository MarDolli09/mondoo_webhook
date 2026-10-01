"""Bestellung des Katalogformulars ueber die Service Catalog API."""

import json
from typing import Any, Optional

from app.core.exceptions import CatalogOrderError, ServiceNowAPIError
from app.core.logging import logger
from app.services.servicenow.constants import PATH_ORDER_NOW, PATH_SUBMIT_ORDER
from app.services.servicenow.transport import ServiceNowTransport

__all__ = ["ServiceCatalog"]


class ServiceCatalog:
    """Bestellt genau ein Katalogformular und liefert die sys_id des Requests."""

    def __init__(
        self, transport: ServiceNowTransport, catalog_item_sys_id: str
    ) -> None:
        self._transport = transport
        self._catalog_item_sys_id = catalog_item_sys_id

    async def order(
        self, variables: dict[str, str], requested_for_sys_id: Optional[str]
    ) -> str:
        """Bestellt das Formular mit diesen Variablen.

        Raises:
            ServiceNowAPIError: ServiceNow lehnt die Bestellung ab.
            CatalogOrderError: Die Antwort enthaelt keine Request-ID.
        """
        body: dict[str, Any] = {"sysparm_quantity": "1", "variables": variables}
        if requested_for_sys_id:
            body["sysparm_requested_for"] = requested_for_sys_id

        result = await self._order_now(body)
        # Bei aktiviertem Two-Step-Checkout verhaelt sich order_now wie
        # "in den Warenkorb legen" und liefert nur eine cart_id.
        if result.get("cart_id") and not result.get("request_id"):
            logger.info("Two-Step-Checkout erkannt. Sende submit_order nach.")
            response = await self._transport.request(
                "POST", PATH_SUBMIT_ORDER, json_body={}
            )
            result = response.get("result") or {}

        request_sys_id = result.get("request_id") or result.get("sys_id")
        if not request_sys_id:
            raise CatalogOrderError(f"order_now lieferte keine Request-ID: {result}")

        logger.info(
            f"Service Catalog Request "
            f"{result.get('request_number') or request_sys_id} erzeugt."
        )
        return str(request_sys_id)

    async def _order_now(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._transport.request(
                "POST",
                PATH_ORDER_NOW.format(item_sys_id=self._catalog_item_sys_id),
                json_body=body,
            )
        except ServiceNowAPIError:
            # Der Body enthaelt keine Geheimwerte und macht den Fehler
            # gegenueber ServiceNow nachstellbar.
            logger.error(
                f"order_now abgelehnt. Gesendeter Body: "
                f"{json.dumps(body, ensure_ascii=False)}"
            )
            raise
        result: dict[str, Any] = response.get("result") or {}
        return result
