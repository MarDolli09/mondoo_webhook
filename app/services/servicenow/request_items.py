"""Requested Items (``sc_req_item``): suchen, nach der Bestellung finden, aendern."""

from typing import Any, Optional

from app.core.exceptions import RequestItemNotFoundError
from app.core.logging import logger
from app.services.servicenow.constants import (
    PATH_TABLE_RECORD,
    RITM_RESOLVE_DELAYS,
    TABLE_REQUEST_ITEM,
)
from app.services.servicenow.transport import Record, ServiceNowTransport, poll

__all__ = ["RequestItems"]


class RequestItems:
    """Zugriff auf die Tabelle ``sc_req_item``."""

    def __init__(self, transport: ServiceNowTransport) -> None:
        self._transport = transport

    async def find_by_correlation_id(self, correlation_id: str) -> Optional[Record]:
        """Neuestes RITM mit dieser correlation_id; warnt bei Duplikaten."""
        records = await self._transport.query(
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

    async def find_for_request(self, request_sys_id: str) -> Record:
        """RITM zu einem Request; wartet, bis die Workflow-Engine es erzeugt hat.

        Raises:
            RequestItemNotFoundError: Auch nach allen Wartezeiten kein RITM.
        """
        records = await poll(
            RITM_RESOLVE_DELAYS,
            lambda: self._transport.query(
                TABLE_REQUEST_ITEM,
                query=f"request={request_sys_id}",
                fields="sys_id,number",
            ),
        )
        if not records:
            raise RequestItemNotFoundError(
                f"Kein RITM zu Request {request_sys_id} gefunden."
            )
        return records[0]

    async def patch(self, ritm_sys_id: str, body: dict[str, Any]) -> Record:
        """Aktualisiert Felder eines RITM und liefert Nummer, Status und Stage."""
        result = await self._transport.request(
            "PATCH",
            PATH_TABLE_RECORD.format(table=TABLE_REQUEST_ITEM, sys_id=ritm_sys_id),
            json_body=body,
            params={
                "sysparm_fields": "sys_id,number,state,stage",
                "sysparm_exclude_reference_link": "true",
            },
        )
        record: Record = result.get("result") or {}
        return record
