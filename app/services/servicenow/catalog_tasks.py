"""Catalog Tasks (``sc_task``), die der Workflow zu einem RITM anlegt."""

from typing import Any

from app.services.servicenow.constants import (
    CATALOG_TASK_LOOKUP_DELAYS,
    PATH_TABLE_RECORD,
    TABLE_CATALOG_TASK,
)
from app.services.servicenow.transport import Record, ServiceNowTransport, poll

__all__ = ["CatalogTasks"]


class CatalogTasks:
    """Zugriff auf die Tabelle ``sc_task``."""

    def __init__(self, transport: ServiceNowTransport) -> None:
        self._transport = transport

    async def find_assigned(self, ritm_sys_id: str) -> list[Record]:
        """SCTASKs eines RITM, sobald der Workflow die Assignment Group gesetzt hat.

        Wartet zwischen den Versuchen; ohne zugeordneten Task bis zum Ende
        eine leere Liste.
        """
        return await poll(
            CATALOG_TASK_LOOKUP_DELAYS,
            lambda: self._transport.query(
                TABLE_CATALOG_TASK,
                query=f"request_item={ritm_sys_id}^assignment_groupISNOTEMPTY",
                fields="sys_id,number,short_description",
                limit=10,
            ),
        )

    async def patch(self, task_sys_id: str, body: dict[str, Any]) -> Record:
        """Aktualisiert Felder eines SCTASK und liefert Nummer und Short Description."""
        result = await self._transport.request(
            "PATCH",
            PATH_TABLE_RECORD.format(table=TABLE_CATALOG_TASK, sys_id=task_sys_id),
            json_body=body,
            params={
                "sysparm_fields": "sys_id,number,short_description",
                "sysparm_exclude_reference_link": "true",
            },
        )
        record: Record = result.get("result") or {}
        return record
