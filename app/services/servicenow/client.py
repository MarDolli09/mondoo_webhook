"""Synchronisiert normalisierte Cases als RITM in ServiceNow."""

from typing import Any, Optional

from app.core.config import settings
from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
from app.core.master_data import SNOW_INTEGRATION_USER
from app.domain.ports import TicketSynchronizer
from app.models.case import NormalizedCase
from app.models.mondoo import CLOSING_EVENTS
from app.services.servicenow.api import ServiceNowAPI
from app.services.servicenow.constants import (
    CATALOG_TASK_WORKFLOW_TITLE_PREFIX,
    TERMINAL_STATES,
)
from app.services.servicenow.mapping import (
    build_catalog_variables,
    build_create_fields,
    build_update_fields,
    correlation_id,
    ticket_title,
    watcher_identifiers,
)

__all__ = ["ServiceNowClient"]


class ServiceNowClient(TicketSynchronizer):
    """Legt RITMs ueber den Service Catalog an und pflegt sie bei Folgeereignissen."""

    def __init__(self, api: ServiceNowAPI) -> None:
        self._api = api

    async def synchronize(self, case: NormalizedCase) -> dict[str, Any]:
        """Anlegen, Aktualisieren oder Verwerfen je nach vorhandenem RITM."""
        case_correlation_id = correlation_id(case)
        existing = await self._api.find_request_item_by_correlation_id(
            case_correlation_id
        )

        if existing is None:
            if case.event_type in CLOSING_EVENTS:
                logger.info(
                    f"Ereignis '{case.raw_event_type}' ohne bestehendes RITM "
                    f"zu '{case_correlation_id}'. Es wird kein Ticket angelegt."
                )
                return {"action": "skipped_closing_without_ritm"}

            logger.info(
                f"Kein RITM zu '{case_correlation_id}' vorhanden. "
                f"Lege neuen Request an."
            )
            return await self._create(case)

        state = str(existing.get("state", ""))
        if state in TERMINAL_STATES:
            logger.info(
                f"RITM {existing.get('number')} befindet sich im Endstatus "
                f"(state={state}). Ereignis '{case.raw_event_type}' wird verworfen."
            )
            return {**existing, "action": "skipped"}

        logger.info(
            f"Bestehendes RITM {existing.get('number')} gefunden. Starte Update."
        )
        return await self._update(existing["sys_id"], case)

    # ------------------------------------------------------------------ #
    # Anlegen
    # ------------------------------------------------------------------ #

    async def _create(self, case: NormalizedCase) -> dict[str, Any]:
        # Ohne sysparm_requested_for traegt ServiceNow den angemeldeten Benutzer
        # ein. Im Namen eines anderen zu bestellen ist dort rollenpflichtig.
        request_sys_id = await self._api.order_catalog_item(
            build_catalog_variables(case),
            requested_for_sys_id=settings.SNOW_REQUESTED_FOR_SYS_ID or None,
        )
        ritm = await self._api.resolve_request_item(request_sys_id)
        ritm_sys_id = ritm["sys_id"]

        body = build_create_fields(
            case,
            opened_by_sys_id=await self._resolve_opened_by(),
            watcher_sys_ids=await self._resolve_watchers(case),
        )
        updated = await self._api.patch_request_item(ritm_sys_id, body)

        number = updated.get("number") or ritm.get("number")
        logger.info(f"RITM {number} schlank angelegt (Status: Offen).")

        await self._retitle_catalog_tasks(ritm_sys_id, str(number), ticket_title(case))

        return {
            **updated,
            "number": number,
            "sys_id": ritm_sys_id,
            "request_sys_id": request_sys_id,
            "action": "created",
        }

    async def _retitle_catalog_tasks(
        self, ritm_sys_id: str, ritm_number: str, title: str
    ) -> None:
        """Ersetzt den Workflow-Text der SCTASKs durch den Tickettitel.

        Ein Workflow bestimmt die Assignment Group aus "Mondoo Vulnerability -
        <Space>"; ueberschrieben wird deshalb erst, wenn die Gruppe gesetzt ist.
        Scheitert das, bleibt der Task wie vom Workflow angelegt, das RITM ist
        davon nicht betroffen.
        """
        try:
            tasks = await self._api.find_assigned_catalog_tasks(ritm_sys_id)
            if not tasks:
                logger.warning(
                    f"Kein SCTASK mit Assignment Group zu RITM {ritm_number} "
                    f"gefunden. Die Short Description des Tasks bleibt unveraendert."
                )
                return

            for task in tasks:
                current = str(task.get("short_description") or "")
                if not current.startswith(CATALOG_TASK_WORKFLOW_TITLE_PREFIX):
                    logger.info(
                        f"SCTASK {task.get('number')} traegt bereits '{current}' "
                        f"und bleibt unveraendert."
                    )
                    continue
                await self._api.patch_catalog_task(
                    task["sys_id"], {"short_description": title}
                )
                logger.info(
                    f"SCTASK {task.get('number')}: '{current}' durch Tickettitel "
                    f"ersetzt."
                )
        except ServiceNowAPIError as exc:
            logger.warning(
                f"Short Description der SCTASKs zu RITM {ritm_number} nicht "
                f"gesetzt: {exc.message}"
            )

    async def _resolve_opened_by(self) -> Optional[str]:
        sys_id = await self._api.resolve_user_sys_id(SNOW_INTEGRATION_USER)
        if not sys_id:
            logger.warning(
                f"Konnte User '{SNOW_INTEGRATION_USER}' in sys_user nicht finden."
            )
        return sys_id

    async def _resolve_watchers(self, case: NormalizedCase) -> list[str]:
        sys_ids: list[str] = []
        for identifier in watcher_identifiers(case):
            sys_id = await self._api.resolve_user_sys_id(identifier)
            if not sys_id:
                logger.warning(
                    f"Beobachter '{identifier}' konnte in ServiceNow nicht "
                    f"aufgeloest werden."
                )
            elif sys_id not in sys_ids:
                sys_ids.append(sys_id)
        return sys_ids

    # ------------------------------------------------------------------ #
    # Aktualisieren
    # ------------------------------------------------------------------ #

    async def _update(self, ritm_sys_id: str, case: NormalizedCase) -> dict[str, Any]:
        updated = await self._api.patch_request_item(
            ritm_sys_id, build_update_fields(case)
        )
        logger.info(
            f"RITM {updated.get('number')} aktualisiert (state={updated.get('state')})."
        )
        return {**updated, "sys_id": ritm_sys_id, "action": "updated"}
