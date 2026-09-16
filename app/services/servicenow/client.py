from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings
from app.core.logging import logger
from app.models.schemas import CLOSING_EVENTS, ServiceNowPayload

from . import mapping
from .api import ServiceNowAPI
from .constants import (
    OPENED_BY_SYSTEM,
    OPENED_BY_USER,
    TERMINAL_STATES,
)


class ServiceNowClient:
    def __init__(self, http_client: httpx.AsyncClient):
        self.api = ServiceNowAPI(http_client)

    # ------------------------------------------------------------------ #
    # Einstiegspunkt
    # ------------------------------------------------------------------ #

    async def process_payload(self, payload: ServiceNowPayload) -> Dict[str, Any]:
        correlation_id = mapping.correlation_id(payload)
        existing = await self.api.find_request_item_by_correlation_id(correlation_id)

        if existing is None:
            if payload.case.eventType in CLOSING_EVENTS:
                logger.info(
                    f"Ereignis '{payload.case.ticketState}' ohne bestehendes RITM "
                    f"zu '{correlation_id}'. Es wird kein Ticket angelegt."
                )
                return {"action": "skipped_closing_without_ritm"}

            logger.info(f"Kein RITM zu '{correlation_id}' vorhanden. Lege neuen Request an.")
            return await self._create(payload)

        state = str(existing.get("state", ""))
        if state in TERMINAL_STATES:
            logger.info(
                f"RITM {existing.get('number')} befindet sich im Endstatus "
                f"(state={state}). Ereignis '{payload.case.ticketState}' wird verworfen."
            )
            return {**existing, "action": "skipped"}

        logger.info(f"Bestehendes RITM {existing.get('number')} gefunden. Starte Update.")
        return await self._update(existing["sys_id"], payload)

    # ------------------------------------------------------------------ #
    # Anlegen
    # ------------------------------------------------------------------ #

    async def _create(self, payload: ServiceNowPayload) -> Dict[str, Any]:
        requested_for = settings.SNOW_REQUESTED_FOR_SYS_ID or await self.api.resolve_user_sys_id(OPENED_BY_USER)
        request_sys_id = await self.api.order_catalog_item(
            mapping.build_variables(payload),
            requested_for_sys_id=requested_for,
        )
        ritm = await self.api.resolve_request_item(request_sys_id)
        ritm_sys_id = ritm["sys_id"]

        body = await self._task_fields(payload, is_initial=True)
        updated = await self.api.patch_request_item(ritm_sys_id, body)

        number = updated.get("number") or ritm.get("number")
        logger.info(f"RITM {number} schlank angelegt (Status: Offen).")

        return {
            **updated,
            "number": number,
            "sys_id": ritm_sys_id,
            "request_sys_id": request_sys_id,
            "attachment": False,
            "action": "created",
        }

    # ------------------------------------------------------------------ #
    # Aktualisieren
    # ------------------------------------------------------------------ #

    async def _update(self, ritm_sys_id: str, payload: ServiceNowPayload) -> Dict[str, Any]:
        body = await self._task_fields(payload, is_initial=False)
        updated = await self.api.patch_request_item(ritm_sys_id, body)
        logger.info(
            f"RITM {updated.get('number')} aktualisiert (state={updated.get('state')})."
        )
        return {**updated, "sys_id": ritm_sys_id, "action": "updated"}

    # ------------------------------------------------------------------ #
    # Bausteine
    # ------------------------------------------------------------------ #

    async def _task_fields(
        self, payload: ServiceNowPayload, *, is_initial: bool
    ) -> Dict[str, Any]:
        group_sys_id = await self.api.resolve_group_sys_id(
            mapping.assignment_group_name(payload)
        )

        opened_by_sys_id: Optional[str] = None
        watcher_sys_ids: List[str] = []

        if is_initial:
            # 1. Geöffnet von ermitteln
            opened_by_target = (
                OPENED_BY_SYSTEM if payload.case.isAutomated else OPENED_BY_USER
            )
            opened_by_sys_id = await self.api.resolve_user_sys_id(opened_by_target)
            if not opened_by_sys_id:
                logger.warning(f"Konnte User '{opened_by_target}' in sys_user nicht finden.")

            # 2. Beobachterliste ermitteln (Lars + Alexander + optional Ersteller)
            target_watchers = mapping.watcher_names(payload)
            for name in target_watchers:
                w_id = await self.api.resolve_user_sys_id(name)
                if w_id and w_id not in watcher_sys_ids:
                    watcher_sys_ids.append(w_id)
                elif not w_id:
                    logger.warning(
                        f"Beobachter '{name}' konnte in ServiceNow nicht aufgelöst werden."
                    )

        return mapping.build_task_fields(
            payload,
            is_initial=is_initial,
            group_sys_id=group_sys_id,
            opened_by_sys_id=opened_by_sys_id,
            watcher_sys_ids=watcher_sys_ids if watcher_sys_ids else None,
        )