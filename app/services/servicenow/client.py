"""Synchronisiert normalisierte Cases als RITM in ServiceNow."""

from typing import Any, Optional

from app.core.config import settings
from app.core.logging import logger
from app.core.master_data import SNOW_INTEGRATION_USER
from app.domain.ports import TicketSynchronizer
from app.models.case import NormalizedCase
from app.models.mondoo import CLOSING_EVENTS
from app.services.servicenow.api import ServiceNowAPI
from app.services.servicenow.constants import TERMINAL_STATES
from app.services.servicenow.mapping import (
    build_catalog_variables,
    build_create_fields,
    build_update_fields,
    correlation_id,
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
        requested_for = (
            settings.SNOW_REQUESTED_FOR_SYS_ID
            or await self._api.resolve_user_sys_id(SNOW_INTEGRATION_USER)
        )
        request_sys_id = await self._api.order_catalog_item(
            build_catalog_variables(case), requested_for_sys_id=requested_for
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

        return {
            **updated,
            "number": number,
            "sys_id": ritm_sys_id,
            "request_sys_id": request_sys_id,
            "action": "created",
        }

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
