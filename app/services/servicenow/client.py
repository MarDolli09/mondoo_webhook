"""Synchronisiert normalisierte Cases als RITM in ServiceNow."""

from typing import Any, Optional

from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
from app.domain.ports import SyncAction, SyncOutcome, TicketSynchronizer
from app.models.case import NormalizedCase
from app.models.mondoo import CLOSING_EVENTS
from app.services.servicenow.api import ServiceNowAPI
from app.services.servicenow.config import ServiceNowConfig
from app.services.servicenow.constants import (
    CATALOG_TASK_WORKFLOW_TITLE_PREFIX,
    SNOW_INTEGRATION_USER,
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

    def __init__(self, api: ServiceNowAPI, config: ServiceNowConfig) -> None:
        self._api = api
        self._config = config

    async def synchronize(self, case: NormalizedCase) -> SyncOutcome:
        """Anlegen, Aktualisieren oder Verwerfen je nach vorhandenem RITM."""
        case_correlation_id = correlation_id(case)
        existing = await self._api.request_items.find_by_correlation_id(
            case_correlation_id
        )

        if existing is None:
            if case.event_type in CLOSING_EVENTS:
                logger.info(
                    f"Ereignis '{case.raw_event_type}' ohne bestehendes RITM. "
                    f"Es wird kein Ticket angelegt."
                )
                return SyncOutcome(SyncAction.SKIPPED_CLOSING_WITHOUT_TICKET)

            logger.info("Kein RITM zum Case vorhanden, bestelle neuen Request.")
            return await self._create(case)

        state = str(existing.get("state", ""))
        if state in TERMINAL_STATES:
            logger.info(
                f"{existing.get('number')} befindet sich im Endstatus "
                f"(state={state}). Ereignis '{case.raw_event_type}' wird verworfen."
            )
            return SyncOutcome(
                SyncAction.SKIPPED_TERMINAL,
                ticket_number=_text(existing.get("number")),
                ticket_id=_text(existing.get("sys_id")),
            )

        logger.debug(f"{existing.get('number')} gefunden. Starte Update.")
        return await self._update(existing["sys_id"], case)

    # ------------------------------------------------------------------ #
    # Anlegen
    # ------------------------------------------------------------------ #

    async def _create(self, case: NormalizedCase) -> SyncOutcome:
        # Ohne sysparm_requested_for traegt ServiceNow den angemeldeten Benutzer
        # ein. Im Namen eines anderen zu bestellen ist dort rollenpflichtig.
        request_sys_id = await self._api.catalog.order(
            build_catalog_variables(case, self._config.user_names),
            requested_for_sys_id=self._config.requested_for_sys_id or None,
        )
        ritm = await self._api.request_items.find_for_request(request_sys_id)
        ritm_sys_id = ritm["sys_id"]

        body = build_create_fields(
            case,
            opened_by_sys_id=await self._resolve_opened_by(),
            watcher_sys_ids=await self._resolve_watchers(case),
        )
        updated = await self._api.request_items.patch(ritm_sys_id, body)

        number = updated.get("number") or ritm.get("number")
        title = ticket_title(case)
        logger.info(f"{number} angelegt (Status Offen): {title}")

        await self._retitle_catalog_tasks(ritm_sys_id, str(number), title)

        return SyncOutcome(
            SyncAction.CREATED,
            ticket_number=_text(number),
            ticket_id=_text(ritm_sys_id),
        )

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
            tasks = await self._api.catalog_tasks.find_assigned(ritm_sys_id)
            if not tasks:
                logger.warning(
                    f"Kein SCTASK mit Assignment Group zu {ritm_number} "
                    f"gefunden. Die Short Description des Tasks bleibt unveraendert."
                )
                return

            for task in tasks:
                current = str(task.get("short_description") or "")
                if not current.startswith(CATALOG_TASK_WORKFLOW_TITLE_PREFIX):
                    logger.info(
                        f"{task.get('number')} traegt bereits '{current}' "
                        f"und bleibt unveraendert."
                    )
                    continue
                await self._api.catalog_tasks.patch(
                    task["sys_id"], {"short_description": title}
                )
                logger.info(
                    f"{task.get('number')}: '{current}' durch Tickettitel ersetzt."
                )
        except ServiceNowAPIError as exc:
            logger.warning(
                f"Short Description der SCTASKs zu {ritm_number} nicht "
                f"gesetzt: {exc.message}"
            )

    async def _resolve_opened_by(self) -> Optional[str]:
        sys_id = await self._api.users.resolve_sys_id(SNOW_INTEGRATION_USER)
        if not sys_id:
            logger.warning(
                f"Konnte User '{SNOW_INTEGRATION_USER}' in sys_user nicht finden."
            )
        return sys_id

    async def _resolve_watchers(self, case: NormalizedCase) -> list[str]:
        sys_ids: list[str] = []
        for identifier in watcher_identifiers(case, self._config.user_names):
            sys_id = await self._api.users.resolve_sys_id(identifier)
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

    async def _update(self, ritm_sys_id: str, case: NormalizedCase) -> SyncOutcome:
        updated = await self._api.request_items.patch(
            ritm_sys_id, build_update_fields(case)
        )
        logger.info(
            f"{updated.get('number')} aktualisiert (state={updated.get('state')})."
        )
        return SyncOutcome(
            SyncAction.UPDATED,
            ticket_number=_text(updated.get("number")),
            ticket_id=_text(ritm_sys_id),
        )


def _text(value: Any) -> Optional[str]:
    """Feldwert eines ServiceNow-Datensatzes als Text, fehlend als ``None``."""
    return None if value is None else str(value)
