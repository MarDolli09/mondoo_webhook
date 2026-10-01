"""Benutzer in ``sys_user``: Aufloesung von Namen und E-Mail-Adressen zu sys_ids."""

from collections.abc import Sequence
from typing import Optional

from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
from app.services.servicenow.cache import ReferenceCache
from app.services.servicenow.constants import TABLE_USER
from app.services.servicenow.transport import ServiceNowTransport

__all__ = ["UserDirectory"]

FALLBACK_LOOKUP_FIELDS = ("name",)


class UserDirectory:
    """Sucht aktive Benutzer; aufgeloeste sys_ids werden prozessweit gemerkt."""

    def __init__(
        self,
        transport: ServiceNowTransport,
        cache: ReferenceCache,
        lookup_fields: Sequence[str],
    ) -> None:
        self._transport = transport
        self._cache = cache
        self._lookup_fields = tuple(lookup_fields) or FALLBACK_LOOKUP_FIELDS

    async def resolve_sys_id(self, identifier: str) -> Optional[str]:
        """sys_id eines aktiven Benutzers ueber die konfigurierten Suchfelder."""
        query = "^OR".join(f"{field}={identifier}" for field in self._lookup_fields)
        return await self._resolve(
            TABLE_USER,
            query=f"{query}^active=true",
            value=identifier,
            label="Benutzer",
        )

    async def _resolve(
        self, table: str, *, query: str, value: str, label: str
    ) -> Optional[str]:
        async def lookup() -> Optional[str]:
            try:
                records = await self._transport.query(
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

        return await self._cache.get_or_resolve((table, query, value), lookup)
