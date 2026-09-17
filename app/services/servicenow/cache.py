"""Prozessweiter Cache fuer aufgeloeste ServiceNow-Referenzen (sys_id)."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Optional

__all__ = ["ReferenceCache", "ReferenceKey"]

# (Tabelle, Abfrage, gesuchter Wert)
ReferenceKey = tuple[str, str, str]


class ReferenceCache:
    """Task-sicherer Cache; nur erfolgreich aufgeloeste Referenzen werden gemerkt.

    Der Schluesselraum ist durch die konfigurierten Benutzer begrenzt. Muss in
    einer laufenden Event-Loop erzeugt werden (Lifespan).
    """

    def __init__(self) -> None:
        self._entries: dict[ReferenceKey, str] = {}
        self._lock = asyncio.Lock()

    async def get_or_resolve(
        self,
        key: ReferenceKey,
        resolve: Callable[[], Awaitable[Optional[str]]],
    ) -> Optional[str]:
        """Liefert den gemerkten Wert oder loest ihn genau einmal auf."""
        cached = self._entries.get(key)
        if cached:
            return cached

        async with self._lock:
            # Zweite Pruefung: waehrend des Wartens kann ein anderer Task
            # dieselbe Referenz bereits aufgeloest haben.
            cached = self._entries.get(key)
            if cached:
                return cached

            value = await resolve()
            if value:
                self._entries[key] = value
            return value

    def clear(self) -> None:
        """Verwirft alle gemerkten Referenzen."""
        self._entries.clear()
