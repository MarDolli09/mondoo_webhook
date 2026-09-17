"""Abstrakte Schnittstellen zwischen Fachlogik und externen Systemen."""

from abc import ABC, abstractmethod
from typing import Any

from app.domain.cvss import CvssDetails
from app.models.case import NormalizedCase

__all__ = ["CvssLookup", "TicketSynchronizer"]


class CvssLookup(ABC):
    """Quelle fuer CVSS-Details zu einem Finding."""

    @abstractmethod
    async def fetch_cvss_details(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> CvssDetails:
        """Sucht das Finding im Scope und liefert Score, Rating und Fundseite.

        Wird nichts gefunden oder schlaegt die Suche fehl, ist das Ergebnis
        ``NO_CVSS_DETAILS``; die Anreicherung ist optional.
        """


class TicketSynchronizer(ABC):
    """Ziel-Ticketsystem fuer normalisierte Cases."""

    @abstractmethod
    async def synchronize(self, case: NormalizedCase) -> dict[str, Any]:
        """Legt ein Ticket an, aktualisiert oder schliesst es, oder verwirft.

        Das Ergebnis enthaelt mindestens ``action`` und, sofern vorhanden,
        ``number`` und ``sys_id`` des Tickets.
        """
