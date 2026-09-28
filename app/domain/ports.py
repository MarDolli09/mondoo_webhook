"""Abstrakte Schnittstellen zwischen Fachlogik und externen Systemen."""

from abc import ABC, abstractmethod
from typing import Any

from app.domain.scores import FindingScores
from app.models.case import NormalizedCase

__all__ = ["FindingScoresLookup", "TicketSynchronizer"]


class FindingScoresLookup(ABC):
    """Quelle fuer die Bewertungen eines Findings."""

    @abstractmethod
    async def fetch_finding_scores(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> FindingScores:
        """Sucht das Finding im Scope und liefert CVSS, Risk und Fundseite.

        Wird nichts gefunden oder schlaegt die Suche fehl, ist das Ergebnis
        ``NO_FINDING_SCORES``; die Anreicherung ist optional.
        """


class TicketSynchronizer(ABC):
    """Ziel-Ticketsystem fuer normalisierte Cases."""

    @abstractmethod
    async def synchronize(self, case: NormalizedCase) -> dict[str, Any]:
        """Legt ein Ticket an, aktualisiert oder schliesst es, oder verwirft.

        Das Ergebnis enthaelt mindestens ``action`` und, sofern vorhanden,
        ``number`` und ``sys_id`` des Tickets.
        """
