"""Abstrakte Schnittstellen zwischen Fachlogik und externen Systemen."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.domain.scores import FindingScores
from app.models.case import NormalizedCase

__all__ = ["FindingScoresLookup", "SyncAction", "SyncOutcome", "TicketSynchronizer"]


class FindingScoresLookup(ABC):
    """Quelle fuer die Bewertungen eines Findings."""

    @abstractmethod
    async def fetch_finding_scores(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> FindingScores:
        """Bewertungen eines Findings im Scope: CVSS-Wert/-Rating, Risk Score/-Rating.

        Wird nichts gefunden oder schlaegt die Abfrage fehl, ist das Ergebnis
        ``NO_FINDING_SCORES``; die Anreicherung ist optional.
        """


class SyncAction(str, Enum):
    """Was die Synchronisierung mit dem Ticket gemacht hat.

    Die Werte erscheinen in Webhook-Antwort und Telemetrie (``snow_action``) und
    werden dort ausgewertet; sie duerfen sich nicht aendern.
    """

    CREATED = "created"
    UPDATED = "updated"
    SKIPPED_TERMINAL = "skipped"
    SKIPPED_CLOSING_WITHOUT_TICKET = "skipped_closing_without_ritm"


@dataclass(frozen=True)
class SyncOutcome:
    """Ergebnis der Synchronisierung, unabhaengig vom Ticketsystem."""

    action: SyncAction
    ticket_number: Optional[str] = None
    ticket_id: Optional[str] = None


class TicketSynchronizer(ABC):
    """Ziel-Ticketsystem fuer normalisierte Cases."""

    @abstractmethod
    async def synchronize(self, case: NormalizedCase) -> SyncOutcome:
        """Legt ein Ticket an, aktualisiert oder schliesst es, oder verwirft."""
