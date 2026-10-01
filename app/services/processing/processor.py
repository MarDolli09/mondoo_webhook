"""Anwendungsablauf je Mondoo-Ereignis: klassifizieren, normalisieren, synchronisieren.

Kennt weder HTTP noch FastAPI; der Webhook-Endpunkt ist nur ein Ausloeser.
"""

import time
from dataclasses import dataclass

from app.core.logging import logger
from app.domain.ports import SyncOutcome, TicketSynchronizer
from app.models.case import NormalizedCase
from app.models.mondoo import MondooWebhookEvent
from app.services.parsing import CaseParser

__all__ = ["ProcessingResult", "WebhookProcessor"]


@dataclass(frozen=True)
class ProcessingResult:
    """Ergebnis eines verarbeiteten Ereignisses samt Laufzeiten."""

    # Erkannter Finding-Typ, z. B. "vulnerability" (vor einem ticketType-Override)
    finding_type: str
    case: NormalizedCase
    outcome: SyncOutcome
    parse_ms: float
    servicenow_ms: float


class WebhookProcessor:
    """Fuehrt ein Mondoo-Ereignis bis ins Ticketsystem."""

    def __init__(self, parser: CaseParser, tickets: TicketSynchronizer) -> None:
        self._parser = parser
        self._tickets = tickets

    async def process(self, event: MondooWebhookEvent) -> ProcessingResult:
        """Klassifiziert, normalisiert und synchronisiert ein Ereignis."""
        started = time.perf_counter()
        finding_type = self._parser.classify_finding_type(event)
        logger.info(
            f"Typ '{finding_type}' erkannt, Ereignis '{event.raw_type or '-'}', "
            f"{event.case.assets_count} Assets. Starte Parsing..."
        )
        case = await self._parser.parse(event, finding_type)
        parse_ms = _elapsed_ms(started)

        synchronize_started = time.perf_counter()
        outcome = await self._tickets.synchronize(case)
        servicenow_ms = _elapsed_ms(synchronize_started)

        return ProcessingResult(
            finding_type=finding_type,
            case=case,
            outcome=outcome,
            parse_ms=parse_ms,
            servicenow_ms=servicenow_ms,
        )


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)
