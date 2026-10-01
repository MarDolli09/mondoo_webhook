"""Bewertung eines Findings ueber die gefilterte Mondoo-Abfrage."""

import httpx

from app.core.exceptions import MondooAPIError
from app.core.logging import logger
from app.domain.identifiers import space_scope_mrn
from app.domain.ports import FindingScoresLookup
from app.domain.scores import NO_FINDING_SCORES, FindingScores
from app.services.mondoo.api import MondooGraphQLAPI
from app.services.mondoo.findings import highest_scores

__all__ = ["MondooGraphQLClient"]

# Die API liefert einen Knoten je betroffenem Asset; eine Seite genuegt fuer
# die hoechste Bewertung, solange sie alle Assets des Findings umfasst.
NODES_PER_FINDING = 100


class MondooGraphQLClient(FindingScoresLookup):
    """Bewertungsquelle auf Basis der Mondoo GraphQL-API."""

    def __init__(self, http_client: httpx.AsyncClient, api_key: str) -> None:
        self._api = MondooGraphQLAPI(http_client, api_key.strip())

    async def fetch_finding_scores(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> FindingScores:
        """Fragt die Bewertungen eines Findings in einem Scope ab.

        Ohne ``scope_mrn`` wird der Scope aus ``space_id`` gebildet. Die
        Anreicherung ist optional: Jeder Fehler fuehrt zu ``NO_FINDING_SCORES``,
        der Case wird dann ohne Bewertung verarbeitet.
        """
        if not finding_mrn:
            return NO_FINDING_SCORES

        scope_mrn = scope_mrn or (space_scope_mrn(space_id) if space_id else "")
        if not scope_mrn:
            logger.warning(
                f"Keine scopeMrn fuer die Bewertung von {finding_mrn} vorhanden."
            )
            return NO_FINDING_SCORES

        try:
            return await self._lookup(finding_mrn, scope_mrn)
        except MondooAPIError as exc:
            logger.error(f"Abfrage fuer {finding_mrn} abgebrochen: {exc.message}")
        except Exception as exc:
            # Bewusst breit: Ein unerwarteter Aufbau der Antwort darf den Webhook
            # nicht scheitern lassen. Der Traceback steht im Log und loest als
            # ERROR die Alarmierung aus.
            logger.error(
                f"Unerwarteter Fehler beim Abruf der Bewertung fuer "
                f"{finding_mrn}: {exc}",
                exc_info=True,
            )
        return NO_FINDING_SCORES

    async def _lookup(self, finding_mrn: str, scope_mrn: str) -> FindingScores:
        result = await self._api.fetch_finding_nodes(
            scope_mrn, finding_mrn, NODES_PER_FINDING
        )
        if not result.nodes:
            logger.info(f"Mondoo kennt {finding_mrn} in {scope_mrn} nicht.")
            return NO_FINDING_SCORES

        if result.total_count > len(result.nodes):
            logger.info(
                f"{finding_mrn} betrifft {result.total_count} Assets, bewertet "
                f"werden die ersten {len(result.nodes)}."
            )

        scores = highest_scores(result.nodes)
        logger.info(
            f"Bewertung fuer {finding_mrn} "
            f"({result.nodes[0].get('__typename', 'Unknown')}, "
            f"{result.total_count} Assets) -> CVSS "
            f"{scores.cvss_score or '-'} ({scores.cvss_rating or '-'}), "
            f"Risk {scores.risk_score or '-'} ({scores.risk_rating or '-'})"
        )
        return scores
