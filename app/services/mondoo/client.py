"""CVSS-Suche ueber die paginierten Findings eines Mondoo-Scope."""

import time
from typing import Any, Optional

import httpx

from app.core.config import settings
from app.core.exceptions import (
    MondooAPIError,
    PaginationLimitExceededError,
    SearchBudgetExceededError,
)
from app.core.logging import logger
from app.core.master_data import master_data
from app.domain.cvss import NO_CVSS_DETAILS, CvssDetails
from app.domain.identifiers import space_scope_mrn
from app.domain.ports import CvssLookup
from app.services.mondoo.api import MondooGraphQLAPI
from app.services.mondoo.findings import (
    extract_score_and_rating,
    node_matches,
    search_key,
)

__all__ = ["MondooGraphQLClient"]


class MondooGraphQLClient(CvssLookup):
    """CVSS-Quelle auf Basis der Mondoo GraphQL-API."""

    def __init__(
        self, http_client: httpx.AsyncClient, api_key: Optional[str] = None
    ) -> None:
        key = (
            api_key
            if api_key is not None
            else settings.MONDOO_API_KEY.get_secret_value()
        )
        self._api = MondooGraphQLAPI(http_client, (key or "").strip())

    async def fetch_cvss_details(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> CvssDetails:
        """Durchsucht die Findings des Scope nach dem Finding.

        Ohne ``scope_mrn`` wird der Scope aus ``space_id`` gebildet. Fehler und
        erschoepfte Limits fuehren zu ``NO_CVSS_DETAILS``.
        """
        if not self._api.is_configured or not finding_mrn:
            return NO_CVSS_DETAILS

        scope_mrn = scope_mrn or (space_scope_mrn(space_id) if space_id else "")
        if not scope_mrn:
            logger.warning(
                f"Keine scopeMrn fuer CVSS-Abruf von {finding_mrn} vorhanden."
            )
            return NO_CVSS_DETAILS

        try:
            return await self._search(finding_mrn, scope_mrn)
        except (PaginationLimitExceededError, SearchBudgetExceededError) as exc:
            logger.warning(f"{exc.message} Verarbeitung ohne CVSS-Wert.")
        except MondooAPIError as exc:
            logger.error(f"CVSS-Suche fuer {finding_mrn} abgebrochen: {exc.message}")
        except Exception as exc:
            # Die Anreicherung ist optional; der Case wird ohne CVSS verarbeitet.
            logger.error(
                f"Unerwarteter Fehler beim Abruf von CVSS fuer {finding_mrn}: {exc}",
                exc_info=True,
            )
        return NO_CVSS_DETAILS

    async def _search(self, finding_mrn: str, scope_mrn: str) -> CvssDetails:
        key = search_key(finding_mrn)
        max_pages = settings.MONDOO_GRAPHQL_MAX_PAGES
        budget = settings.CVSS_SEARCH_BUDGET_SECONDS
        log_interval = settings.CVSS_SEARCH_LOG_INTERVAL
        deadline = time.monotonic() + budget

        logger.info(f"Suche nach '{key}' (max. {max_pages} Seiten, Budget {budget}s)")

        cursor: Optional[str] = None
        page = 0

        while True:
            if time.monotonic() > deadline:
                raise SearchBudgetExceededError(budget, page)

            page += 1
            if page > max_pages:
                raise PaginationLimitExceededError(max_pages)

            findings_page = await self._api.fetch_findings_page(scope_mrn, cursor)

            hit = self._match_in_page(
                findings_page.edges, key=key, finding_mrn=finding_mrn, page=page
            )
            if hit:
                return hit

            if not findings_page.page_info.get("hasNextPage"):
                logger.info(f"'{key}' in {page} Seiten nicht gefunden.")
                return NO_CVSS_DETAILS

            next_cursor = findings_page.page_info.get("endCursor")
            if next_cursor == cursor:
                logger.warning("Paginierungs-Cursor unveraendert. Breche Suche ab.")
                return NO_CVSS_DETAILS
            cursor = next_cursor

            if page % log_interval == 0 and page < max_pages:
                logger.info(
                    f"'{key}' auf den Seiten {page - log_interval + 1}-{page} "
                    f"nicht gefunden. Suche wird fortgesetzt."
                )

    @staticmethod
    def _match_in_page(
        edges: list[dict[str, Any]], *, key: str, finding_mrn: str, page: int
    ) -> Optional[CvssDetails]:
        for edge in edges:
            node = (edge or {}).get("node") or {}
            if not node_matches(node, key=key, finding_mrn=finding_mrn):
                continue

            score, rating = extract_score_and_rating(
                node, master_data.CVSS_RATING_THRESHOLDS
            )
            logger.info(
                f"CVSS-Details auf Seite {page} geladen fuer {finding_mrn} "
                f"({node.get('__typename', 'Unknown')}) -> Score: {score}, "
                f"Rating: {rating}"
            )
            return CvssDetails(score=score, rating=rating, found_on_page=page)
        return None
