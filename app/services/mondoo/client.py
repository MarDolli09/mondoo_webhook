import time
from typing import Optional, Tuple
 
import httpx
 
from app.core.config import settings
from app.core.exceptions import (
    MondooAPIError,
    PaginationLimitExceededError,
    SearchBudgetExceededError,
)
from app.core.logging import logger
 
from . import findings as finding_utils
from .api import MondooGraphQLAPI, is_eu_scope, scope_mrn_for_space
 
CvssDetails = Tuple[Optional[str], Optional[str], Optional[int]]
NO_DETAILS: CvssDetails = (None, None, None)
 
 
class MondooGraphQLClient:
    def __init__(
        self, http_client: httpx.AsyncClient, api_key: Optional[str] = None
    ):
        key = api_key if api_key is not None else settings.MONDOO_API_KEY.get_secret_value()
        self.api = MondooGraphQLAPI(http_client, (key or "").strip())
 
    # ------------------------------------------------------------------ #
    # Asset-Namen
    # ------------------------------------------------------------------ #
 
    async def fetch_asset_name(
        self, space_id: str, asset_id: str, scope_mrn: str
    ) -> Optional[str]:
        if not self.api.is_configured:
            logger.warning("API-Key fehlt. GraphQL-Abruf wird uebersprungen.")
            return None
 
        try:
            return await self.api.fetch_asset_name(
                scope_mrn, is_eu=is_eu_scope(space_id=space_id, scope_mrn=scope_mrn)
            )
        except MondooAPIError as exc:
            logger.error(f"Asset-Name fuer {asset_id} nicht ermittelbar: {exc.message}")
        except Exception as exc:
            logger.error(f"Unerwarteter Fehler beim Abruf von Asset {asset_id}: {exc}")
        return None
 
    # ------------------------------------------------------------------ #
    # CVSS
    # ------------------------------------------------------------------ #
 
    async def fetch_cvss_details(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> CvssDetails:

        if not self.api.is_configured or not finding_mrn:
            return NO_DETAILS
 
        scope_mrn = scope_mrn or (scope_mrn_for_space(space_id) if space_id else "")
        if not scope_mrn:
            logger.warning(f"Keine scopeMrn fuer CVSS-Abruf von {finding_mrn} vorhanden.")
            return NO_DETAILS
 
        try:
            return await self._search(finding_mrn, scope_mrn, space_id)
        except (PaginationLimitExceededError, SearchBudgetExceededError) as exc:
            logger.warning(f"{exc.message} Verarbeitung ohne CVSS-Wert.")
        except MondooAPIError as exc:
            logger.error(f"CVSS-Suche fuer {finding_mrn} abgebrochen: {exc.message}")
        except Exception as exc:
            logger.error(f"Unerwarteter Fehler beim Abruf von CVSS fuer {finding_mrn}: {exc}")
        return NO_DETAILS
 
    async def _search(
        self, finding_mrn: str, scope_mrn: str, space_id: str
    ) -> CvssDetails:
        is_eu = is_eu_scope(
            space_id=space_id, finding_mrn=finding_mrn, scope_mrn=scope_mrn
        )
        key = finding_utils.search_key(finding_mrn)
 
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
 
            edges, page_info = await self.api.fetch_findings_page(
                scope_mrn, cursor, is_eu=is_eu
            )
 
            hit = self._match_in_page(edges, key=key, finding_mrn=finding_mrn, page=page)
            if hit:
                return hit
 
            if not page_info.get("hasNextPage"):
                logger.info(f"'{key}' in {page} Seiten nicht gefunden.")
                return NO_DETAILS
 
            next_cursor = page_info.get("endCursor")
            if next_cursor == cursor:
                logger.warning("Paginierungs-Cursor unveraendert. Breche Suche ab.")
                return NO_DETAILS
            cursor = next_cursor
 
            if page % log_interval == 0 and page < max_pages:
                logger.info(
                    f"'{key}' auf den Seiten {page - log_interval + 1}-{page} "
                    f"nicht gefunden. Suche wird fortgesetzt."
                )
 
    def _match_in_page(
        self, edges, *, key: str, finding_mrn: str, page: int
    ) -> Optional[CvssDetails]:
        for edge in edges:
            node = (edge or {}).get("node") or {}
            if not finding_utils.node_matches(node, key=key, finding_mrn=finding_mrn):
                continue
 
            score, rating = finding_utils.extract_score_and_rating(
                node, settings.CVSS_RATING_THRESHOLDS
            )
            logger.info(
                f"CVSS-Details auf Seite {page} geladen fuer {finding_mrn} "
                f"({node.get('__typename', 'Unknown')}) -> Score: {score}, Rating: {rating}"
            )
            return score, rating, page
        return None