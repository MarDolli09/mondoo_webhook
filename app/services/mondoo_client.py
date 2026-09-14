import re
import time
from typing import Optional, Tuple

import httpx

from app.core.config import settings
from app.core.exceptions import PaginationLimitExceededError
from app.core.logging import logger
from app.domain.normalizer import calculate_rating_from_score, normalize_cvss_score
from app.services.graphql_queries import GET_ASSET_QUERY, GET_FINDINGS_PAGINATED_QUERY


class MondooGraphQLClient:
    def __init__(self, http_client: httpx.AsyncClient, api_key: str = settings.MONDOO_API_KEY):
        self.http_client = http_client
        self.api_key = api_key.strip() if api_key else ""

    @staticmethod
    def _endpoint(is_eu: bool) -> str:
        return "https://eu.api.mondoo.com/query" if is_eu else "https://api.mondoo.com/query"

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    async def fetch_asset_name(self, space_id: str, asset_id: str, scope_mrn: str) -> Optional[str]:
        if not self.api_key:
            logger.warning("API-Key fehlt. GraphQL API-Abruf wird übersprungen.")
            return None

        endpoint = self._endpoint(space_id.startswith("eu-"))
        payload = {"query": GET_ASSET_QUERY, "variables": {"mrn": scope_mrn}}

        try:
            response = await self.http_client.post(endpoint, json=payload, headers=self._headers())
            if response.status_code == 200:
                res_data = response.json()
                if "errors" in res_data:
                    logger.error(f"GraphQL API Fehler für Asset {asset_id}: {res_data['errors']}")
                    return None

                asset_obj = res_data.get("data", {}).get("asset") or {}
                name = asset_obj.get("name")
                if name:
                    return name
            else:
                logger.error(
                    f"GraphQL API HTTP-Fehler {response.status_code} für Asset {asset_id}: {response.text}"
                )
        except Exception as e:
            logger.error(f"Unerwarteter Fehler beim Abruf von Asset {asset_id}: {e}")

        return None

    async def fetch_cvss_details(
        self, finding_mrn: str, scope_mrn: str = "", space_id: str = ""
    ) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """
        Sucht den CVSS-Score zu einem Befund über die paginierte Findings-Query.

        Die Suche ist doppelt begrenzt: durch MONDOO_GRAPHQL_MAX_PAGES und durch
        ein Zeitbudget. Letzteres ist der wirksamere Schutz, weil die Laufzeit
        einer Seite nicht vorhersagbar ist. Wird das Budget überschritten, bricht
        die Suche kontrolliert ab - der Befund wird dann ohne CVSS-Wert
        weiterverarbeitet, statt den gesamten Webhook in einen Timeout laufen
        zu lassen.
        """
        if not self.api_key or not finding_mrn:
            return None, None, None

        if not scope_mrn and space_id:
            scope_mrn = f"//captain.api.mondoo.app/spaces/{space_id}"

        if not scope_mrn:
            logger.warning(f"Keine scopeMrn für CVSS-Abruf von {finding_mrn} vorhanden.")
            return None, None, None

        is_eu = (
            space_id.startswith("eu-")
            or "eu-" in finding_mrn
            or "eu.api.mondoo" in finding_mrn
            or "eu-" in scope_mrn
        )
        endpoint = self._endpoint(is_eu)
        headers = self._headers()

        cve_match = re.search(r"CVE-\d{4}-\d+", finding_mrn, re.IGNORECASE)
        target_cve = cve_match.group(0).lower() if cve_match else finding_mrn.split("/")[-1].lower()

        has_next_page = True
        cursor = None
        page_count = 0
        log_interval = settings.CVSS_SEARCH_LOG_INTERVAL
        max_pages = settings.MONDOO_GRAPHQL_MAX_PAGES
        deadline = time.monotonic() + settings.CVSS_SEARCH_BUDGET_SECONDS

        try:
            logger.info(
                f"Suche nach '{target_cve}' (max. {max_pages} Seiten, "
                f"Budget {settings.CVSS_SEARCH_BUDGET_SECONDS}s)"
            )

            while has_next_page:
                if time.monotonic() > deadline:
                    logger.warning(
                        f"Zeitbudget für CVSS-Suche nach '{target_cve}' nach {page_count} Seiten "
                        f"erschöpft. Verarbeitung wird ohne CVSS-Wert fortgesetzt."
                    )
                    break

                page_count += 1
                if page_count > max_pages:
                    raise PaginationLimitExceededError(max_pages)

                payload = {
                    "query": GET_FINDINGS_PAGINATED_QUERY,
                    "variables": {"scopeMrn": scope_mrn, "cursor": cursor},
                }

                response = await self.http_client.post(endpoint, json=payload, headers=headers)

                if response.status_code != 200:
                    logger.error(
                        f"GraphQL API HTTP-Fehler {response.status_code} für Scope {scope_mrn}: {response.text}"
                    )
                    break

                res_data = response.json()
                if "errors" in res_data:
                    logger.error(f"GraphQL API Schema-Fehler auf Seite {page_count}: {res_data['errors']}")
                    break

                findings_union = res_data.get("data", {}).get("findings") or {}

                if "message" in findings_union:
                    logger.error(
                        f"GraphQL API Union-Fehler auf Seite {page_count}: {findings_union.get('message')}"
                    )
                    break

                for edge in findings_union.get("edges") or []:
                    node = edge.get("node") or {}
                    f_mrn = node.get("mrn", "").lower()
                    title = (
                        node.get("cveTitle")
                        or node.get("advTitle")
                        or node.get("pkgTitle")
                        or node.get("chkTitle")
                        or node.get("genTitle")
                        or ""
                    ).lower()

                    typename = node.get("__typename", "Unknown")

                    is_match = (
                        target_cve in f_mrn
                        or target_cve in title
                        or finding_mrn.lower() in f_mrn
                    )

                    if not is_match:
                        continue

                    raw_cvss_val = None
                    cvss_rating = None

                    cvss_obj = node.get("cveCvss") or node.get("advCvss") or node.get("pkgCvss")
                    if isinstance(cvss_obj, dict):
                        raw_cvss_val = cvss_obj.get("value")
                        cvss_rating = cvss_obj.get("rating")

                    if isinstance(cvss_rating, str) and cvss_rating.upper() in ["NONE", "NONE - EOL"]:
                        cvss_rating = None

                    if raw_cvss_val is None or raw_cvss_val in [0, 0.0, "0", "0.0"]:
                        raw_cvss_val = (
                            node.get("riskValue")
                            or node.get("riskScore")
                            or node.get("baseValue")
                            or node.get("baseScore")
                        )

                    if cvss_rating is None:
                        cvss_rating = node.get("rating") or node.get("baseRating")

                    f_val_clean, score_str = normalize_cvss_score(raw_cvss_val)

                    if cvss_rating is None and f_val_clean is not None:
                        cvss_rating = calculate_rating_from_score(
                            f_val_clean, settings.CVSS_RATING_THRESHOLDS
                        )

                    rating_str = str(cvss_rating).upper() if cvss_rating is not None else None

                    logger.info(
                        f"CVSS Details auf Seite {page_count} geladen für {finding_mrn} ({typename}) -> "
                        f"Score: {score_str}, Rating: {rating_str}"
                    )
                    return score_str, rating_str, page_count

                page_info = findings_union.get("pageInfo") or {}
                has_next_page = page_info.get("hasNextPage", False)
                new_cursor = page_info.get("endCursor")

                if new_cursor == cursor:
                    logger.warning("Paginierungs-Cursor hat sich nicht verändert. Breche Schleife ab.")
                    break
                cursor = new_cursor

                if has_next_page and page_count % log_interval == 0 and page_count < max_pages:
                    interval_start = page_count - log_interval + 1
                    logger.info(
                        f"'{target_cve}' auf den Seiten {interval_start}-{page_count} nicht gefunden. "
                        f"Suche wird fortgesetzt."
                    )

        except PaginationLimitExceededError as e:
            logger.error(str(e))
        except Exception as e:
            logger.error(f"Unerwarteter Fehler beim Abruf von CVSS für {finding_mrn}: {e}")

        return None, None, None