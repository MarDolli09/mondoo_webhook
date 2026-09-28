"""Abgleich und Auswertung einzelner Finding-Knoten der GraphQL-Antwort."""

import re
from collections.abc import Mapping
from typing import Any, Optional

from app.domain.scores import (
    FindingScores,
    calculate_rating_from_score,
    normalize_cvss_score,
    normalize_risk_score,
)

__all__ = ["extract_finding_scores", "node_matches", "search_key"]

CVE_IN_MRN_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# Titelfelder der Union-Typen, in Auswerte-Reihenfolge
TITLE_FIELDS = ("cveTitle", "advTitle", "pkgTitle", "chkTitle", "genTitle")

# CVSS-Objekte der Union-Typen. CheckFinding und GenericFinding haben keines -
# Fehlkonfigurationen tragen kein CVSS, sondern nur ein Risk Rating.
CVSS_FIELDS = ("cveCvss", "advCvss", "pkgCvss")

# CVSS-Basiswerte, falls das CVSS-Objekt fehlt oder leer ist
CVSS_FALLBACK_FIELDS = ("baseValue", "baseScore")

# Kontextbezogener Mondoo Risk Score (0-100)
RISK_SCORE_FIELDS = ("riskValue", "riskScore")

# Ratings, die Mondoo fuer "kein Wert" verwendet
EMPTY_RATINGS = frozenset({"NONE", "NONE - EOL"})


def search_key(finding_mrn: str) -> str:
    """Der Wert, auf den beim Durchsuchen der Findings verglichen wird.

    Bei Vulnerabilities ist das die CVE-Kennung aus der MRN, sonst das letzte
    Pfadsegment - bei Fehlkonfigurationen also die Query-ID.
    """
    match = CVE_IN_MRN_PATTERN.search(finding_mrn)
    if match:
        return match.group(0).lower()
    return finding_mrn.split("/")[-1].lower()


def node_matches(node: Mapping[str, Any], *, key: str, finding_mrn: str) -> bool:
    """True, wenn MRN oder Titel des Knotens zum gesuchten Finding passen."""
    node_mrn = (node.get("mrn") or "").lower()
    return (
        key in node_mrn
        or key in _node_title(node).lower()
        or finding_mrn.lower() in node_mrn
    )


def extract_finding_scores(
    node: Mapping[str, Any], thresholds: Mapping[str, float]
) -> FindingScores:
    """CVSS-Wert und Mondoo Risk Score eines Knotens, strikt getrennt.

    Fehlt das CVSS-Objekt, bleiben die CVSS-Felder leer; der Risk Score tritt
    nicht an seine Stelle. Das CVSS-Rating wird notfalls aus dem CVSS-Wert
    abgeleitet.
    """
    cvss_object = _first_mapping(node, CVSS_FIELDS)
    cvss_value, cvss_score = normalize_cvss_score(_cvss_raw_value(node, cvss_object))
    cvss_rating = _clean_rating(
        cvss_object.get("rating") if cvss_object else None
    ) or _clean_rating(node.get("baseRating"))
    if cvss_rating is None:
        cvss_rating = calculate_rating_from_score(cvss_value, thresholds)

    return FindingScores(
        cvss_score=cvss_score,
        cvss_rating=cvss_rating,
        risk_score=normalize_risk_score(_first_value(node, RISK_SCORE_FIELDS)),
        risk_rating=_clean_rating(node.get("rating")),
        found_on_page=None,
    )


def _node_title(node: Mapping[str, Any]) -> str:
    for field in TITLE_FIELDS:
        value = node.get(field)
        if value:
            return str(value)
    return ""


def _first_mapping(
    node: Mapping[str, Any], fields: tuple[str, ...]
) -> Optional[Mapping[str, Any]]:
    for field in fields:
        candidate = node.get(field)
        if isinstance(candidate, dict):
            return candidate
    return None


def _first_value(node: Mapping[str, Any], fields: tuple[str, ...]) -> Any:
    for field in fields:
        value = node.get(field)
        if value:
            return value
    return None


def _cvss_raw_value(
    node: Mapping[str, Any], cvss_object: Optional[Mapping[str, Any]]
) -> Any:
    value = cvss_object.get("value") if cvss_object else None
    return value if value else _first_value(node, CVSS_FALLBACK_FIELDS)


def _clean_rating(rating: Any) -> Optional[str]:
    if not isinstance(rating, str) or rating.upper() in EMPTY_RATINGS:
        return None
    return rating.upper()
