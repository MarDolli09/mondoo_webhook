"""Auswertung der Finding-Knoten aus der GraphQL-Antwort."""

from collections.abc import Iterable, Mapping
from typing import Any, Optional

from app.domain.scores import (
    NO_FINDING_SCORES,
    FindingScores,
    normalize_cvss_score,
    normalize_risk_score,
)
from app.services.mondoo.queries import CVSS_FIELDS

__all__ = ["extract_finding_scores", "highest_scores"]

# Ratings, die Mondoo fuer "kein Wert" verwendet
EMPTY_RATINGS = frozenset({"NONE", "NONE - EOL"})


def extract_finding_scores(node: Mapping[str, Any]) -> FindingScores:
    """Bewertungen eines Knotens; CVSS nur aus dem ``cvss``-Objekt.

    Das ``cvss``-Objekt steht je Typ unter einem eigenen Alias (``CVSS_FIELDS``).
    ``baseValue`` und ``baseScore`` sind der Basiswert auf der Risk-Skala und
    kein CVSS-Wert; sie bleiben deshalb unberuecksichtigt.
    """
    cvss: Mapping[str, Any] = next(
        (node[field] for field in CVSS_FIELDS if isinstance(node.get(field), Mapping)),
        {},
    )
    _, cvss_score = normalize_cvss_score(cvss.get("value"))
    return FindingScores(
        cvss_score=cvss_score,
        cvss_rating=_clean_rating(cvss.get("rating")) if cvss_score else None,
        risk_score=normalize_risk_score(node.get("riskValue") or node.get("riskScore")),
        risk_rating=_clean_rating(node.get("rating")),
    )


def highest_scores(nodes: Iterable[Mapping[str, Any]]) -> FindingScores:
    """Hoechste Bewertung ueber alle Knoten; die API liefert einen je Asset."""
    best = NO_FINDING_SCORES
    best_risk = -1.0
    for node in nodes:
        scores = extract_finding_scores(node)
        risk = float(scores.risk_score) if scores.risk_score else 0.0
        if best is NO_FINDING_SCORES or risk > best_risk:
            best, best_risk = scores, risk
    return best


def _clean_rating(rating: Any) -> Optional[str]:
    if not isinstance(rating, str) or rating.upper() in EMPTY_RATINGS:
        return None
    return rating.upper()
