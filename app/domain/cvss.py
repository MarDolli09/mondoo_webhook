"""CVSS-Werte: Ergebnistyp, Normalisierung und Ableitung des Ratings."""

from collections.abc import Mapping
from typing import Any, NamedTuple, Optional

__all__ = [
    "NO_CVSS_DETAILS",
    "CvssDetails",
    "calculate_rating_from_score",
    "normalize_cvss_score",
]

MAX_CVSS_SCORE = 10.0
EMPTY_SCORE_VALUES = ("", "NONE", "NONE - EOL")


class CvssDetails(NamedTuple):
    """CVSS-Anreicherung eines Findings."""

    score: Optional[str]
    rating: Optional[str]
    found_on_page: Optional[int]


NO_CVSS_DETAILS = CvssDetails(score=None, rating=None, found_on_page=None)


def normalize_cvss_score(raw_value: Any) -> tuple[Optional[float], Optional[str]]:
    """Normalisiert einen Score auf die Skala 0-10.

    Werte ueber 10 gelten als Zehntel (81 -> 8.1). Liefert den Wert als Zahl
    und als Text mit einer Nachkommastelle, oder zweimal ``None``.
    """
    if raw_value is None or raw_value in EMPTY_SCORE_VALUES:
        return None, None

    try:
        value = float(raw_value)
    except (ValueError, TypeError):
        return None, None

    if value < 0:
        return None, None
    if value > MAX_CVSS_SCORE:
        value = value / 10.0
        if value > MAX_CVSS_SCORE:
            return None, None

    value = round(value, 1)
    return value, f"{value:.1f}"


def calculate_rating_from_score(
    score: Optional[float], thresholds: Mapping[str, float]
) -> Optional[str]:
    """Ermittelt das Rating ueber absteigend geordnete Schwellenwerte."""
    if score is None:
        return None

    for rating_name, threshold in thresholds.items():
        if score >= threshold:
            return rating_name.upper()

    return None
