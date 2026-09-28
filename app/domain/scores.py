"""Bewertungen eines Findings: CVSS-Wert und Mondoo Risk Score.

Mondoo unterscheidet beides: Der Risk Score ist ein kontextbezogener Wert von
0 bis 100 mit eigenem Rating, CVSS ist der Ausgangswert auf der Skala 0 bis 10.
Die Werte duerfen nicht ineinander umgerechnet werden.
"""

from collections.abc import Mapping
from typing import Any, NamedTuple, Optional

__all__ = [
    "NO_FINDING_SCORES",
    "FindingScores",
    "calculate_rating_from_score",
    "normalize_cvss_score",
    "normalize_risk_score",
]

MAX_CVSS_SCORE = 10.0
MAX_RISK_SCORE = 100.0
EMPTY_SCORE_VALUES = ("", "NONE", "NONE - EOL")


class FindingScores(NamedTuple):
    """Bewertungen eines Findings aus der Mondoo-API."""

    cvss_score: Optional[str]
    cvss_rating: Optional[str]
    risk_score: Optional[str]
    risk_rating: Optional[str]
    found_on_page: Optional[int]


NO_FINDING_SCORES = FindingScores(
    cvss_score=None,
    cvss_rating=None,
    risk_score=None,
    risk_rating=None,
    found_on_page=None,
)


def normalize_cvss_score(raw_value: Any) -> tuple[Optional[float], Optional[str]]:
    """Normalisiert einen CVSS-Wert auf die Skala 0-10.

    Liefert den Wert als Zahl und als Text mit einer Nachkommastelle, oder
    zweimal ``None``.
    """
    value = _as_float(raw_value)
    if value is None or value < 0 or value > MAX_CVSS_SCORE:
        return None, None

    value = round(value, 1)
    return value, f"{value:.1f}"


def normalize_risk_score(raw_value: Any) -> Optional[str]:
    """Mondoo Risk Score als ganze Zahl von 0 bis 100, sonst ``None``."""
    value = _as_float(raw_value)
    if value is None or value < 0 or value > MAX_RISK_SCORE:
        return None
    return str(round(value))


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


def _as_float(raw_value: Any) -> Optional[float]:
    if raw_value is None or raw_value in EMPTY_SCORE_VALUES:
        return None
    try:
        return float(raw_value)
    except (ValueError, TypeError):
        return None
