"""Bewertungen eines Findings: CVSS-Wert und Mondoo Risk Score.

Mondoo unterscheidet beides: Der Risk Score ist ein kontextbezogener Wert von
0 bis 100 mit eigenem Rating, CVSS ist der Ausgangswert auf der Skala 0 bis 10.
Die Werte duerfen nicht ineinander umgerechnet werden.
"""

from typing import Any, NamedTuple, Optional

__all__ = [
    "NO_FINDING_SCORES",
    "FindingScores",
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


NO_FINDING_SCORES = FindingScores(
    cvss_score=None,
    cvss_rating=None,
    risk_score=None,
    risk_rating=None,
)


def normalize_cvss_score(raw_value: Any) -> tuple[Optional[float], Optional[str]]:
    """Normalisiert einen CVSS-Wert auf die Skala 0-10.

    Die Mondoo-API liefert CVSS auf der Skala 0-100 (98 entspricht 9.8). Der
    Wert 0 bedeutet "kein CVSS", etwa bei End-of-Life-Hinweisen.
    """
    value = _as_float(raw_value)
    if value is None or value <= 0:
        return None, None
    if value > MAX_CVSS_SCORE:
        value = value / 10.0
    if value > MAX_CVSS_SCORE:
        return None, None

    value = round(value, 1)
    return value, f"{value:.1f}"


def normalize_risk_score(raw_value: Any) -> Optional[str]:
    """Mondoo Risk Score als ganze Zahl von 0 bis 100, sonst ``None``."""
    value = _as_float(raw_value)
    if value is None or value < 0 or value > MAX_RISK_SCORE:
        return None
    return str(round(value))


def _as_float(raw_value: Any) -> Optional[float]:
    if raw_value is None or raw_value in EMPTY_SCORE_VALUES:
        return None
    try:
        return float(raw_value)
    except (ValueError, TypeError):
        return None
