"""Priorisierung: Urgency und Impact aus Rating, Titel-Praefix oder Default."""

from collections.abc import Mapping
from typing import NamedTuple, Optional

__all__ = [
    "PRIORITY_SOURCE_CVSS",
    "PRIORITY_SOURCE_DEFAULT",
    "PRIORITY_SOURCE_MONDOO_RISK",
    "PRIORITY_SOURCE_TITLE",
    "Priority",
    "PriorityMatch",
    "determine_priority",
]

PRIORITY_SOURCE_CVSS = "cvss"
PRIORITY_SOURCE_MONDOO_RISK = "mondoo_risk"
PRIORITY_SOURCE_TITLE = "title"
PRIORITY_SOURCE_DEFAULT = "default"


class PriorityMatch(NamedTuple):
    """Womit die Zuordnung gelungen ist: ``rating``, ``title`` oder ``none``."""

    kind: str
    value: Optional[str]


class Priority(NamedTuple):
    """Ermittelte Priorisierung samt Herkunft fuer Auswertung und Logging."""

    urgency: str
    impact: str
    source: str
    match: PriorityMatch


def determine_priority(
    title: str,
    cvss_rating: Optional[str],
    risk_rating: Optional[str],
    priority_map: Mapping[str, tuple[str, str]],
    default_urgency_impact: tuple[str, str],
) -> Priority:
    """Ermittelt Urgency und Impact.

    Reihenfolge: CVSS-Rating, Mondoo Risk Rating, Schweregrad-Tag im Titel
    (z. B. ``[HIGH]``), Default. Ergibt der Titel den Default-Wert, lautet die
    Herkunft ``default``.
    """
    effective_rating = cvss_rating or risk_rating
    if cvss_rating:
        source = PRIORITY_SOURCE_CVSS
    elif risk_rating:
        source = PRIORITY_SOURCE_MONDOO_RISK
    else:
        source = ""

    urgency, impact, match = _map_priority(
        title, effective_rating, priority_map, default_urgency_impact
    )

    if not source:
        is_default = (urgency, impact) == tuple(default_urgency_impact)
        source = PRIORITY_SOURCE_DEFAULT if is_default else PRIORITY_SOURCE_TITLE

    return Priority(urgency, impact, source, match)


def _map_priority(
    title: str,
    rating: Optional[str],
    priority_map: Mapping[str, tuple[str, str]],
    default_urgency_impact: tuple[str, str],
) -> tuple[str, str, PriorityMatch]:
    if rating:
        rating_upper = rating.upper()
        if rating_upper in priority_map:
            urgency, impact = priority_map[rating_upper]
            return urgency, impact, PriorityMatch("rating", rating_upper)

    title_upper = title.upper()
    for severity, (urgency, impact) in priority_map.items():
        if f"[{severity}]" in title_upper:
            return urgency, impact, PriorityMatch("title", f"[{severity}]")

    urgency, impact = default_urgency_impact
    return urgency, impact, PriorityMatch("none", None)
