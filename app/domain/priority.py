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

    Reihenfolge: Mondoo Risk Rating, CVSS-Rating, Schweregrad-Tag im Titel
    (z. B. ``[HIGH]``), Default. Das Mondoo-Risk geht vor, weil es den Kontext
    des Space beruecksichtigt (Exploits, Angriffsflaeche, Assets). Ein Rating
    ohne Eintrag in ``priority_map`` (etwa ``NONE``) wird uebersprungen. Ergibt
    der Titel den Default-Wert, lautet die Herkunft ``default``.
    """
    ratings = (
        (risk_rating, PRIORITY_SOURCE_MONDOO_RISK),
        (cvss_rating, PRIORITY_SOURCE_CVSS),
    )
    for rating, source in ratings:
        key = (rating or "").upper()
        if key in priority_map:
            urgency, impact = priority_map[key]
            return Priority(urgency, impact, source, PriorityMatch("rating", key))

    urgency, impact, match = _map_title(title, priority_map, default_urgency_impact)
    is_default = (urgency, impact) == tuple(default_urgency_impact)
    source = PRIORITY_SOURCE_DEFAULT if is_default else PRIORITY_SOURCE_TITLE
    return Priority(urgency, impact, source, match)


def _map_title(
    title: str,
    priority_map: Mapping[str, tuple[str, str]],
    default_urgency_impact: tuple[str, str],
) -> tuple[str, str, PriorityMatch]:
    title_upper = title.upper()
    for severity, (urgency, impact) in priority_map.items():
        if f"[{severity}]" in title_upper:
            return urgency, impact, PriorityMatch("title", f"[{severity}]")

    urgency, impact = default_urgency_impact
    return urgency, impact, PriorityMatch("none", None)
