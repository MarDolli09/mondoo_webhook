"""Priorisierung: Urgency und Impact aus Rating, Titel-Praefix oder Default."""

from collections.abc import Mapping
from enum import Enum
from typing import Literal, NamedTuple, Optional

__all__ = [
    "MatchKind",
    "Priority",
    "PriorityMatch",
    "PrioritySource",
    "determine_priority",
]


class PrioritySource(str, Enum):
    """Herkunft der Priorisierung; der Wert erscheint in Log und Telemetrie."""

    MONDOO_RISK = "mondoo_risk"
    CVSS = "cvss"
    TITLE = "title"
    DEFAULT = "default"


# Womit die Zuordnung gelungen ist: Rating, Schweregrad-Tag im Titel oder nichts
MatchKind = Literal["rating", "title", "none"]


class PriorityMatch(NamedTuple):
    """Gefundener Schluessel der Zuordnung, etwa ``HIGH`` oder ``[HIGH]``."""

    kind: MatchKind
    value: Optional[str]


class Priority(NamedTuple):
    """Ermittelte Priorisierung samt Herkunft fuer Auswertung und Logging."""

    urgency: str
    impact: str
    source: PrioritySource
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
        (risk_rating, PrioritySource.MONDOO_RISK),
        (cvss_rating, PrioritySource.CVSS),
    )
    for rating, source in ratings:
        key = (rating or "").upper()
        if key in priority_map:
            urgency, impact = priority_map[key]
            return Priority(urgency, impact, source, PriorityMatch("rating", key))

    urgency, impact, match = _map_title(title, priority_map, default_urgency_impact)
    is_default = (urgency, impact) == tuple(default_urgency_impact)
    source = PrioritySource.DEFAULT if is_default else PrioritySource.TITLE
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
