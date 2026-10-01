"""Zuordnungstabellen und Grenzen des Parsings.

Der Startpunkt der Anwendung (``app.api.dependencies``) befuellt sie aus den
Stammdaten; das Teilsystem selbst liest keine globale Konfiguration.
"""

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["ParsingConfig"]


@dataclass(frozen=True)
class ParsingConfig:
    """Fachliche Tabellen fuer Klassifikation, Space-Namen und Priorisierung."""

    # Pfadfragment der Finding-MRN -> Finding-Typ; die Reihenfolge ist relevant
    finding_type_patterns: Mapping[str, str]
    # Mondoo-Space-ID -> Anzeigename des Space
    space_names: Mapping[str, str]
    # Rating -> (Urgency, Impact)
    priority_map: Mapping[str, tuple[str, str]]
    default_urgency_impact: tuple[str, str]
    # Platzhalter im Feld CVE, wenn der Titel keine CVE nennt
    default_cve: str
    # Wie viele verschiedene Findings eines Case hoechstens abgefragt werden
    max_finding_lookups: int
