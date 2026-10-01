"""Finding-Typen: Klassifikation ueber die Finding-MRN und Typ im Ticket."""

from collections.abc import Iterable, Mapping

__all__ = [
    "DEFAULT_FINDING_TYPE",
    "REPORTED_FINDING_TYPES",
    "classify_finding_type",
    "reported_finding_type",
]

DEFAULT_FINDING_TYPE = "other"

# Typen, die im Ticket unter eigenem Namen erscheinen. End-of-Life-Befunde sind
# Advisories, werden aber als eigener Typ gemeldet; Fehlkonfigurationen tragen
# kein CVSS, nur ein Mondoo Risk Rating.
REPORTED_FINDING_TYPES = frozenset(
    {"vulnerability", "advisories", "end-of-life", "misconfiguration"}
)


def classify_finding_type(
    finding_mrns: Iterable[str], type_patterns: Mapping[str, str]
) -> str:
    """Erster Typ, dessen Pfadfragment in einer der Finding-MRNs vorkommt."""
    for finding_mrn in finding_mrns:
        for pattern, finding_type in type_patterns.items():
            if pattern in finding_mrn:
                return finding_type
    return DEFAULT_FINDING_TYPE


def reported_finding_type(finding_type: str) -> str:
    """Typ fuer das Ticket; unbekannte Typen erscheinen als ``other``."""
    if finding_type in REPORTED_FINDING_TYPES:
        return finding_type
    return DEFAULT_FINDING_TYPE
