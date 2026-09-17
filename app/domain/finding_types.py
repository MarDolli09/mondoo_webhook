"""Finding-Typen: Klassifikation ueber die Finding-MRN und Verarbeitungsprofile."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

__all__ = [
    "DEFAULT_FINDING_TYPE",
    "FindingTypeProfile",
    "classify_finding_type",
    "profile_for",
]

DEFAULT_FINDING_TYPE = "other"


@dataclass(frozen=True)
class FindingTypeProfile:
    """Wie ein Finding-Typ verarbeitet und an ServiceNow gemeldet wird."""

    servicenow_type: str
    resolves_cvss: bool


_PROFILES: Mapping[str, FindingTypeProfile] = {
    "vulnerability": FindingTypeProfile("vulnerability", resolves_cvss=True),
    "advisories": FindingTypeProfile("advisories", resolves_cvss=True),
    # End-of-Life-Befunde werden wie Advisories angereichert, aber als eigener
    # Typ an ServiceNow gemeldet.
    "end-of-life": FindingTypeProfile("end-of-life", resolves_cvss=True),
    # Fehlkonfigurationen tragen kein CVSS, nur ein Mondoo Risk Rating.
    "misconfiguration": FindingTypeProfile("misconfiguration", resolves_cvss=False),
}
_DEFAULT_PROFILE = FindingTypeProfile(DEFAULT_FINDING_TYPE, resolves_cvss=False)


def classify_finding_type(
    finding_mrns: Iterable[str], type_patterns: Mapping[str, str]
) -> str:
    """Erster Typ, dessen Pfadfragment in einer der Finding-MRNs vorkommt."""
    for finding_mrn in finding_mrns:
        for pattern, finding_type in type_patterns.items():
            if pattern in finding_mrn:
                return finding_type
    return DEFAULT_FINDING_TYPE


def profile_for(finding_type: str) -> FindingTypeProfile:
    """Verarbeitungsprofil eines Typs; unbekannte Typen erhalten das Standardprofil."""
    return _PROFILES.get(finding_type, _DEFAULT_PROFILE)
