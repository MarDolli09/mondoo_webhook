"""Fachliche Stammdaten: Spaces, Personen, Prioritaeten und Klassifikation.

Die Tabellen in ``MasterData`` lassen sich wie bisher per Umgebungsvariable
(JSON) ueberschreiben. Die Konstanten sind feste Organisationsdaten.
"""

from pydantic_settings import BaseSettings

from app.core.config import SETTINGS_CONFIG

__all__ = [
    "AUTOMATED_CREATOR_LABEL",
    "FIXED_WATCHERS",
    "SNOW_INTEGRATION_USER",
    "MasterData",
    "master_data",
]

# Technischer ServiceNow-Benutzer: "Geoeffnet von" und Fallback fuer
# "Angefordert fuer".
SNOW_INTEGRATION_USER = "mosca.rest"

# Beobachter jedes neuen RITM; aufgeloest ueber SNOW_USER_LOOKUP_FIELDS.
FIXED_WATCHERS: tuple[str, ...] = ("lars.siefert@mosca.com",)

# Anzeigename des Erstellers bei automatisch erzeugten Mondoo-Tickets.
AUTOMATED_CREATOR_LABEL = "Mondoo-Drift"

_MONDOO_USER_MRN = "//captain.api.mondoo.app/users/"


class MasterData(BaseSettings):
    """Ueberschreibbare Zuordnungstabellen."""

    # Mondoo-Space-ID -> Anzeigename des Space
    CATEGORY_MAP: dict[str, str] = {
        "eu-elastic-hodgkin-413342": "Azure",
        "eu-peaceful-elgamal-693498": "Microsoft-Defender-for-Cloud",
        "eu-loving-lichterman-592949": "Domänen",
        "eu-crazy-driscoll-397797": "IP-Adressen",
        "eu-hungry-maxwell-418237": "Grafana",
        "eu-vigorous-mcnulty-229373": "M365",
        "eu-nifty-mendeleev-113214": "Server",
        "eu-great-goldwasser-976351": "VMware",
        "eu-sweet-sanderson-152264": "Windows-Clients",
    }

    # Mondoo-Benutzer-MRN -> Name des Benutzers in ServiceNow
    USER_MAP: dict[str, str] = {
        f"{_MONDOO_USER_MRN}3CnXrWtrHy64L3xt2SCzgJKX0OM": "Marius Dollinger",
        f"{_MONDOO_USER_MRN}2nFSVWcDIyqJLXA0A2xvpfU6pXg": "Lars Siefert",
        f"{_MONDOO_USER_MRN}2nZF38ZPg7vhizUrgIHqRF1aUwu": "Alexander Haller",
    }

    # Rating -> (Urgency, Impact); 1 = Critical ... 4 = Low
    PRIORITY_MAP: dict[str, tuple[str, str]] = {
        "CRITICAL": ("1", "1"),
        "HIGH": ("2", "2"),
        "MEDIUM": ("3", "3"),
        "LOW": ("4", "4"),
    }

    # Untergrenze des CVSS-Scores je Rating, absteigend geordnet
    CVSS_RATING_THRESHOLDS: dict[str, float] = {
        "CRITICAL": 9.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 0.1,
    }

    # Pfadfragment der Finding-MRN -> Finding-Typ; die Reihenfolge ist relevant
    FINDING_TYPE_MAP: dict[str, str] = {
        "/cves/": "vulnerability",
        "/advisories/MONDOO-EOL-": "end-of-life",
        "/advisories/": "advisories",
        "/queries/": "misconfiguration",
    }

    DEFAULT_CVE: str = " / "
    DEFAULT_URGENCY_IMPACT: tuple[str, str] = ("3", "3")

    model_config = SETTINGS_CONFIG


master_data = MasterData()
