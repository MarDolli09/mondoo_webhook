"""Fachliche Stammdaten: Spaces, Personen, Prioritaeten und Klassifikation.

Die Tabellen in ``MasterData`` lassen sich per Umgebungsvariable (JSON)
ueberschreiben; der Startpunkt (``app.api.dependencies``) reicht sie an die
Teilsysteme weiter. Feste Organisationsdaten der ServiceNow-Anbindung stehen in
``app.services.servicenow.constants``.
"""

from pydantic_settings import BaseSettings

from app.core.config import SETTINGS_CONFIG

__all__ = ["MasterData", "master_data"]

_MONDOO_USER_MRN = "//captain.api.mondoo.app/users/"


class MasterData(BaseSettings):
    """Ueberschreibbare Zuordnungstabellen."""

    # Mondoo-Space-ID -> Anzeigename des Space. Der Name ist historisch; er bleibt,
    # weil er zugleich der Name der Umgebungsvariablen zum Ueberschreiben ist.
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

    # Mondoo-Space-ID -> Wert der Auswahl "Mondoo Space" im Katalogformular
    # (Variable mondoo_space). Daraus bestimmt der Workflow die Assignment Group;
    # ein unbekannter Wert landet dort bei der ersten Auswahl (Azure).
    SPACE_CHOICE_MAP: dict[str, str] = {
        "eu-elastic-hodgkin-413342": "space_azure",
        "eu-peaceful-elgamal-693498": "space_microsoft_defender_for_cloud",
        "eu-loving-lichterman-592949": "space_domain",
        "eu-crazy-driscoll-397797": "space_ip_address",
        "eu-hungry-maxwell-418237": "space_grafana",
        "eu-vigorous-mcnulty-229373": "space_m365",
        "eu-nifty-mendeleev-113214": "space_server",
        "eu-great-goldwasser-976351": "space_vmware",
        "eu-sweet-sanderson-152264": "space_windows_clients",
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
