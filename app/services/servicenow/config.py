"""Einstellungen der ServiceNow-Anbindung.

Der Startpunkt der Anwendung (``app.api.dependencies``) befuellt sie aus der
Umgebung; das Teilsystem selbst liest keine globale Konfiguration.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from pydantic import SecretStr

__all__ = ["ServiceNowConfig"]


@dataclass(frozen=True)
class ServiceNowConfig:
    """Zugang und Zuordnungen fuer genau eine ServiceNow-Instanz."""

    base_url: str
    user: str
    password: SecretStr
    catalog_item_sys_id: str
    use_oauth: bool = False
    client_id: str = ""
    client_secret: SecretStr = field(default_factory=lambda: SecretStr(""))
    # Leer: ServiceNow traegt den angemeldeten Benutzer als "Angefordert fuer" ein
    requested_for_sys_id: str = ""
    # Felder in sys_user, ueber die Benutzer gesucht werden
    user_lookup_fields: tuple[str, ...] = ("user_name", "email", "name")
    # Mondoo-Benutzer-MRN -> Name des Benutzers in ServiceNow
    user_names: Mapping[str, str] = field(default_factory=dict)
