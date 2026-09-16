from typing import Dict, List, Tuple
from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

UNRESOLVED_KEYVAULT_MARKER = "@Microsoft.KeyVault"
 
 
class Settings(BaseSettings):
 
    MONDOO_API_KEY: SecretStr
    WEBHOOK_SECRET_KEY: SecretStr
    SNOW_PASSWORD: SecretStr
    SNOW_CLIENT_SECRET: SecretStr = SecretStr("")
    SNOW_INSTANCE_URL: str
    SNOW_AUTH_MODE: str
    SNOW_USER: str
    SNOW_CLIENT_ID: str = ""
    SNOW_CATALOG_ITEM_SYS_ID: str
    SNOW_REQUESTED_FOR_SYS_ID: str = ""
    MONDOO_GRAPHQL_MAX_PAGES: int = 50
    HTTP_TIMEOUT_SECONDS: float = 10.0
    CVSS_SEARCH_BUDGET_SECONDS: float = 20.0
    CVSS_SEARCH_LOG_INTERVAL: int = 5
    CVSS_MAX_FINDING_ATTEMPTS: int = 3
    ASSET_NAME_LOOKUP_CONCURRENCY: int = 10
    ASSET_NAME_LOOKUP_LIMIT: int = 50
    DESCRIPTION_ASSET_PREVIEW: int = 10
    SNOW_USER_LOOKUP_FIELDS: List[str] = ["user_name", "email", "name"]

    CATEGORY_MAP: Dict[str, str] = {
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

    USER_MAP: Dict[str, str] = {
        "//captain.api.mondoo.app/users/3CnXrWtrHy64L3xt2SCzgJKX0OM": "Marius Dollinger",
        "//captain.api.mondoo.app/users/2nFSVWcDIyqJLXA0A2xvpfU6pXg": "Lars Siefert",
    }

    ASSIGNMENTGROUP_MAP: Dict[str, str] = {
        "eu-elastic-hodgkin-413342": "Mosca IT - Infrastructure Server & Storage",
        "eu-peaceful-elgamal-693498": "Mosca IT - Security",
        "eu-loving-lichterman-592949": "Mosca IT - Infrastrukture External Network (WAN / Access)",
        "eu-crazy-driscoll-397797": "Mosca IT - Infrastructure Internal Network (LAN / WLAN)",
        "eu-hungry-maxwell-418237":  "Mosca IT - Infrastructure Server & Storage",
        "eu-vigorous-mcnulty-229373": "Mosca IT - M365 General",
        "eu-nifty-mendeleev-113214": "Mosca IT - Infrastructure Server & Storage",
        "eu-great-goldwasser-976351": "Mosca IT - Infrastructure Server & Storage",
        "eu-sweet-sanderson-152264": "Mosca IT - Client General",
    }

    PRIORITY_MAP: Dict[str, Tuple[str, str]] = { 
        "CRITICAL": ("1", "1"), # Urgency: 1 - Critical, Impact: 1 - Critical
        "HIGH":     ("2", "2"), # Urgency: 2 - High,     Impact: 2 - High
        "MEDIUM":   ("3", "3"), # Urgency: 3 - Medium,   Impact: 3 - Medium
        "LOW":      ("4", "4"), # Urgency: 4 - Low,      Impact: 4 - Low
    }

    CVSS_RATING_THRESHOLDS: Dict[str, float] = {
        "CRITICAL": 9.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 0.1,
    }

    FINDING_TYPE_MAP: Dict[str, str] = {
        "/cves/": "vulnerability",
        "/advisories/MONDOO-EOL-": "end-of-life",
        "/advisories/": "advisories",
        "/queries/": "misconfiguration",
    }

    DEFAULT_CVE: str = " / "
    DEFAULT_URGENCY_IMPACT: Tuple[str, str] = ("3", "3")
    DEFAULT_TICKET_TYPE: str = " / "

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    @field_validator(
        "MONDOO_API_KEY", "WEBHOOK_SECRET_KEY", "SNOW_PASSWORD", "SNOW_CLIENT_SECRET"
    )
    @classmethod
    def _reject_unresolved_keyvault(cls, value: SecretStr, info) -> SecretStr:
        if value.get_secret_value().startswith(UNRESOLVED_KEYVAULT_MARKER):
            raise ValueError(
                f"{info.field_name} enthaelt eine nicht aufgeloeste "
                f"Key-Vault-Referenz. Pruefen: Managed Identity der App Service "
                f"aktiviert, Rolle 'Key Vault Secrets User' vergeben, "
                f"Secret-Name korrekt."
            )
        return value
 
    @model_validator(mode="after")
    def _check_required_secrets(self) -> "Settings":
        missing = [
            name
            for name in ("MONDOO_API_KEY", "WEBHOOK_SECRET_KEY", "SNOW_PASSWORD")
            if not getattr(self, name).get_secret_value()
        ]
        if missing:
            raise ValueError(f"Pflicht-Geheimwerte sind leer: {', '.join(missing)}")
 
        if self.SNOW_AUTH_MODE.lower() == "oauth":
            oauth_missing = [
                name
                for name, value in (
                    ("SNOW_CLIENT_ID", self.SNOW_CLIENT_ID),
                    ("SNOW_CLIENT_SECRET", self.SNOW_CLIENT_SECRET.get_secret_value()),
                )
                if not value
            ]
            if oauth_missing:
                raise ValueError(
                    f"SNOW_AUTH_MODE=oauth erfordert: {', '.join(oauth_missing)}"
                )
        return self
 

    def secret_values(self) -> List[str]:
        """Alle Geheimwerte im Klartext, fuer den Log-Formatter.
 
        Bewusst die einzige Stelle, die alle vier zusammen herausgibt - wer
        hier etwas ergaenzt, sorgt automatisch dafuer, dass es maskiert wird.
        """
        return [
            value
            for value in (
                self.MONDOO_API_KEY.get_secret_value(),
                self.WEBHOOK_SECRET_KEY.get_secret_value(),
                self.SNOW_PASSWORD.get_secret_value(),
                self.SNOW_CLIENT_SECRET.get_secret_value(),
            )
            if value
        ]
 
 
settings = Settings()