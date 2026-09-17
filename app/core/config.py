"""Technische Konfiguration aus Umgebungsvariablen: Secrets, Endpunkte, Limits.

Fachliche Stammdaten stehen in ``app.core.master_data``.
"""

import os
import re

from pydantic import (
    PositiveInt,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.webhook_signature import decode_signing_secret

__all__ = ["SETTINGS_CONFIG", "Settings", "settings"]

UNRESOLVED_KEYVAULT_MARKER = "@Microsoft.KeyVault"
# Zulaessige Zeichen eines HTTP-Headernamens (RFC 9110, token)
HEADER_NAME_PATTERN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
OAUTH_AUTH_MODE = "oauth"

# APP_ENV_FILE erlaubt Tests und Audits, eine Dummy-Datei statt .env zu laden.
# hide_input_in_errors: Validierungsfehler beim Start duerfen keine Werte (Secrets)
# ins Log schreiben, nur die Namen der betroffenen Felder.
SETTINGS_CONFIG = SettingsConfigDict(
    env_file=os.environ.get("APP_ENV_FILE", ".env"),
    env_file_encoding="utf-8",
    extra="ignore",
    case_sensitive=False,
    hide_input_in_errors=True,
)


class Settings(BaseSettings):
    """Infrastruktur-Einstellungen des Webhooks."""

    MONDOO_API_KEY: SecretStr
    # Authentifizierung der Mondoo-Zustellungen (Standard Webhooks + Header)
    MONDOO_WEBHOOK_SIGNING_SECRET: SecretStr
    MONDOO_WEBHOOK_AUTH_HEADER_VALUE: SecretStr
    MONDOO_WEBHOOK_AUTH_HEADER: str = "Authorization"
    MONDOO_WEBHOOK_TOLERANCE_SECONDS: PositiveInt = 300
    SNOW_PASSWORD: SecretStr
    SNOW_CLIENT_SECRET: SecretStr = SecretStr("")
    SNOW_INSTANCE_URL: str
    SNOW_AUTH_MODE: str
    SNOW_USER: str
    SNOW_CLIENT_ID: str = ""
    SNOW_CATALOG_ITEM_SYS_ID: str
    SNOW_REQUESTED_FOR_SYS_ID: str = ""
    SNOW_USER_LOOKUP_FIELDS: list[str] = ["user_name", "email", "name"]
    MONDOO_GRAPHQL_MAX_PAGES: int = 50
    HTTP_TIMEOUT_SECONDS: float = 10.0
    CVSS_SEARCH_BUDGET_SECONDS: float = 20.0
    CVSS_SEARCH_LOG_INTERVAL: int = 5
    CVSS_MAX_FINDING_ATTEMPTS: int = 3

    model_config = SETTINGS_CONFIG

    @property
    def uses_oauth(self) -> bool:
        """True, wenn ServiceNow per OAuth statt Basic Auth angesprochen wird."""
        return self.SNOW_AUTH_MODE.lower() == OAUTH_AUTH_MODE

    @property
    def snow_base_url(self) -> str:
        """Instanz-URL ohne abschliessenden Schraegstrich."""
        return self.SNOW_INSTANCE_URL.rstrip("/")

    @field_validator(
        "MONDOO_API_KEY",
        "MONDOO_WEBHOOK_SIGNING_SECRET",
        "MONDOO_WEBHOOK_AUTH_HEADER_VALUE",
        "SNOW_PASSWORD",
        "SNOW_CLIENT_SECRET",
    )
    @classmethod
    def _reject_unresolved_keyvault(
        cls, value: SecretStr, info: ValidationInfo
    ) -> SecretStr:
        if value.get_secret_value().startswith(UNRESOLVED_KEYVAULT_MARKER):
            raise ValueError(
                f"{info.field_name} enthaelt eine nicht aufgeloeste "
                f"Key-Vault-Referenz. Pruefen: Managed Identity der App Service "
                f"aktiviert, Rolle 'Key Vault Secrets User' vergeben, "
                f"Secret-Name korrekt."
            )
        return value

    @field_validator(
        "MONDOO_WEBHOOK_SIGNING_SECRET", "MONDOO_WEBHOOK_AUTH_HEADER_VALUE"
    )
    @classmethod
    def _strip_surrounding_whitespace(cls, value: SecretStr) -> SecretStr:
        # HTTP-Headerwerte haben nie Whitespace am Rand; ein beim Einfuegen in den
        # Key Vault mitkopierter Zeilenumbruch wuerde sonst nie uebereinstimmen.
        return SecretStr(value.get_secret_value().strip())

    @field_validator("MONDOO_WEBHOOK_AUTH_HEADER")
    @classmethod
    def _require_header_name(cls, value: str) -> str:
        # Die Meldung nennt den Wert nicht: steht hier versehentlich der Token,
        # darf er nicht im Log landen.
        if not HEADER_NAME_PATTERN.fullmatch(value):
            raise ValueError(
                "MONDOO_WEBHOOK_AUTH_HEADER ist der Name des Headers (z. B. "
                "Authorization), kein Wert. 'Bearer <token>' gehoert nach "
                "MONDOO_WEBHOOK_AUTH_HEADER_VALUE."
            )
        return value

    @field_validator("MONDOO_WEBHOOK_SIGNING_SECRET")
    @classmethod
    def _require_standard_webhooks_secret(cls, value: SecretStr) -> SecretStr:
        decode_signing_secret(value.get_secret_value())
        return value

    @model_validator(mode="after")
    def _check_required_secrets(self) -> "Settings":
        missing = [
            name
            for name in (
                "MONDOO_API_KEY",
                "MONDOO_WEBHOOK_AUTH_HEADER_VALUE",
                "SNOW_PASSWORD",
            )
            if not getattr(self, name).get_secret_value()
        ]
        if missing:
            raise ValueError(f"Pflicht-Geheimwerte sind leer: {', '.join(missing)}")

        if self.uses_oauth:
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

    def secret_values(self) -> list[str]:
        """Alle gesetzten Geheimwerte im Klartext, fuer die Log-Maskierung."""
        return [
            value
            for value in (
                self.MONDOO_API_KEY.get_secret_value(),
                self.MONDOO_WEBHOOK_SIGNING_SECRET.get_secret_value(),
                self.MONDOO_WEBHOOK_AUTH_HEADER_VALUE.get_secret_value(),
                self.SNOW_PASSWORD.get_secret_value(),
                self.SNOW_CLIENT_SECRET.get_secret_value(),
            )
            if value
        ]


# Pflichtwerte kommen aus der Umgebung; mypy kennt pydantic-settings nicht.
settings = Settings()  # type: ignore[call-arg]
