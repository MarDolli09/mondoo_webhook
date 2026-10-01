"""Anmeldung an einer ServiceNow-Instanz per OAuth (Password Grant) oder Basic Auth."""

import asyncio
import time
from typing import Optional

import httpx

from app.core.exceptions import ServiceNowAuthError
from app.core.logging import logger
from app.services.servicenow.config import ServiceNowConfig
from app.services.servicenow.constants import (
    PATH_OAUTH_TOKEN,
    TOKEN_EXPIRY_MARGIN_SECONDS,
)
from app.services.servicenow.http_session import drop_session_cookies

__all__ = ["ServiceNowAuth"]

DEFAULT_TOKEN_LIFETIME_SECONDS = 1800.0
OAUTH_ERROR_TEXT_LIMIT = 200


class ServiceNowAuth:
    """Authentifizierung gegenueber genau einer Instanz; haelt deren OAuth-Token.

    Eine Instanz wird pro Anwendung im Lifespan erzeugt und von allen Requests
    geteilt, damit das Token wiederverwendet wird.
    """

    def __init__(
        self, http_client: httpx.AsyncClient, config: ServiceNowConfig
    ) -> None:
        self._http_client = http_client
        self._config = config
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        """Basis-URL der Instanz, zu der das Token gehoert."""
        return self._config.base_url

    @property
    def uses_oauth(self) -> bool:
        """True im OAuth-Modus, False bei Basic Auth."""
        return self._config.use_oauth

    def basic_auth(self) -> Optional[httpx.BasicAuth]:
        """httpx-Auth-Objekt fuer Basic Auth, ``None`` im OAuth-Modus."""
        if self.uses_oauth:
            return None
        return httpx.BasicAuth(
            self._config.user, self._config.password.get_secret_value()
        )

    async def headers(self, content_type: str = "application/json") -> dict[str, str]:
        """Request-Header, im OAuth-Modus inklusive Bearer-Token."""
        headers = {"Accept": "application/json", "Content-Type": content_type}
        if self.uses_oauth:
            headers["Authorization"] = f"Bearer {await self._valid_token()}"
        return headers

    def invalidate(self) -> None:
        """Verwirft das Token, etwa nach einer 401-Antwort."""
        self._token = None
        self._token_expires_at = 0.0

    async def _valid_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token

        async with self._lock:
            # Zweite Pruefung: waehrend des Wartens kann ein anderer Task
            # den Token bereits erneuert haben.
            if self._token and time.monotonic() < self._token_expires_at:
                return self._token

            token, expires_in = await self._fetch_token()
            self._token = token
            self._token_expires_at = (
                time.monotonic() + expires_in - TOKEN_EXPIRY_MARGIN_SECONDS
            )
            logger.info("ServiceNow OAuth-Token erneuert.")
            return token

    async def _fetch_token(self) -> tuple[str, float]:
        config = self._config
        data = {
            "grant_type": "password",
            "client_id": config.client_id,
            "client_secret": config.client_secret.get_secret_value(),
            "username": config.user,
            "password": config.password.get_secret_value(),
        }
        drop_session_cookies(self._http_client)
        try:
            response = await self._http_client.post(
                f"{config.base_url}{PATH_OAUTH_TOKEN}",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ServiceNowAuthError(
                f"Verbindungsfehler beim OAuth-Handshake: {exc}"
            ) from exc

        if response.status_code != 200:
            logger.error(
                f"OAuth-Token von {config.base_url} abgelehnt: HTTP "
                f"{response.status_code}, {_oauth_error_details(response)}, "
                f"Benutzer '{config.user}', Leerzeichen am Rand in: "
                f"{_credentials_with_edge_whitespace(config)}"
            )
            raise ServiceNowAuthError(
                f"OAuth Token-Generierung fehlgeschlagen ({response.status_code})",
                upstream_status=response.status_code,
            )

        try:
            body = response.json()
        except ValueError as exc:
            # Rumpf bewusst nicht ins Log: Token-Antworten koennen Geheimwerte tragen.
            logger.error(
                f"OAuth-Antwort von {config.base_url} ist kein JSON "
                f"(HTTP {response.status_code})."
            )
            raise ServiceNowAuthError(
                f"OAuth-Antwort ist kein JSON (HTTP {response.status_code})",
                upstream_status=response.status_code,
            ) from exc
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise ServiceNowAuthError("OAuth-Antwort enthaelt kein access_token")

        return token, float(body.get("expires_in", DEFAULT_TOKEN_LIFETIME_SECONDS))


def _oauth_error_details(response: httpx.Response) -> str:
    """Fehlerfelder der OAuth-Antwort von ServiceNow; enthalten keine Secrets."""
    try:
        body = response.json()
    except ValueError:
        return "Antwort ohne JSON"
    if not isinstance(body, dict):
        return "Antwort ohne Fehlerfelder"
    error = str(body.get("error", ""))[:OAUTH_ERROR_TEXT_LIMIT]
    description = str(body.get("error_description", ""))[:OAUTH_ERROR_TEXT_LIMIT]
    return f"error={error!r}, error_description={description!r}"


def _credentials_with_edge_whitespace(config: ServiceNowConfig) -> str:
    """Welche Zugangsdaten Leerzeichen/Umbrueche am Rand haben (ohne Werte).

    Genannt werden die Namen der Umgebungsvariablen, damit der Fehler im
    Key Vault bzw. in den App-Settings auffindbar ist.
    """
    credentials = {
        "SNOW_CLIENT_ID": config.client_id,
        "SNOW_CLIENT_SECRET": config.client_secret.get_secret_value(),
        "SNOW_USER": config.user,
        "SNOW_PASSWORD": config.password.get_secret_value(),
    }
    affected = [name for name, value in credentials.items() if value != value.strip()]
    return ", ".join(affected) or "keine"
