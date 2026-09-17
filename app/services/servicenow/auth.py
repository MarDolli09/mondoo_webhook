"""Anmeldung an einer ServiceNow-Instanz per OAuth (Password Grant) oder Basic Auth."""

import asyncio
import time
from typing import Optional

import httpx

from app.core.config import settings
from app.core.exceptions import ServiceNowAuthError
from app.core.logging import logger
from app.services.servicenow.constants import (
    PATH_OAUTH_TOKEN,
    TOKEN_EXPIRY_MARGIN_SECONDS,
)

__all__ = ["ServiceNowAuth"]

DEFAULT_TOKEN_LIFETIME_SECONDS = 1800.0


class ServiceNowAuth:
    """Authentifizierung gegenueber genau einer Instanz; haelt deren OAuth-Token.

    Eine Instanz wird pro Anwendung im Lifespan erzeugt und von allen Requests
    geteilt, damit das Token wiederverwendet wird.
    """

    def __init__(self, http_client: httpx.AsyncClient, base_url: str) -> None:
        self._http_client = http_client
        self._base_url = base_url
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        """Basis-URL der Instanz, zu der das Token gehoert."""
        return self._base_url

    @property
    def uses_oauth(self) -> bool:
        """True im OAuth-Modus, False bei Basic Auth."""
        return settings.uses_oauth

    def basic_auth(self) -> Optional[httpx.BasicAuth]:
        """httpx-Auth-Objekt fuer Basic Auth, ``None`` im OAuth-Modus."""
        if self.uses_oauth:
            return None
        return httpx.BasicAuth(
            settings.SNOW_USER, settings.SNOW_PASSWORD.get_secret_value()
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
        data = {
            "grant_type": "password",
            "client_id": settings.SNOW_CLIENT_ID,
            "client_secret": settings.SNOW_CLIENT_SECRET.get_secret_value(),
            "username": settings.SNOW_USER,
            "password": settings.SNOW_PASSWORD.get_secret_value(),
        }
        try:
            response = await self._http_client.post(
                f"{self._base_url}{PATH_OAUTH_TOKEN}",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ServiceNowAuthError(
                f"Verbindungsfehler beim OAuth-Handshake: {exc}"
            ) from exc

        if response.status_code != 200:
            raise ServiceNowAuthError(
                f"OAuth Token-Generierung fehlgeschlagen ({response.status_code})",
                status_code=401 if response.status_code == 401 else 502,
            )

        body = response.json()
        token = body.get("access_token")
        if not token:
            raise ServiceNowAuthError("OAuth-Antwort enthaelt kein access_token")

        return token, float(body.get("expires_in", DEFAULT_TOKEN_LIFETIME_SECONDS))
