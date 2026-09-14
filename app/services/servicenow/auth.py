import asyncio
import time
from typing import Dict, Optional
 
import httpx
 
from app.core.config import settings
from app.core.exceptions import ServiceNowAuthError
from app.core.logging import logger
 
from .constants import PATH_OAUTH_TOKEN, TOKEN_EXPIRY_MARGIN_SECONDS
 
 
class ServiceNowAuth:
    _token: Optional[str] = None
    _token_expires_at: float = 0.0
    _lock = asyncio.Lock()
 
    def __init__(self, http_client: httpx.AsyncClient, base_url: str):
        self.http_client = http_client
        self.base_url = base_url
 
    # ------------------------------------------------------------------ #
    # Modus
    # ------------------------------------------------------------------ #
 
    @property
    def uses_oauth(self) -> bool:
        return settings.SNOW_AUTH_MODE.lower() == "oauth"
 
    def basic_auth(self) -> Optional[httpx.BasicAuth]:
        """httpx-Auth-Objekt fuer Basic Auth, None im OAuth-Modus."""
        if self.uses_oauth:
            return None
        return httpx.BasicAuth(settings.SNOW_USER, settings.SNOW_PASSWORD)
 
    async def headers(self, content_type: str = "application/json") -> Dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": content_type}
        if self.uses_oauth:
            headers["Authorization"] = f"Bearer {await self.token()}"
        return headers
 
    # ------------------------------------------------------------------ #
    # Token
    # ------------------------------------------------------------------ #
 
    @classmethod
    def invalidate(cls) -> None:
        cls._token = None
        cls._token_expires_at = 0.0
 
    async def token(self) -> str:
        cls = ServiceNowAuth
        if cls._token and time.monotonic() < cls._token_expires_at:
            return cls._token
 
        async with cls._lock:
            # Zweite Pruefung: waehrend des Wartens kann ein anderer Task
            # den Token bereits erneuert haben.
            if cls._token and time.monotonic() < cls._token_expires_at:
                return cls._token
 
            token, expires_in = await self._fetch_token()
            cls._token = token
            cls._token_expires_at = (
                time.monotonic() + expires_in - TOKEN_EXPIRY_MARGIN_SECONDS
            )
            logger.info("ServiceNow OAuth-Token erneuert.")
            return token
 
    async def _fetch_token(self) -> tuple[str, float]:
        data = {
            "grant_type": "password",
            "client_id": settings.SNOW_CLIENT_ID,
            "client_secret": settings.SNOW_CLIENT_SECRET,
            "username": settings.SNOW_USER,
            "password": settings.SNOW_PASSWORD,
        }
        try:
            response = await self.http_client.post(
                f"{self.base_url}{PATH_OAUTH_TOKEN}",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ServiceNowAuthError(f"Verbindungsfehler beim OAuth-Handshake: {exc}")
 
        if response.status_code != 200:
            raise ServiceNowAuthError(
                f"OAuth Token-Generierung fehlgeschlagen ({response.status_code})",
                status_code=401 if response.status_code == 401 else 502,
            )
 
        body = response.json()
        token = body.get("access_token")
        if not token:
            raise ServiceNowAuthError("OAuth-Antwort enthaelt kein access_token")
 
        return token, float(body.get("expires_in", 1800))