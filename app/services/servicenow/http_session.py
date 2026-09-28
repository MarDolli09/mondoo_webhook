"""Sitzungsfreie HTTP-Aufrufe gegen ServiceNow.

ServiceNow setzt bei jedem Aufruf ein Sitzungs-Cookie. Schickt ein Client es
beim naechsten Aufruf zurueck, behandelt ServiceNow den Request als Teil einer
bestehenden Sitzung und verlangt fuer schreibende Zugriffe zusaetzlich ein
CSRF-Token. Eine REST-Integration hat keines; lesende Aufrufe gelingen dann,
schreibende scheitern mit "Security constraints prevent ordering of Item".
Jeder Aufruf authentifiziert sich daher neu und sendet keine Cookies.
"""

import httpx

__all__ = ["drop_session_cookies"]


def drop_session_cookies(http_client: httpx.AsyncClient) -> None:
    """Verwirft gespeicherte Cookies vor dem naechsten Aufruf."""
    http_client.cookies.clear()
