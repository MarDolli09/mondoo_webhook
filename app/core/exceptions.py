"""Ausnahmen des Webhooks mit HTTP-Statuscode und Meldungspraefix."""

from typing import Optional

__all__ = [
    "CatalogOrderError",
    "ConfigurationError",
    "InvalidSecretKeyError",
    "MondooAPIError",
    "MondooGraphQLError",
    "PaginationLimitExceededError",
    "PayloadParsingError",
    "RequestItemNotFoundError",
    "SearchBudgetExceededError",
    "ServiceNowAPIError",
    "ServiceNowAuthError",
    "WebhookError",
]


class WebhookError(Exception):
    """Basisklasse aller Projektausnahmen."""

    status_code: int = 400
    prefix: str = ""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        self.message = f"{self.prefix}{message}" if self.prefix else message
        self.status_code = status_code if status_code is not None else self.status_code
        # Ohne diesen Aufruf bleibt Exception.args leer und str(exc) liefert "".
        super().__init__(self.message)


# ---------------------------------------------------------------------- #
# Konfiguration und Eingang
# ---------------------------------------------------------------------- #


class ConfigurationError(WebhookError):
    """Die Anwendung ist nicht lauffaehig konfiguriert."""

    status_code = 500
    prefix = "Konfigurationsfehler: "


class InvalidSecretKeyError(WebhookError):
    """Der Secret Key im Webhook-Pfad stimmt nicht.

    Antwortet bewusst mit 404 statt 401, damit die Existenz des Endpunkts
    nicht bestaetigt wird.
    """

    status_code = 404

    def __init__(self, message: str = "Endpoint not found") -> None:
        super().__init__(message)


class PayloadParsingError(WebhookError):
    """Der eingehende Payload hat nicht die erwartete Struktur."""

    status_code = 422
    prefix = "Fehler beim Parsen des Payloads: "


# ---------------------------------------------------------------------- #
# Mondoo GraphQL
# ---------------------------------------------------------------------- #


class MondooAPIError(WebhookError):
    """Kommunikation mit der Mondoo GraphQL-Schnittstelle fehlgeschlagen."""

    status_code = 502
    prefix = "Mondoo API Kommunikation fehlgeschlagen: "


class MondooGraphQLError(MondooAPIError):
    """GraphQL meldet einen Fehler im Rumpf einer HTTP-200-Antwort.

    Betrifft sowohl das errors-Array als auch die Fehlertypen der
    Findings-Union (RequestError, NotFoundError).
    """


class PaginationLimitExceededError(MondooAPIError):
    """Die Suche hat die zulaessige Seitenzahl ueberschritten."""

    def __init__(self, max_pages: int) -> None:
        super().__init__(f"Paginierungslimit von {max_pages} Seiten ueberschritten.")


class SearchBudgetExceededError(MondooAPIError):
    """Das Zeitbudget der Suche ist erschoepft.

    Kein Fehlerfall im engeren Sinn: Die Anreicherung ist optional, der Befund
    wird ohne CVSS-Wert weiterverarbeitet. Die Ausnahme dient dazu, die
    Suchschleife kontrolliert zu verlassen, und wird vom Aufrufer gefangen.
    """

    def __init__(self, seconds: float, pages: int) -> None:
        super().__init__(f"Zeitbudget von {seconds}s nach {pages} Seiten erschoepft.")


# ---------------------------------------------------------------------- #
# ServiceNow REST
# ---------------------------------------------------------------------- #


class ServiceNowAPIError(WebhookError):
    """Kommunikation mit der ServiceNow REST-Schnittstelle fehlgeschlagen."""

    status_code = 502
    prefix = "ServiceNow API Kommunikation fehlgeschlagen: "


class ServiceNowAuthError(ServiceNowAPIError):
    """Anmeldung oder Tokenbeschaffung fehlgeschlagen."""

    status_code = 401


class CatalogOrderError(ServiceNowAPIError):
    """order_now hat kein verwertbares Ergebnis geliefert."""


class RequestItemNotFoundError(ServiceNowAPIError):
    """Zum erzeugten Request liess sich kein RITM aufloesen.

    Deutet in aller Regel darauf hin, dass am Katalogformular kein Workflow
    hinterlegt ist.
    """

    status_code = 404
