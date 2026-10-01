"""Logging mit Secret-Maskierung und Correlation-ID je Request."""

import logging
import sys
from collections.abc import Iterable
from contextvars import ContextVar, Token
from typing import Optional

from app.core.config import settings

__all__ = [
    "bind_correlation_id",
    "current_correlation_id",
    "logger",
    "mask_secrets",
    "reset_correlation_id",
]

LOGGER_NAME = "mondoo-receiver"
MASK = "***MASKED_SECRET***"
NO_CORRELATION_ID = "-"
# Kein eigener Zeitstempel: Azure stellt jeder Zeile einen voran. "[ERROR]"
# muss so bleiben, die Log-Alarmregel sucht danach. Von der Correlation-ID
# genuegen 8 Zeichen, um die Zeilen eines Requests zu finden; vollstaendig
# steht sie in request_completed und im Telemetriedatensatz.
LOG_FORMAT = "[%(levelname)s] [%(correlation_id).8s] %(message)s"

_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


def bind_correlation_id(correlation_id: str) -> Token[Optional[str]]:
    """Setzt die Correlation-ID fuer den laufenden Request-Kontext."""
    return _correlation_id.set(correlation_id)


def reset_correlation_id(token: Token[Optional[str]]) -> None:
    """Stellt den Zustand vor ``bind_correlation_id`` wieder her."""
    _correlation_id.reset(token)


def current_correlation_id() -> Optional[str]:
    """Correlation-ID des laufenden Requests, sofern gesetzt."""
    return _correlation_id.get()


def mask_secrets(text: str, secrets: Iterable[str]) -> str:
    """Ersetzt jedes Vorkommen der Geheimwerte in ``text`` durch eine Maske."""
    for secret in secrets:
        if secret and text:
            text = text.replace(secret, MASK)
    return text


class SecretMaskingFormatter(logging.Formatter):
    """Formatter, der Geheimwerte in der fertigen Logzeile maskiert."""

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        secrets: Iterable[str] = (),
    ) -> None:
        super().__init__(fmt, datefmt)
        # Laengste zuerst: verhindert, dass ein kurzer Wert Teile eines
        # laengeren zerschneidet und der Rest sichtbar bleibt.
        self._secrets: tuple[str, ...] = tuple(
            sorted({s for s in secrets if s}, key=len, reverse=True)
        )

    def format(self, record: logging.LogRecord) -> str:
        return mask_secrets(super().format(record), self._secrets)


class CorrelationIdFilter(logging.Filter):
    """Ergaenzt jeden Logeintrag um die Correlation-ID des Requests."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _correlation_id.get() or NO_CORRELATION_ID
        return True


def _setup_logging() -> logging.Logger:
    configured = logging.getLogger(LOGGER_NAME)
    configured.setLevel(settings.LOG_LEVEL)

    if not configured.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.addFilter(CorrelationIdFilter())
        handler.setFormatter(
            SecretMaskingFormatter(fmt=LOG_FORMAT, secrets=settings.secret_values())
        )
        configured.addHandler(handler)

    return configured


logger = _setup_logging()
