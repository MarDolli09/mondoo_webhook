"""Signaturpruefung nach der Standard-Webhooks-Spezifikation (symmetrisch, ``v1``).

Signiert wird ``<webhook-id>.<webhook-timestamp>.<body>`` mit HMAC-SHA256. Der
Schluessel ist der base64-dekodierte Teil des ``whsec_``-Secrets. Spezifikation:
https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md
"""

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping

__all__ = [
    "HEADER_ID",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "SECRET_PREFIX",
    "SignatureVerificationError",
    "StandardWebhookVerifier",
    "decode_signing_secret",
    "sign_delivery",
]

SECRET_PREFIX = "whsec_"
SIGNATURE_VERSION = "v1"
HEADER_ID = "webhook-id"
HEADER_TIMESTAMP = "webhook-timestamp"
HEADER_SIGNATURE = "webhook-signature"


class SignatureVerificationError(Exception):
    """Die Zustellung ist nicht gueltig signiert; die Meldung ist fuer das Log."""


def decode_signing_secret(secret: str) -> bytes:
    """HMAC-Schluessel aus einem ``whsec_``-Secret.

    Raises:
        ValueError: Praefix fehlt, der Rest ist kein base64 oder leer. Die
            Meldung enthaelt den Secret-Wert nicht.
    """
    if not secret.startswith(SECRET_PREFIX):
        raise ValueError(f"Signing Secret muss mit '{SECRET_PREFIX}' beginnen.")
    try:
        key = base64.b64decode(secret[len(SECRET_PREFIX) :], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"Signing Secret ist nach '{SECRET_PREFIX}' kein gueltiges base64."
        ) from exc
    if not key:
        raise ValueError("Signing Secret ist leer.")
    return key


def sign_delivery(key: bytes, webhook_id: str, timestamp: int, body: bytes) -> str:
    """Signatur einer Zustellung im Header-Format ``v1,<base64>``."""
    signed_content = f"{webhook_id}.{timestamp}.".encode() + body
    digest = hmac.new(key, signed_content, hashlib.sha256).digest()
    return f"{SIGNATURE_VERSION},{base64.b64encode(digest).decode()}"


class StandardWebhookVerifier:
    """Prueft die ``webhook-*``-Header einer Zustellung gegen Body und Secret."""

    def __init__(self, secret: str, tolerance_seconds: int) -> None:
        self._key = decode_signing_secret(secret)
        self._tolerance_seconds = tolerance_seconds

    def verify(self, headers: Mapping[str, str], body: bytes, now: float) -> str:
        """Liefert die ``webhook-id`` einer gueltig signierten, aktuellen Zustellung.

        Der Zeitstempel darf hoechstens ``tolerance_seconds`` von ``now``
        abweichen; das verhindert das Wiedereinspielen alter Zustellungen.

        Raises:
            SignatureVerificationError: Header fehlen, Zeitstempel ausserhalb der
                Toleranz oder keine passende ``v1``-Signatur.
        """
        webhook_id = headers.get(HEADER_ID)
        timestamp_text = headers.get(HEADER_TIMESTAMP)
        signature_header = headers.get(HEADER_SIGNATURE)
        if not webhook_id or not timestamp_text or not signature_header:
            raise SignatureVerificationError("Signatur-Header fehlen.")

        try:
            timestamp = int(timestamp_text)
        except ValueError as exc:
            raise SignatureVerificationError(
                "webhook-timestamp ist keine Ganzzahl."
            ) from exc
        if abs(now - timestamp) > self._tolerance_seconds:
            raise SignatureVerificationError(
                f"webhook-timestamp weicht mehr als {self._tolerance_seconds}s "
                f"von der Serverzeit ab."
            )

        expected = sign_delivery(self._key, webhook_id, timestamp, body).encode()
        # Mehrere Signaturen (z. B. waehrend einer Secret-Rotation) sind durch
        # Leerzeichen getrennt; asymmetrische v1a-Signaturen werden ignoriert.
        for candidate in signature_header.split(" "):
            if candidate.startswith(f"{SIGNATURE_VERSION},") and hmac.compare_digest(
                candidate.encode(), expected
            ):
                return webhook_id
        raise SignatureVerificationError("Keine gueltige v1-Signatur.")
