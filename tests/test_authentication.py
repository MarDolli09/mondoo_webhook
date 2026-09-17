"""Standard-Webhooks-Signaturpruefung gegen den Referenzvektor der Spezifikation."""

import unittest

import tests  # noqa: F401  (Dummy-Umgebung)
from app.core.webhook_signature import (
    SignatureVerificationError,
    StandardWebhookVerifier,
    decode_signing_secret,
    sign_delivery,
)

# Referenzbeispiel der Standard-Webhooks-/Svix-Dokumentation
SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
WEBHOOK_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
TIMESTAMP = 1614265330
BODY = b'{"test": 2432232314}'
SIGNATURE = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="


def headers(signature: str = SIGNATURE, timestamp: str = str(TIMESTAMP)) -> dict:
    return {
        "webhook-id": WEBHOOK_ID,
        "webhook-timestamp": timestamp,
        "webhook-signature": signature,
    }


class StandardWebhookVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = StandardWebhookVerifier(SECRET, tolerance_seconds=300)

    def test_reference_vector(self) -> None:
        key = decode_signing_secret(SECRET)
        self.assertEqual(sign_delivery(key, WEBHOOK_ID, TIMESTAMP, BODY), SIGNATURE)
        self.assertEqual(
            self.verifier.verify(headers(), BODY, now=TIMESTAMP), WEBHOOK_ID
        )

    def test_any_valid_signature_in_list_is_accepted(self) -> None:
        signatures = f"v1a,aW52YWxpZA== v1,YmxhYmxh {SIGNATURE}"
        result = self.verifier.verify(headers(signatures), BODY, now=TIMESTAMP)
        self.assertEqual(result, WEBHOOK_ID)

    def test_tolerance_boundaries(self) -> None:
        self.verifier.verify(headers(), BODY, now=TIMESTAMP + 300)
        self.verifier.verify(headers(), BODY, now=TIMESTAMP - 300)
        for now in (TIMESTAMP + 301, TIMESTAMP - 301):
            with self.assertRaises(SignatureVerificationError):
                self.verifier.verify(headers(), BODY, now=now)

    def test_rejections(self) -> None:
        cases = {
            "veraenderter Body": (headers(), BODY + b" "),
            "nur asymmetrische Signatur": (headers("v1a,aW52YWxpZA=="), BODY),
            "falsche Signatur": (headers("v1,YmxhYmxh"), BODY),
            "Zeitstempel keine Zahl": (headers(timestamp="gestern"), BODY),
            "Nicht-ASCII in der Signatur": (headers("v1,äöü"), BODY),
            "Header fehlen": ({}, BODY),
        }
        for label, (request_headers, body) in cases.items():
            with self.subTest(label), self.assertRaises(SignatureVerificationError):
                self.verifier.verify(request_headers, body, now=TIMESTAMP)

    def test_secret_format(self) -> None:
        for invalid in (
            "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
            "whsec_",
            "whsec_!!keinb64",
        ):
            with self.subTest(invalid), self.assertRaises(ValueError):
                decode_signing_secret(invalid)


if __name__ == "__main__":
    unittest.main()
