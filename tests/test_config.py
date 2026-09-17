"""Startverhalten der Konfiguration bei fehlenden Umgebungsvariablen."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

from pydantic import SecretStr

import tests  # noqa: F401  (Dummy-Umgebung)
from app.core.config import Settings

ROOT = Path(__file__).resolve().parent.parent
SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.geheimes-signatur-ende-4711"


class SettingsStartupTest(unittest.TestCase):
    def test_missing_variables_are_named_without_leaking_secrets(self) -> None:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(ROOT),
            "APP_ENV_FILE": str(ROOT / "tests" / "does-not-exist.env"),
            "MONDOO_API_KEY": SECRET,
        }
        result = subprocess.run(
            [sys.executable, "-c", "import app.core.config"],
            cwd=ROOT / "tests",
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SNOW_INSTANCE_URL", result.stderr)
        self.assertIn("SNOW_AUTH_MODE", result.stderr)
        self.assertNotIn("signatur-ende-4711", result.stderr)
        self.assertNotIn("eyJhb", result.stderr)

    def test_invalid_signing_secret_fails_start_without_leaking_it(self) -> None:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(ROOT),
            "APP_ENV_FILE": str(ROOT / "tests" / ".env.test"),
            "MONDOO_WEBHOOK_SIGNING_SECRET": "kein-whsec-geheimwert-4711",
        }
        result = subprocess.run(
            [sys.executable, "-c", "import app.core.config"],
            cwd=ROOT / "tests",
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MONDOO_WEBHOOK_SIGNING_SECRET", result.stderr)
        self.assertIn("whsec_", result.stderr)
        self.assertNotIn("geheimwert-4711", result.stderr)


class WebhookSecretNormalizationTest(unittest.TestCase):
    def test_surrounding_whitespace_is_removed(self) -> None:
        signing_secret = os.environ["MONDOO_WEBHOOK_SIGNING_SECRET"]
        configured = Settings(  # type: ignore[call-arg]
            MONDOO_WEBHOOK_AUTH_HEADER_VALUE=SecretStr("  Bearer token-mit-umbruch \n"),
            MONDOO_WEBHOOK_SIGNING_SECRET=SecretStr(f"{signing_secret}\n"),
        )
        self.assertEqual(
            configured.MONDOO_WEBHOOK_AUTH_HEADER_VALUE.get_secret_value(),
            "Bearer token-mit-umbruch",
        )
        self.assertEqual(
            configured.MONDOO_WEBHOOK_SIGNING_SECRET.get_secret_value(), signing_secret
        )


if __name__ == "__main__":
    unittest.main()
