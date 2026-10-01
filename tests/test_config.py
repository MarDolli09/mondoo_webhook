"""Startverhalten der Konfiguration bei fehlenden Umgebungsvariablen."""

import os
import subprocess
import sys
import unittest

from pydantic import SecretStr

import tests  # noqa: F401  (Dummy-Umgebung, vor jedem app-Import)
from app.core.config import Settings
from tests import ROOT_DIR, isolated_env

SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.geheimes-signatur-ende-4711"
TEST_ENV_FILE = str(ROOT_DIR / "tests" / ".env.test")


def start_config(**env: str) -> "subprocess.CompletedProcess[str]":
    """Importiert ``app.core.config`` in einem frischen Prozess mit genau ``env``."""
    return subprocess.run(
        [sys.executable, "-c", "import app.core.config"],
        cwd=ROOT_DIR / "tests",
        env=isolated_env(**env),
        capture_output=True,
        text=True,
        check=False,
    )


class SettingsStartupTest(unittest.TestCase):
    def test_missing_variables_are_named_without_leaking_secrets(self) -> None:
        result = start_config(
            APP_ENV_FILE=str(ROOT_DIR / "tests" / "does-not-exist.env"),
            MONDOO_API_KEY=SECRET,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SNOW_INSTANCE_URL", result.stderr)
        self.assertIn("SNOW_AUTH_MODE", result.stderr)
        self.assertNotIn("signatur-ende-4711", result.stderr)
        self.assertNotIn("eyJhb", result.stderr)

    def test_invalid_signing_secret_fails_start_without_leaking_it(self) -> None:
        result = start_config(
            APP_ENV_FILE=TEST_ENV_FILE,
            MONDOO_WEBHOOK_SIGNING_SECRET="kein-whsec-geheimwert-4711",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MONDOO_WEBHOOK_SIGNING_SECRET", result.stderr)
        self.assertIn("whsec_", result.stderr)
        self.assertNotIn("geheimwert-4711", result.stderr)

    def test_token_in_header_name_setting_fails_start_without_leaking_it(self) -> None:
        result = start_config(
            APP_ENV_FILE=TEST_ENV_FILE,
            MONDOO_WEBHOOK_AUTH_HEADER="Bearer geheimes-token-4711",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MONDOO_WEBHOOK_AUTH_HEADER_VALUE", result.stderr)
        self.assertNotIn("geheimes-token-4711", result.stderr)

    def test_instance_url_with_path_fails_start(self) -> None:
        for url in (
            "https://instanz.service-now.com/oauth_token.do",
            "http://instanz.service-now.com",
            "instanz.service-now.com",
        ):
            result = start_config(APP_ENV_FILE=TEST_ENV_FILE, SNOW_INSTANCE_URL=url)
            with self.subTest(url):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ohne Pfad wie /oauth_token.do", result.stderr)

    def test_servicenow_settings_are_checked_at_start(self) -> None:
        invalid = {
            "SNOW_CATALOG_ITEM_SYS_ID": ("", "sys_id des"),
            "SNOW_AUTH_MODE": ("kerberos", "SNOW_AUTH_MODE muss"),
            "SNOW_USER": ("  ", "SNOW_USER darf nicht leer sein"),
        }
        for name, (value, expected_hint) in invalid.items():
            result = start_config(APP_ENV_FILE=TEST_ENV_FILE, **{name: value})
            with self.subTest(name):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertIn(expected_hint, result.stderr)

    def test_unknown_log_level_fails_start(self) -> None:
        result = start_config(APP_ENV_FILE=TEST_ENV_FILE, LOG_LEVEL="verbose")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LOG_LEVEL muss einer von DEBUG, INFO", result.stderr)


class LogLevelTest(unittest.TestCase):
    def test_default_is_info_and_case_is_ignored(self) -> None:
        self.assertEqual(Settings.model_fields["LOG_LEVEL"].default, "INFO")
        configured = Settings(LOG_LEVEL=" debug ")  # type: ignore[call-arg]
        self.assertEqual(configured.LOG_LEVEL, "DEBUG")


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
