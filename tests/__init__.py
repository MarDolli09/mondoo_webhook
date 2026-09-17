"""Tests mit Dummy-Umgebung; muss vor jedem Import aus ``app`` geladen werden."""

import logging
import os
from pathlib import Path

__all__ = ["DUMMY_ENV_FILE", "FIXTURES", "load_dummy_environment"]

TESTS_DIR = Path(__file__).resolve().parent
DUMMY_ENV_FILE = TESTS_DIR / ".env.test"
FIXTURES = TESTS_DIR / "fixtures"


def load_dummy_environment() -> None:
    """Setzt alle Werte aus ``.env.test`` und blendet eine lokale ``.env`` aus."""
    os.environ["APP_ENV_FILE"] = str(DUMMY_ENV_FILE)
    for line in DUMMY_ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ[key] = value


load_dummy_environment()

# Anwendungslogs nur bei Bedarf anzeigen: TEST_LOGS=1
logging.getLogger("mondoo-receiver").disabled = not os.environ.get("TEST_LOGS")
