"""Tests mit Dummy-Umgebung; muss vor jedem Import aus ``app`` geladen werden."""

import logging
import os
from pathlib import Path

__all__ = [
    "DUMMY_ENV_FILE",
    "FIXTURES",
    "ROOT_DIR",
    "isolated_env",
    "load_dummy_environment",
]

TESTS_DIR = Path(__file__).resolve().parent
ROOT_DIR = TESTS_DIR.parent
DUMMY_ENV_FILE = TESTS_DIR / ".env.test"
FIXTURES = TESTS_DIR / "fixtures"

# Basisvariablen fuer Unterprozesse. Ohne SYSTEMROOT scheitert unter Windows die
# Winsock-Initialisierung beim Import von asyncio (WinError 10106); ohne
# SYSTEMDRIVE/PROGRAMDATA legt Windows Caches unter "%SystemDrive%" im
# Arbeitsverzeichnis an. Unter Linux fehlen diese Namen und werden uebersprungen.
SUBPROCESS_ENV_KEYS = (
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "PROGRAMDATA",
    "ALLUSERSPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "TEMP",
    "TMP",
)


def isolated_env(**overrides: str) -> dict[str, str]:
    """Umgebung fuer einen Unterprozess: Basisvariablen plus ``overrides``.

    Werte aus ``.env.test`` werden bewusst nicht vererbt; jeder Test legt seine
    Konfiguration selbst fest.
    """
    env = {key: os.environ[key] for key in SUBPROCESS_ENV_KEYS if key in os.environ}
    env["PYTHONPATH"] = str(ROOT_DIR)
    env.update(overrides)
    return env


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
