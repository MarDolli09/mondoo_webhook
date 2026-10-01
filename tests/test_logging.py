"""Zeilenformat der Anwendungslogs; die Log-Alarmregel in Azure haengt daran."""

import logging
import os
import unittest

import tests  # noqa: F401  (Dummy-Umgebung)
from app.core.logging import bind_correlation_id, logger, reset_correlation_id

CORRELATION_ID = "a18f4807-1621-42a5-9f92-32ab15f9b0ac"


def format_line(level: int, message: str) -> str:
    """Formatiert einen Eintrag wie der konfigurierte Handler."""
    (handler,) = logger.handlers
    record = logger.makeRecord(logger.name, level, __file__, 1, message, (), None)
    handler.filter(record)
    return handler.format(record)


class LogFormatTest(unittest.TestCase):
    def test_line_keeps_level_marker_and_short_correlation_id(self) -> None:
        token = bind_correlation_id(CORRELATION_ID)
        try:
            line = format_line(logging.ERROR, "Abfrage abgebrochen")
        finally:
            reset_correlation_id(token)

        self.assertEqual(line, "[ERROR] [a18f4807] Abfrage abgebrochen")

    def test_line_outside_a_request_has_placeholder(self) -> None:
        line = format_line(logging.INFO, "HTTP-Client geschlossen")

        self.assertEqual(line, "[INFO] [-] HTTP-Client geschlossen")

    def test_secrets_are_masked(self) -> None:
        secret = os.environ["SNOW_PASSWORD"]

        line = format_line(logging.ERROR, f"Anmeldung mit {secret} fehlgeschlagen")

        self.assertNotIn(secret, line)
        self.assertIn("***MASKED_SECRET***", line)


if __name__ == "__main__":
    unittest.main()
