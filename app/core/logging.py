import logging
import sys


def mask_secret(text: str, secret: str) -> str:
    if not secret or not text:
        return text
    return text.replace(secret, "***MASKED_SECRET***")


class SecretMaskingFormatter(logging.Formatter):
    def __init__(self, fmt: str = None, datefmt: str = None, secret: str = ""):
        super().__init__(fmt, datefmt)
        self.secret = secret

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        if self.secret:
            return mask_secret(original, self.secret)
        return original


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("mondoo-receiver")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        from app.core.config import settings
        secret_key = getattr(settings, "WEBHOOK_SECRET_KEY", "")

        handler = logging.StreamHandler(sys.stdout)
        formatter = SecretMaskingFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            secret=secret_key,
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()