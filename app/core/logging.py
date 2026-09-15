import logging
import sys
from typing import Iterable, List
 
MASK = "***MASKED_SECRET***"
 
 
def mask_secret(text: str, secret: str) -> str:
    if not secret or not text:
        return text
    return text.replace(secret, MASK)
 
 
def mask_secrets(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        text = mask_secret(text, secret)
    return text
 
 
class SecretMaskingFormatter(logging.Formatter):
 
    def __init__(
        self,
        fmt: str = None,
        datefmt: str = None,
        secrets: Iterable[str] = (),
    ):
        super().__init__(fmt, datefmt)
        # Laengste zuerst: verhindert, dass ein kurzer Wert Teile eines
        # laengeren zerschneidet und der Rest sichtbar bleibt.
        self.secrets: List[str] = sorted({s for s in secrets if s}, key=len, reverse=True)
 
    def format(self, record: logging.LogRecord) -> str:
        return mask_secrets(super().format(record), self.secrets)
 
 
def setup_logging() -> logging.Logger:
    logger = logging.getLogger("mondoo-receiver")
    logger.setLevel(logging.INFO)
 
    if not logger.handlers:
        from app.core.config import settings
 
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            SecretMaskingFormatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                secrets=settings.secret_values(),
            )
        )
        logger.addHandler(handler)
 
    return logger
 
 
logger = setup_logging()