"""Auswertung des Mondoo-Befundtexts: Ticket-Link, CVE, Risiko und Titel."""

import html
import re
from typing import Optional

__all__ = [
    "extract_cve",
    "extract_risk_from_summary",
    "extract_ticket_url",
    "sanitize_url",
    "strip_asset_suffix",
    "strip_mitigate_phrase",
]

TICKET_URL_PATTERN = re.compile(
    r"You can find all details for this ticket in \[?Mondoo\]?\((https?://[^\)]+)\)",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"https?://[^\s\",<>\)]+")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# "[HIGH] Mitigate vulnerability CVE-…" bzw. "[MEDIUM] Mitigate advisory …";
# Fehlkonfigurationen beginnen nie so und bleiben unveraendert.
MITIGATE_PHRASE_PATTERN = re.compile(
    r"^\s*(\[[A-Z]+\]\s*)?Mitigate\s+(?:vulnerability|advisory)\s+", re.IGNORECASE
)
# Mondoo haengt das Asset immer ans Ende: "… on SUBVWBN", "… on multiple assets"
ASSET_SUFFIX_SEPARATOR = " on "

_RATINGS = r"CRITICAL|HIGH|MEDIUM|LOW|NONE"

# V2-Format: "The combined risk is **CRITICAL** (99/100)"
RISK_SENTENCE_PATTERN = re.compile(
    rf"combined risk is\s*\**\s*({_RATINGS})\s*\**\s*"
    rf"(?:\(\s*(\d{{1,3}})\s*/\s*100\s*\))?",
    re.IGNORECASE,
)
# V1-Format: Scoring-Tabelle mit "|Risk|CRITICAL|" und "|Risk value|99 / 100|"
RISK_TABLE_PATTERN = re.compile(
    rf"\|\s*Risk\s*\|\s*\**\s*({_RATINGS})\b", re.IGNORECASE
)
RISK_VALUE_PATTERN = re.compile(
    r"\|\s*Risk value\s*\|\s*(\d{1,3})\s*/\s*100", re.IGNORECASE
)
# Letzter Ausweg: irgendeine Risikoangabe der Form "**HIGH** (72/100)"
RISK_LOOSE_PATTERN = re.compile(
    rf"\*\*({_RATINGS})\*\*\s*\(\s*(\d{{1,3}})\s*/\s*100\s*\)", re.IGNORECASE
)


def sanitize_url(raw_url: str) -> str:
    """Entfernt HTML-Entities und alles nach dem ersten Zeichen, das keine URL ist."""
    if not raw_url:
        return ""
    unescaped = html.unescape(raw_url)
    match = URL_PATTERN.search(unescaped)
    return match.group(0).strip() if match else unescaped.strip("\"' ")


def extract_ticket_url(description: str) -> str:
    """Link auf das Mondoo-Ticket aus dem Fusstext der Beschreibung."""
    match = TICKET_URL_PATTERN.search(description)
    return sanitize_url(match.group(1)) if match else ""


def extract_cve(title: str, default: str) -> str:
    """Erste CVE-Kennung im Titel in Grossschreibung, sonst ``default``."""
    match = CVE_PATTERN.search(title)
    return match.group(0).upper() if match else default


def extract_risk_from_summary(description: str) -> tuple[Optional[str], Optional[str]]:
    """Mondoo Risk Rating und Score (0-100) aus der AI-Summary.

    Unterstuetzt das V2-Satzformat, die V1-Scoring-Tabelle und als Rueckfall
    eine lose Angabe wie ``**HIGH** (72/100)``.
    """
    if not description:
        return None, None

    match = RISK_SENTENCE_PATTERN.search(description)
    if match:
        return match.group(1).upper(), match.group(2)

    match = RISK_TABLE_PATTERN.search(description)
    if match:
        rating = match.group(1).upper()
        value_match = RISK_VALUE_PATTERN.search(description)
        return rating, value_match.group(1) if value_match else None

    match = RISK_LOOSE_PATTERN.search(description)
    if match:
        return match.group(1).upper(), match.group(2)

    return None, None


def strip_mitigate_phrase(title: str) -> str:
    """Entfernt "Mitigate vulnerability/advisory" hinter dem Schweregrad-Tag.

    ``[HIGH] Mitigate vulnerability CVE-2026-1 on X`` wird zu
    ``[HIGH] CVE-2026-1 on X``; das Tag bleibt erhalten.
    """

    def keep_severity_tag(match: "re.Match[str]") -> str:
        tag = (match.group(1) or "").strip()
        return f"{tag} " if tag else ""

    return MITIGATE_PHRASE_PATTERN.sub(keep_severity_tag, title, count=1).strip()


def strip_asset_suffix(title: str) -> str:
    """Entfernt das Asset am Ende des Titels samt dem "on" davor.

    Getrennt wird am letzten " on ", damit Pruefungen wie "Ensure 'Turn on …'
    is set to …" vollstaendig bleiben.
    """
    head, separator, _ = title.rpartition(ASSET_SUFFIX_SEPARATOR)
    return head.rstrip() if separator and head.strip() else title
