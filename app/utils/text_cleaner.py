import html
import re
from typing import Dict, List, Optional, Tuple

HTML_EMOJI_PATTERN = re.compile(r"<[^>]+>|[❌✅⚠️🔴🟢]")
MARKDOWN_FMT_PATTERN = re.compile(r"(\*{1,2}|`)(.*?)\1")
TICKET_URL_PATTERN = re.compile(
    r"You can find all details for this ticket in \[?Mondoo\]?\((https?://[^\)]+)\)",
    re.IGNORECASE,
)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SPACE_ID_PATTERN = re.compile(r"/spaces/([^/]+)")
MD_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\((https?://[^\)]+)\)")
SCOPE_MRN_PATTERN = re.compile(r"/spaces/([^/]+)/assets/([^/]+)")
INVENTORY_ASSET_ID_PATTERN = re.compile(r"/space/inventory/([^?/#]+)")
TITLE_SINGLE_ASSET_PATTERN = re.compile(r"\s+on\s+([a-zA-Z0-9\-_]+)\s*$", re.IGNORECASE)

_RATINGS = r"CRITICAL|HIGH|MEDIUM|LOW|NONE"

# V2-Format: "The combined risk is **CRITICAL** (99/100)"
RISK_SENTENCE_PATTERN = re.compile(
    rf"combined risk is\s*\**\s*({_RATINGS})\s*\**\s*(?:\(\s*(\d{{1,3}})\s*/\s*100\s*\))?",
    re.IGNORECASE,
)
# V1-Format: Scoring-Tabelle mit "|Risk|CRITICAL|" und "|Risk value|99 / 100|"
RISK_TABLE_PATTERN = re.compile(rf"\|\s*Risk\s*\|\s*\**\s*({_RATINGS})\b", re.IGNORECASE)
RISK_VALUE_PATTERN = re.compile(r"\|\s*Risk value\s*\|\s*(\d{1,3})\s*/\s*100", re.IGNORECASE)
# Letzter Ausweg: irgendeine Risikoangabe der Form "**HIGH** (72/100)"
RISK_LOOSE_PATTERN = re.compile(
    rf"\*\*({_RATINGS})\*\*\s*\(\s*(\d{{1,3}})\s*/\s*100\s*\)", re.IGNORECASE
)


def clean_markdown(text: str) -> str:
    if not isinstance(text, str):
        return text
    clean = HTML_EMOJI_PATTERN.sub("", html.unescape(text))
    clean = MARKDOWN_FMT_PATTERN.sub(r"\2", clean)
    return clean.strip()


def extract_cve(title: str, default: str) -> str:
    match = CVE_PATTERN.search(title)
    return match.group(0).upper() if match else default


def extract_ticket_url(description: str) -> str:
    match = TICKET_URL_PATTERN.search(description)
    return sanitize_url(match.group(1)) if match else ""


def sanitize_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    unescaped = html.unescape(raw_url)
    match = re.search(r"https?://[^\s\",<>\)]+", unescaped)
    return match.group(0).strip() if match else unescaped.strip('\"\' ')


def extract_space_id(owner_mrn: str) -> Optional[str]:
    match = SPACE_ID_PATTERN.search(owner_mrn)
    return match.group(1) if match else None


def extract_single_asset_from_title(title: str) -> Optional[str]:
    match = TITLE_SINGLE_ASSET_PATTERN.search(title)
    if match:
        candidate = match.group(1).strip()
        if candidate.lower() not in ["assets", "multiple"]:
            return candidate
    return None


def extract_risk_from_summary(description: str) -> Tuple[Optional[str], Optional[str]]:
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


def extract_asset_table_from_markdown(description: str) -> List[Dict[str, str]]:
    assets: List[Dict[str, str]] = []
    seen = set()

    for line in description.splitlines():
        line_str = line.strip()
        if not line_str.startswith("|") or "|-|-|-|" in line_str or "|Status|" in line_str:
            continue

        cells = [c.strip() for c in line_str.split("|")[1:-1]]
        if len(cells) < 2:
            continue

        for idx, cell in enumerate(cells):
            if link_match := MD_LINK_PATTERN.search(cell):
                name = link_match.group(1).strip()
                # Direkte Sanitisierung der Asset-URL
                url = sanitize_url(link_match.group(2))

                platform = ""
                if idx + 1 < len(cells):
                    platform = clean_markdown(cells[idx + 1])

                if (name, url) not in seen:
                    seen.add((name, url))
                    assets.append({
                        "asset_name_name": name,
                        "asset_name_url": url,
                        "platform": platform
                    })
                break

    return assets


def build_asset_index(description: str) -> Dict[str, Dict[str, str]]:

    index: Dict[str, Dict[str, str]] = {}
    for entry in extract_asset_table_from_markdown(description):
        match = INVENTORY_ASSET_ID_PATTERN.search(entry["asset_name_url"])
        if not match:
            continue
        # Der erste Treffer gewinnt: die KB-Tabellen stehen vor der
        # Sammeltabelle "No packages found" und tragen die genauere Plattform.
        index.setdefault(match.group(1), entry)
    return index