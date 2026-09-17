"""Mondoo-Bezeichner: MRNs, Space-IDs, Identitaeten und App-Links."""

import re
from collections.abc import Iterable
from typing import Optional
from urllib.parse import quote

__all__ = [
    "case_app_url",
    "count_referenced_assets",
    "extract_space_id",
    "is_automated_identity",
    "space_scope_mrn",
]

MONDOO_APP_URL = "https://app.mondoo.com"
SPACE_SCOPE_MRN_PREFIX = "//captain.api.mondoo.app/spaces/"
SPACE_ID_PATTERN = re.compile(r"/spaces/([^/]+)")
ASSET_SCOPE_MRN_PATTERN = re.compile(r"/spaces/[^/]+/assets/([^/]+)")
HUMAN_USER_MRN_PATTERN = re.compile(r"/users/[^/]+$")
SYSTEM_IDENTITY_SUFFIXES = ("/system",)
SYSTEM_IDENTITY_MARKERS = ("/serviceaccounts/", "/identity/user/system")


def extract_space_id(mrn: str) -> Optional[str]:
    """Space-ID aus einer beliebigen Mondoo-MRN, z. B. ``ownerMrn``."""
    match = SPACE_ID_PATTERN.search(mrn)
    return match.group(1) if match else None


def space_scope_mrn(space_id: str) -> str:
    """Scope-MRN eines Space, nutzbar als GraphQL-Suchbereich."""
    return f"{SPACE_SCOPE_MRN_PREFIX}{space_id}"


def count_referenced_assets(scope_mrns: Iterable[str]) -> int:
    """Anzahl verschiedener Assets, auf die Asset-Scope-MRNs verweisen."""
    asset_ids = set()
    for scope_mrn in scope_mrns:
        match = ASSET_SCOPE_MRN_PATTERN.search(scope_mrn)
        if match:
            asset_ids.add(match.group(1))
    return len(asset_ids)


def is_automated_identity(created_by: str) -> bool:
    """True, wenn ``createdBy`` keinen menschlichen Mondoo-Benutzer bezeichnet.

    Leere Werte, System-Identitaeten und Service-Accounts gelten als
    automatisch erzeugt (z. B. Regressions-Tickets).
    """
    if not created_by:
        return True
    lowered = created_by.lower()
    if lowered.endswith(SYSTEM_IDENTITY_SUFFIXES):
        return True
    if any(marker in lowered for marker in SYSTEM_IDENTITY_MARKERS):
        return True
    return HUMAN_USER_MRN_PATTERN.search(created_by) is None


def case_app_url(case_mrn: str, space_id: str) -> str:
    """Link auf einen Case in der Mondoo-Weboberflaeche (Region EU)."""
    quoted_mrn = quote(case_mrn, safe="")
    return f"{MONDOO_APP_URL}/space/tickets/{quoted_mrn}?region=EU&spaceId={space_id}"
