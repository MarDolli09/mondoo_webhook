import re
from typing import Any, Dict, Optional, Tuple
 
from app.domain.normalizer import calculate_rating_from_score, normalize_cvss_score
 
CVE_IN_MRN_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
 
# Titelfelder der Union-Typen, in Auswerte-Reihenfolge
TITLE_FIELDS = ("cveTitle", "advTitle", "pkgTitle", "chkTitle", "genTitle")
 
# CVSS-Objekte der Union-Typen. CheckFinding und GenericFinding haben keines -
# Fehlkonfigurationen tragen kein CVSS, sondern nur ein Risk Rating.
CVSS_FIELDS = ("cveCvss", "advCvss", "pkgCvss")
 
# Numerische Ersatzwerte, falls kein CVSS-Wert vorliegt oder er null ist
SCORE_FALLBACK_FIELDS = ("riskValue", "riskScore", "baseValue", "baseScore")
 
# Ratings, die Mondoo fuer "kein Wert" verwendet
EMPTY_RATINGS = frozenset({"NONE", "NONE - EOL"})
 
 
def search_key(finding_mrn: str) -> str:
    """Der Wert, auf den beim Durchsuchen der Findings verglichen wird.
 
    Bei Vulnerabilities ist das die CVE-Kennung aus der MRN, sonst das letzte
    Pfadsegment - bei Fehlkonfigurationen also die Query-ID.
    """
    match = CVE_IN_MRN_PATTERN.search(finding_mrn)
    if match:
        return match.group(0).lower()
    return finding_mrn.split("/")[-1].lower()
 
 
def node_title(node: Dict[str, Any]) -> str:
    for field in TITLE_FIELDS:
        value = node.get(field)
        if value:
            return value
    return ""
 
 
def node_matches(node: Dict[str, Any], *, key: str, finding_mrn: str) -> bool:
    node_mrn = (node.get("mrn") or "").lower()
    return (
        key in node_mrn
        or key in node_title(node).lower()
        or finding_mrn.lower() in node_mrn
    )
 
 
def _raw_rating(node: Dict[str, Any], cvss_obj: Optional[Dict[str, Any]]) -> Optional[str]:
    rating = cvss_obj.get("rating") if isinstance(cvss_obj, dict) else None
    if isinstance(rating, str) and rating.upper() in EMPTY_RATINGS:
        rating = None
    if rating is None:
        rating = node.get("rating") or node.get("baseRating")
    return rating
 
 
def _raw_score(node: Dict[str, Any], cvss_obj: Optional[Dict[str, Any]]) -> Any:
    value = cvss_obj.get("value") if isinstance(cvss_obj, dict) else None
    if value is None or value in (0, 0.0, "0", "0.0"):
        for field in SCORE_FALLBACK_FIELDS:
            fallback = node.get(field)
            if fallback:
                return fallback
    return value
 
 
def extract_score_and_rating(
    node: Dict[str, Any], thresholds: Dict[str, float]
) -> Tuple[Optional[str], Optional[str]]:
    
    cvss_obj = None
    for field in CVSS_FIELDS:
        candidate = node.get(field)
        if isinstance(candidate, dict):
            cvss_obj = candidate
            break
 
    rating = _raw_rating(node, cvss_obj)
    score_value, score_text = normalize_cvss_score(_raw_score(node, cvss_obj))
 
    if rating is None and score_value is not None:
        rating = calculate_rating_from_score(score_value, thresholds)
 
    return score_text, str(rating).upper() if rating is not None else None