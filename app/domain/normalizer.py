from typing import Any, Dict, Optional, Tuple

#     Normalisiert einen numerischen CVSS/Risk-Score. Sorgt dafür, dass Werte > 10.0 korrigiert werden (z. B. 81 -> 8.1).

def normalize_cvss_score(raw_value: Any) -> Tuple[Optional[float], Optional[str]]:
    
    if raw_value is None or raw_value in ["", "NONE", "NONE - EOL"]:
        return None, None

    try:
        f_val = float(raw_value)
        if f_val < 0:
            return None, None

        if f_val > 10.0:
            f_val = f_val / 10.0
            if f_val > 10.0:
                return None, None

        f_val = round(f_val, 1)
        return f_val, f"{f_val:.1f}"
    except (ValueError, TypeError):
        return None, None

# Ermittelt das Text-Rating anhand von konfigurierbaren Schwellenwerten.
def calculate_rating_from_score(score: float, thresholds: Dict[str, float]) -> Optional[str]:

    if score is None:
        return None

    for rating_name, threshold in thresholds.items():
        if score >= threshold:
            return rating_name.upper()

    return None