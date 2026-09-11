from typing import Dict, Optional, Tuple
from app.core.logging import logger


def resolve_priority_mapping(
    title: str,
    cvss_risk_rating: Optional[str],
    priority_map: Dict[str, Tuple[str, str]],
    default_urgency_impact: Tuple[str, str]
) -> Tuple[str, str]:
    # Ermittelt Urgency & Impact anhand des Ratings oder Fallback-Titels.
    if cvss_risk_rating:
        rating_upper = cvss_risk_rating.upper()
        if rating_upper in priority_map:
            logger.info(f"Priority Mapping via GraphQL Rating ('{rating_upper}') erfolgreich.")
            return priority_map[rating_upper]

    title_upper = title.upper()
    for severity, (urgency, impact) in priority_map.items():
        if f"[{severity}]" in title_upper:
            logger.info(f"Priority Mapping via Titel-Fallback ('[{severity}]') erfolgreich.")
            return urgency, impact

    logger.warning("Kein passendes Priority Mapping gefunden. Verwende Default-Werte.")
    return default_urgency_impact