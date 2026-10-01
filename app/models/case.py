"""Normalisierter Case: Ergebnis des Parsings und Eingabe fuer ServiceNow."""

from pydantic import BaseModel, ConfigDict

from app.domain.priority import PrioritySource
from app.models.mondoo import MondooEventType

__all__ = ["NormalizedCase"]


class NormalizedCase(BaseModel):
    """Bereinigter und angereicherter Mondoo-Case; nach dem Parsing unveraenderlich.

    Leere Texte stehen fuer "kein Wert": ServiceNow erwartet in den
    Katalogvariablen leere Zeichenketten, nicht ``null``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Rohwert aus dem Payload (z. B. "TYPE_CREATED"), bleibt fuer das Logging erhalten
    raw_event_type: str
    # Statusfeld des Case, z. B. CASE_CLOSED. Leer bei aelteren Payloads.
    case_status: str = ""
    # Normalisierte Ereignisart, steuert die Schliesslogik
    event_type: MondooEventType = MondooEventType.UNKNOWN

    mrn: str
    owner_mrn: str
    mondoo_space: str
    finding_type: str
    finding_cve: str
    # Anzahl betroffener Assets laut Mondoo; fehlt sie, die Assets aus den Refs
    assets_count: int = 0

    # CVSS: nur bei Vulnerabilities und Advisories belegt
    cvss_score: str = ""
    cvss_rating: str = ""

    # Mondoo Risk Rating (CRITICAL/HIGH/MEDIUM/LOW) und Score 0-100. Bewusst
    # getrennt von CVSS: Fehlkonfigurationen haben kein CVSS, aber ein Risiko.
    risk_rating: str = ""
    risk_score: str = ""
    # Herkunft der Priorisierung fuer Auswertung und Nachvollziehbarkeit
    priority_source: PrioritySource = PrioritySource.DEFAULT
    urgency: str
    impact: str

    title: str
    ticket_url: str
    created_at: str
    updated_at: str

    # MRN des eroeffnenden Benutzers. Leer bzw. ohne /users/-Segment deutet auf
    # ein automatisch erzeugtes Regressions-Ticket hin.
    created_by: str = ""
    is_automated: bool = False

    # Compliance-Kontext aus case.tags.policies (z. B. CIS-Benchmark)
    policies: str = ""
