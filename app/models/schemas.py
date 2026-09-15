from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class MondooEventType(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    CLOSED = "closed"
    UNKNOWN = "unknown"


_EVENT_ALIASES = {
    "CREATED": MondooEventType.CREATED,
    "UPDATED": MondooEventType.UPDATED,
    "DELETED": MondooEventType.DELETED,
    "CLOSED": MondooEventType.CLOSED,
    "RESOLVED": MondooEventType.CLOSED,
}

CLOSING_EVENTS = (MondooEventType.CLOSED, MondooEventType.DELETED)

CASE_STATUS_CLOSED = "CASE_CLOSED"


def map_event_type(raw_type: str) -> MondooEventType:
    if not raw_type:
        return MondooEventType.UNKNOWN
    key = raw_type.strip().upper()
    if key.startswith("TYPE_"):
        key = key[len("TYPE_"):]
    return _EVENT_ALIASES.get(key, MondooEventType.UNKNOWN)


class AssetRemediation(BaseModel):
    asset_name_name: str
    asset_name_url: str
    platform: str


class RemediationTable(BaseModel):
    table: List[AssetRemediation] = Field(default_factory=list)


class ServiceNowCase(BaseModel):
    # Rohwert aus dem Payload (z. B. "TYPE_CREATED"), bleibt fuer das Logging erhalten
    ticketState: str
    # Statusfeld des Case, z. B. CASE_CLOSED. Leer bei aelteren Payloads.
    caseStatus: str = ""
    # Normalisierte Ereignisart, steuert die Schliesslogik im ServiceNowClient
    eventType: MondooEventType = MondooEventType.UNKNOWN

    mrn: str
    ownerMrn: str
    mondooSpace: str
    ticketType: str
    findingCVE: str

    # CVSS: nur bei Vulnerabilities und Advisories belegt
    cvssScore: Optional[str] = ""
    cvssRiskRating: Optional[str] = ""

    # Mondoo Risk Rating (0-100 bzw. CRITICAL/HIGH/MEDIUM/LOW). Bewusst getrennt
    # von CVSS: Fehlkonfigurationen haben kein CVSS, aber sehr wohl ein Risiko.
    riskRating: str = ""
    riskScore: str = ""
    # Herkunft der Priorisierung fuer Auswertung und Nachvollziehbarkeit
    prioritySource: str = "default"

    title: str
    urgency: str
    impact: str
    ticket_url: str
    createdAt: str
    updatedAt: str
    assetsCount: int

    # Vollstaendiger Befundtext (AI-Summary inkl. Validierungsplan). Wird in
    # ServiceNow gekuerzt in description geschrieben und vollstaendig als
    # Anhang abgelegt.
    description: str = ""

    # MRN des eroeffnenden Benutzers. Leer bzw. ohne /users/-Segment deutet auf
    # ein automatisch erzeugtes Regressions-Ticket hin.
    createdBy: str = ""
    isAutomated: bool = False

    # Compliance-Kontext aus case.tags.policies (z. B. CIS-Benchmark)
    policies: str = ""

    remediations: RemediationTable


class ServiceNowPayload(BaseModel):
    case: ServiceNowCase

    model_config = ConfigDict(extra="ignore")