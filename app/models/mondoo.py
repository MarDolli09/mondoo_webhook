"""Eingangsmodell des Mondoo-Webhooks und Ereignistypen."""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.exceptions import PayloadParsingError

__all__ = [
    "CASE_STATUS_CLOSED",
    "CLOSING_EVENTS",
    "CaseContent",
    "CaseTags",
    "FindingRef",
    "MondooCase",
    "MondooEventType",
    "MondooWebhookEvent",
    "map_event_type",
]


class MondooEventType(str, Enum):
    """Normalisierte Ereignisart eines Webhooks."""

    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    CLOSED = "closed"
    UNKNOWN = "unknown"


EVENT_TYPE_PREFIX = "TYPE_"
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
    """Bildet ``TYPE_CREATED`` usw. auf ``MondooEventType`` ab."""
    if not raw_type:
        return MondooEventType.UNKNOWN
    key = raw_type.strip().upper()
    if key.startswith(EVENT_TYPE_PREFIX):
        key = key[len(EVENT_TYPE_PREFIX) :]
    return _EVENT_ALIASES.get(key, MondooEventType.UNKNOWN)


class _PayloadModel(BaseModel):
    """Basis der Eingangsmodelle: unbekannte Felder und null-Werte entfallen."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def _drop_null_values(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if value is not None}
        return data


class CaseContent(_PayloadModel):
    """Inhaltsblock mit der Markdown-Beschreibung (AI-Summary)."""

    description: str = ""


class CaseTags(_PayloadModel):
    """Tags eines Case; ``policies`` nennt z. B. den CIS-Benchmark."""

    policies: str = ""


class FindingRef(_PayloadModel):
    """Verweis eines Case auf ein Finding in einem Asset-Scope."""

    finding_mrn: str = Field(default="", alias="findingMrn")
    scope_mrn: str = Field(default="", alias="scopeMrn")


class MondooCase(_PayloadModel):
    """Mondoo-Case aus dem Webhook-Payload."""

    mrn: str
    owner_mrn: str = Field(default="", alias="ownerMrn")
    title: str = ""
    status: str = ""
    created_at: Optional[str] = Field(default=None, alias="createdAt")
    updated_at: str = Field(default="", alias="updatedAt")
    created_by: str = Field(default="", alias="createdBy")
    assets_count: int = Field(default=0, alias="assetsCount")
    description: str = ""
    content: CaseContent = Field(default_factory=CaseContent)
    tags: CaseTags = Field(default_factory=CaseTags)
    vulnerability_refs: list[FindingRef] = Field(
        default_factory=list, alias="vulnerabilityRefs"
    )
    query_refs: list[FindingRef] = Field(default_factory=list, alias="queryRefs")

    @property
    def finding_refs(self) -> list[FindingRef]:
        """Alle Finding-Verweise: zuerst Vulnerabilities, dann Queries."""
        return [*self.vulnerability_refs, *self.query_refs]


class MondooWebhookEvent(_PayloadModel):
    """Webhook-Ereignis: Ereignistyp, Case und optionale Beschreibung."""

    raw_type: str = Field(default="", alias="type")
    case: MondooCase
    content: CaseContent = Field(default_factory=CaseContent)
    ticket_type: Optional[str] = Field(default=None, alias="ticketType")

    @property
    def description(self) -> str:
        """Beschreibung aus ``content``, ersatzweise aus dem Case."""
        return (
            self.content.description
            or self.case.content.description
            or self.case.description
        )

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "MondooWebhookEvent":
        """Liest den Payload mit oder ohne ``body``-Huelle.

        Raises:
            PayloadParsingError: ``case`` fehlt oder hat keine ``mrn``.
        """
        body = payload.get("body")
        data = body if isinstance(body, dict) else payload
        case = data.get("case")
        if not isinstance(case, dict) or not case.get("mrn"):
            raise PayloadParsingError("case fehlt oder enthaelt keine mrn.")
        return cls.model_validate(data)
