from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class AssetRemediation(BaseModel):
    asset_name_name: str
    asset_name_url: str
    platform: str


class RemediationTable(BaseModel):
    table: List[AssetRemediation] = Field(default_factory=list)


class ServiceNowCase(BaseModel):
    ticketState: str
    mrn: str
    ownerMrn: str
    mondooSpace: str
    ticketType: str
    findingCVE: str
    cvssScore: Optional[str] = ""
    cvssRiskRating: Optional[str] = ""
    title: str
    urgency: str
    impact: str
    ticket_url: str
    createdAt: str
    updatedAt: str
    assetsCount: int
    remediations: RemediationTable


class ServiceNowPayload(BaseModel):
    case: ServiceNowCase

    model_config = ConfigDict(extra="ignore")