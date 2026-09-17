"""Lebenszyklus geteilter Ressourcen und FastAPI-Abhaengigkeiten."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import Depends, FastAPI, Request

from app.api.telemetry import InboundHeaderSampler
from app.core.config import settings
from app.core.logging import logger
from app.domain.ports import TicketSynchronizer
from app.services.mondoo import MondooGraphQLClient
from app.services.parsing import CaseParser
from app.services.servicenow import (
    ReferenceCache,
    ServiceNowAPI,
    ServiceNowAuth,
    ServiceNowClient,
)

__all__ = [
    "AppResources",
    "get_case_parser",
    "get_resources",
    "get_ticket_synchronizer",
    "lifespan",
]

CONNECT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class AppResources:
    """Ressourcen, die alle Requests eines Prozesses teilen."""

    http_client: httpx.AsyncClient
    servicenow_auth: ServiceNowAuth
    reference_cache: ReferenceCache
    header_sampler: InboundHeaderSampler


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Erzeugt die geteilten Ressourcen beim Start und schliesst sie beim Stopp."""
    timeout = httpx.Timeout(
        settings.HTTP_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS
    )
    async with httpx.AsyncClient(timeout=timeout) as http_client:
        app.state.resources = AppResources(
            http_client=http_client,
            servicenow_auth=ServiceNowAuth(http_client, settings.snow_base_url),
            reference_cache=ReferenceCache(),
            header_sampler=InboundHeaderSampler(),
        )
        yield
    logger.info("Gemeinsamer HTTP-Client erfolgreich geschlossen.")


def get_resources(request: Request) -> AppResources:
    """Geteilte Ressourcen der laufenden Anwendung."""
    resources: AppResources = request.app.state.resources
    return resources


def get_case_parser(resources: AppResources = Depends(get_resources)) -> CaseParser:
    """Parser mit Mondoo als CVSS-Quelle."""
    return CaseParser(MondooGraphQLClient(resources.http_client))


def get_ticket_synchronizer(
    resources: AppResources = Depends(get_resources),
) -> TicketSynchronizer:
    """ServiceNow-Client mit geteiltem Token und Referenz-Cache."""
    api = ServiceNowAPI(
        resources.http_client, resources.servicenow_auth, resources.reference_cache
    )
    return ServiceNowClient(api)
