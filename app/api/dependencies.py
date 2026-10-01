from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import Depends, FastAPI, Request

from app.api.telemetry import InboundHeaderSampler
from app.core.config import settings
from app.core.logging import logger
from app.core.master_data import master_data
from app.core.webhook_signature import HEADER_SIGNATURE, StandardWebhookVerifier
from app.domain.ports import TicketSynchronizer
from app.services.mondoo import MondooGraphQLClient
from app.services.parsing import CaseParser, ParsingConfig
from app.services.processing import WebhookProcessor
from app.services.servicenow import (
    ReferenceCache,
    ServiceNowAPI,
    ServiceNowAuth,
    ServiceNowClient,
    ServiceNowConfig,
)

__all__ = [
    "AppResources",
    "get_resources",
    "get_webhook_processor",
    "lifespan",
]

CONNECT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class AppResources:
    """Ressourcen, die alle Requests eines Prozesses teilen.

    Alle sind zustandslos oder task-sicher; so werden etwa das OAuth-Token und
    der Referenz-Cache von ServiceNow von allen Requests wiederverwendet. Nur
    dieses Modul reicht ``settings`` und ``master_data`` an die Teilsysteme.
    """

    webhook_processor: WebhookProcessor
    header_sampler: InboundHeaderSampler
    webhook_verifier: StandardWebhookVerifier


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Erzeugt die geteilten Ressourcen beim Start und schliesst sie beim Stopp."""
    timeout = httpx.Timeout(
        settings.HTTP_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS
    )
    async with httpx.AsyncClient(timeout=timeout) as http_client:
        app.state.resources = AppResources(
            webhook_processor=WebhookProcessor(
                _case_parser(http_client), _ticket_synchronizer(http_client)
            ),
            header_sampler=InboundHeaderSampler(
                extra_sensitive_headers=(
                    settings.MONDOO_WEBHOOK_AUTH_HEADER,
                    HEADER_SIGNATURE,
                )
            ),
            webhook_verifier=StandardWebhookVerifier(
                settings.MONDOO_WEBHOOK_SIGNING_SECRET.get_secret_value(),
                settings.MONDOO_WEBHOOK_TOLERANCE_SECONDS,
            ),
        )
        _log_effective_configuration()
        yield
    logger.info("Gemeinsamer HTTP-Client erfolgreich geschlossen.")


def get_resources(request: Request) -> AppResources:
    """Geteilte Ressourcen der laufenden Anwendung."""
    resources: AppResources = request.app.state.resources
    return resources


def get_webhook_processor(
    resources: AppResources = Depends(get_resources),
) -> WebhookProcessor:
    """Verarbeitung mit Mondoo als Bewertungsquelle und ServiceNow als Ziel."""
    return resources.webhook_processor


# ---------------------------------------------------------------------- #
# Aufbau der Teilsysteme
# ---------------------------------------------------------------------- #


def _case_parser(http_client: httpx.AsyncClient) -> CaseParser:
    scores_lookup = MondooGraphQLClient(
        http_client, settings.MONDOO_API_KEY.get_secret_value()
    )
    config = ParsingConfig(
        finding_type_patterns=dict(master_data.FINDING_TYPE_MAP),
        space_names=dict(master_data.CATEGORY_MAP),
        priority_map=dict(master_data.PRIORITY_MAP),
        default_urgency_impact=master_data.DEFAULT_URGENCY_IMPACT,
        default_cve=master_data.DEFAULT_CVE,
        max_finding_lookups=settings.MONDOO_MAX_FINDING_LOOKUPS,
    )
    return CaseParser(scores_lookup, config)


def _ticket_synchronizer(http_client: httpx.AsyncClient) -> TicketSynchronizer:
    config = ServiceNowConfig(
        base_url=settings.snow_base_url,
        user=settings.SNOW_USER,
        password=settings.SNOW_PASSWORD,
        catalog_item_sys_id=settings.SNOW_CATALOG_ITEM_SYS_ID,
        use_oauth=settings.uses_oauth,
        client_id=settings.SNOW_CLIENT_ID,
        client_secret=settings.SNOW_CLIENT_SECRET,
        requested_for_sys_id=settings.SNOW_REQUESTED_FOR_SYS_ID,
        user_lookup_fields=tuple(settings.SNOW_USER_LOOKUP_FIELDS),
        user_names=dict(master_data.USER_MAP),
    )
    api = ServiceNowAPI.connect(
        http_client, ServiceNowAuth(http_client, config), ReferenceCache(), config
    )
    return ServiceNowClient(api, config)


def _log_effective_configuration() -> None:
    """Protokolliert die wirksamen Einstellungen beim Start; ohne Geheimwerte."""
    requested_for = (
        "gesetzt" if settings.SNOW_REQUESTED_FOR_SYS_ID else "angemeldeter Benutzer"
    )
    logger.info(
        f"ServiceNow: {settings.snow_base_url}, Auth-Modus "
        f"'{settings.SNOW_AUTH_MODE}', Benutzer '{settings.SNOW_USER}', "
        f"Katalog-Item {settings.SNOW_CATALOG_ITEM_SYS_ID}, "
        f"Angefordert fuer: {requested_for}"
    )
    logger.info(
        f"Mondoo-Webhook: Auth-Header '{settings.MONDOO_WEBHOOK_AUTH_HEADER}', "
        f"Zeittoleranz {settings.MONDOO_WEBHOOK_TOLERANCE_SECONDS}s"
    )
