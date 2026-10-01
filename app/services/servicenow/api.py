"""Fachliche Zugaenge zu einer ServiceNow-Instanz, je Tabelle bzw. Endpunkt."""

from dataclasses import dataclass

import httpx

from app.services.servicenow.auth import ServiceNowAuth
from app.services.servicenow.cache import ReferenceCache
from app.services.servicenow.catalog import ServiceCatalog
from app.services.servicenow.catalog_tasks import CatalogTasks
from app.services.servicenow.config import ServiceNowConfig
from app.services.servicenow.request_items import RequestItems
from app.services.servicenow.transport import ServiceNowTransport
from app.services.servicenow.users import UserDirectory

__all__ = ["ServiceNowAPI"]


@dataclass(frozen=True)
class ServiceNowAPI:
    """Buendelt die Ressourcen einer Instanz; alle teilen einen Transport."""

    request_items: RequestItems
    catalog_tasks: CatalogTasks
    catalog: ServiceCatalog
    users: UserDirectory

    @classmethod
    def connect(
        cls,
        http_client: httpx.AsyncClient,
        auth: ServiceNowAuth,
        reference_cache: ReferenceCache,
        config: ServiceNowConfig,
    ) -> "ServiceNowAPI":
        """Baut alle Ressourcen auf einem gemeinsamen Transport auf."""
        transport = ServiceNowTransport(http_client, auth)
        return cls(
            request_items=RequestItems(transport),
            catalog_tasks=CatalogTasks(transport),
            catalog=ServiceCatalog(transport, config.catalog_item_sys_id),
            users=UserDirectory(transport, reference_cache, config.user_lookup_fields),
        )
