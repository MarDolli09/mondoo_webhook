import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings
from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
from app.models.schemas import MondooEventType, ServiceNowPayload
from app.utils.text_cleaner import sanitize_url

# ServiceNow-Feldgrenzen (task-Tabelle)
SHORT_DESCRIPTION_MAX = 160
DESCRIPTION_MAX = 3900          # defensiv unter dem 4000-Zeichen-Limit
CORRELATION_ID_MAX = 100

# RITM-Endzustaende: in diesen Zustaenden werden eingehende Updates verworfen,
# damit manuelle Abschluesse nicht von nachfolgenden Scan-Events ueberschrieben
# werden.
TERMINAL_STATES = ("3", "4", "7")
STATE_CLOSED_COMPLETE = "3"
STATE_CLOSED_SKIPPED = "7"

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
SPACE_ID_PATTERN = re.compile(r"/spaces/([^/]+)")


class ServiceNowClient:

    _token: Optional[str] = None
    _token_expires_at: float = 0.0
    _token_lock = asyncio.Lock()

    _group_cache: Dict[str, str] = {}
    _group_lock = asyncio.Lock()

    def __init__(self, http_client: httpx.AsyncClient):
        self.http_client = http_client
        self.base_url = settings.SNOW_INSTANCE_URL.rstrip("/")

    # ------------------------------------------------------------------ #
    # Authentifizierung
    # ------------------------------------------------------------------ #

    @property
    def _uses_oauth(self) -> bool:
        return settings.SNOW_AUTH_MODE.lower() == "oauth"

    def _basic_auth(self) -> Optional[httpx.BasicAuth]:
        if self._uses_oauth:
            return None
        return httpx.BasicAuth(settings.SNOW_USER, settings.SNOW_PASSWORD)

    async def _headers(self, content_type: str = "application/json") -> Dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": content_type}
        if self._uses_oauth:
            headers["Authorization"] = f"Bearer {await self._get_token()}"
        return headers

    async def _get_token(self) -> str:
        cls = ServiceNowClient
        if cls._token and time.monotonic() < cls._token_expires_at:
            return cls._token

        async with cls._token_lock:
            if cls._token and time.monotonic() < cls._token_expires_at:
                return cls._token

            data = {
                "grant_type": "password",
                "client_id": settings.SNOW_CLIENT_ID,
                "client_secret": settings.SNOW_CLIENT_SECRET,
                "username": settings.SNOW_USER,
                "password": settings.SNOW_PASSWORD,
            }
            try:
                response = await self.http_client.post(
                    f"{self.base_url}/oauth_token.do",
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except httpx.HTTPError as exc:
                raise ServiceNowAPIError(f"Verbindungsfehler beim OAuth-Handshake: {exc}")

            if response.status_code != 200:
                raise ServiceNowAPIError(
                    f"OAuth Token-Generierung fehlgeschlagen ({response.status_code})",
                    status_code=401 if response.status_code == 401 else 502,
                )

            body = response.json()
            token = body.get("access_token")
            if not token:
                raise ServiceNowAPIError("OAuth-Antwort enthaelt kein access_token")

            cls._token = token
            # 60s Sicherheitsmarge, damit kein Token mitten im Vorgang ablaeuft
            cls._token_expires_at = time.monotonic() + float(body.get("expires_in", 1800)) - 60
            logger.info("ServiceNow OAuth-Token erneuert.")
            return token

    # ------------------------------------------------------------------ #
    # HTTP mit Retry
    # ------------------------------------------------------------------ #

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        last_status: Optional[int] = None

        for attempt in range(1, max_retries + 1):
            headers = await self._headers()
            try:
                response = await self.http_client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=headers,
                    auth=self._basic_auth(),
                )
            except httpx.HTTPError as exc:
                if attempt == max_retries:
                    raise ServiceNowAPIError(f"Netzwerkfehler bei {method} {path}: {exc}")
                await asyncio.sleep(2 ** attempt)
                continue

            if response.status_code == 401 and self._uses_oauth and attempt < max_retries:
                ServiceNowClient._token = None
                ServiceNowClient._token_expires_at = 0.0
                logger.warning("ServiceNow lieferte 401. Token wird erneuert.")
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < max_retries:
                delay = float(response.headers.get("Retry-After") or 2 ** attempt)
                last_status = response.status_code
                logger.warning(
                    f"ServiceNow HTTP {response.status_code} bei {method} {path}. "
                    f"Retry {attempt}/{max_retries - 1} in {delay}s."
                )
                await asyncio.sleep(delay)
                continue

            if response.status_code >= 400:
                raise ServiceNowAPIError(
                    f"HTTP {response.status_code} bei {method} {path}: {response.text[:400]}",
                    status_code=response.status_code,
                )

            return response.json() if response.content else {}

        raise ServiceNowAPIError(
            f"{method} {path} nach {max_retries} Versuchen fehlgeschlagen (zuletzt HTTP {last_status})"
        )

    # ------------------------------------------------------------------ #
    # Aufloesung des Referenzfeldes assignment_group
    # ------------------------------------------------------------------ #

    async def _resolve_group_sys_id(self, group_name: str) -> Optional[str]:
        cls = ServiceNowClient
        if group_name in cls._group_cache:
            return cls._group_cache[group_name]

        async with cls._group_lock:
            if group_name in cls._group_cache:
                return cls._group_cache[group_name]

            try:
                result = await self._request(
                    "GET",
                    "/api/now/table/sys_user_group",
                    params={
                        "sysparm_query": f"name={group_name}",
                        "sysparm_fields": "sys_id,name",
                        "sysparm_limit": 1,
                        "sysparm_exclude_reference_link": "true",
                    },
                )
            except ServiceNowAPIError as exc:
                logger.error(
                    f"Aufloesung der Assignment Group '{group_name}' fehlgeschlagen: {exc.message}"
                )
                return None

            records = result.get("result") or []
            if not records:
                logger.error(
                    f"Assignment Group '{group_name}' existiert nicht in ServiceNow. "
                    f"Das RITM wird ohne Gruppenzuweisung angelegt."
                )
                return None

            sys_id = records[0]["sys_id"]
            cls._group_cache[group_name] = sys_id
            logger.info(f"Assignment Group '{group_name}' aufgeloest und zwischengespeichert.")
            return sys_id

    # ------------------------------------------------------------------ #
    # Mapping
    # ------------------------------------------------------------------ #

    @staticmethod
    def _truncate(value: str, limit: int) -> str:
        if not value:
            return ""
        return value if len(value) <= limit else value[: limit - 1] + "\u2026"

    @staticmethod
    def _extract_space_id(owner_mrn: str) -> str:
        match = SPACE_ID_PATTERN.search(owner_mrn or "")
        return match.group(1) if match else ""

    def _build_variables(self, payload: ServiceNowPayload) -> Dict[str, str]:
        case = payload.case

        # Ein MRVS erwartet den kompletten Zeilensatz als EIN JSON-String,
        # nicht als natives Array.
        mrvs_rows: List[Dict[str, str]] = [
            {
                "asset_name": asset.asset_name_name,
                "asset_url": sanitize_url(asset.asset_name_url),
                "platform": asset.platform,
            }
            for asset in case.remediations.table
        ]

        return {
            "mondoo_mrn": self._truncate(case.mrn, CORRELATION_ID_MAX),
            "mondoo_title": self._truncate(case.title, SHORT_DESCRIPTION_MAX),
            "mondoo_cve": case.findingCVE or "",
            "cvss_score": case.cvssScore or "",
            "cvss_rating": case.cvssRiskRating or "",
            "risk_rating": case.riskRating or "",
            "risk_score": case.riskScore or "",
            "priority_source": case.prioritySource,
            "mondoo_space": case.mondooSpace or "",
            "finding_type": case.ticketType or "",
            "ticket_url": sanitize_url(case.ticket_url),
            "assets_count": str(case.assetsCount),
            "mondoo_created_by": case.createdBy or "",
            "mondoo_policies": case.policies or "",
            "mondoo_assets": json.dumps(mrvs_rows, ensure_ascii=False),
        }

    def _build_description(self, payload: ServiceNowPayload) -> str:
        case = payload.case

        if case.cvssRiskRating or case.cvssScore:
            risk_line = f"CVSS: {case.cvssScore or '-'} ({case.cvssRiskRating or '-'})"
        elif case.riskRating:
            risk_line = f"Mondoo Risk: {case.riskRating}" + (
                f" ({case.riskScore}/100)" if case.riskScore else ""
            )
        else:
            risk_line = "Risikobewertung: nicht ermittelbar"

        header = [
            f"Mondoo Security Finding | {case.mondooSpace} | {case.ticketType}",
            f"CVE: {case.findingCVE}   {risk_line}",
            f"Betroffene Assets: {case.assetsCount}",
            f"Mondoo-Ticket: {sanitize_url(case.ticket_url)}",
        ]
        if case.policies:
            header.append(f"Policy: {case.policies}")

        header.append("")
        # Bei einem Flotten-Rollup koennen das dreistellig viele Systeme sein.
        # Die vollstaendige Liste steht im MRVS und im Anhang; hier nur ein
        # Auszug, damit der Befundtext nicht aus dem Feld gedraengt wird.
        preview_limit = settings.DESCRIPTION_ASSET_PREVIEW
        shown = case.remediations.table[:preview_limit]
        hidden = len(case.remediations.table) - len(shown)

        header.append("Betroffene Systeme:" if not hidden else f"Betroffene Systeme (Auszug):")
        header.extend(f"  - {a.asset_name_name} ({a.platform})" for a in shown)
        if hidden > 0:
            header.append(f"  ... und {hidden} weitere (siehe Formularvariablen und Anhang)")
        header.append("")
        header.append("-" * 60)
        header.append("")

        head_text = "\n".join(header)
        remaining = DESCRIPTION_MAX - len(head_text)

        if remaining <= 0:
            return head_text[:DESCRIPTION_MAX]

        body = case.description or ""
        if len(body) <= remaining:
            return head_text + body

        hint = "\n\n[Gekuerzt. Der vollstaendige Befundtext liegt diesem Ticket als Anhang bei.]"
        cut = max(0, remaining - len(hint))
        # An der letzten Absatzgrenze schneiden, damit kein Satz zerrissen wird
        snippet = body[:cut]
        boundary = snippet.rfind("\n\n")
        if boundary > cut * 0.5:
            snippet = snippet[:boundary]
        return head_text + snippet + hint

    def _build_work_notes(self, payload: ServiceNowPayload, is_initial: bool) -> str:
        case = payload.case
        if is_initial:
            origin = case.createdBy or "unbekannt"
            suffix = " (automatisch erzeugt)" if case.isAutomated else ""
            return (
                f"Automatisch angelegt aus Mondoo-Ticket.\n"
                f"MRN: {case.mrn}\n"
                f"Eroeffnet durch: {origin}{suffix}\n"
                f"Mondoo createdAt: {case.createdAt}"
            )
        return (
            f"Mondoo-Update ({case.ticketState}) vom {case.updatedAt}\n"
            f"CVSS: {case.cvssScore or '-'} ({case.cvssRiskRating or '-'}) | "
            f"Betroffene Assets: {case.assetsCount}"
        )

    async def _build_task_fields(
        self, payload: ServiceNowPayload, is_initial: bool
    ) -> Dict[str, Any]:
        case = payload.case

        space_id = self._extract_space_id(case.ownerMrn)
        group_name = settings.ASSIGNMENTGROUP_MAP.get(space_id)
        if not group_name:
            group_name = "Mosca IT - Security"
            logger.warning(
                f"Keine Assignment Group fuer Space '{space_id}' hinterlegt. "
                f"Fallback auf '{group_name}'."
            )

        body: Dict[str, Any] = {
            "urgency": case.urgency,
            "impact": case.impact,
            "work_notes": self._build_work_notes(payload, is_initial),
        }

        group_sys_id = await self._resolve_group_sys_id(group_name)
        if group_sys_id:
            body["assignment_group"] = group_sys_id

        if is_initial:
            body["description"] = self._build_description(payload)
        else:
            # description bleibt bei Updates unangetastet, damit Ergaenzungen
            # der Bearbeiter nicht ueberschrieben werden.
            body["short_description"] = self._truncate(case.title, SHORT_DESCRIPTION_MAX)

        if case.eventType is MondooEventType.CLOSED:
            body["state"] = STATE_CLOSED_COMPLETE
            body["close_notes"] = (
                "Automatisierter Abschluss: Das zugehoerige Mondoo-Ticket wurde geschlossen. "
                "Der Befund gilt als behoben oder es wurde eine formale Ausnahme genehmigt."
            )
        elif case.eventType is MondooEventType.DELETED:
            # Ein Delete in Mondoo bedeutet nicht, dass der Befund behoben wurde.
            # Deshalb Closed Skipped statt Closed Complete.
            body["state"] = STATE_CLOSED_SKIPPED
            body["close_notes"] = (
                "Das zugehoerige Mondoo-Ticket wurde geloescht. Der Befund wurde nicht "
                "nachweislich behoben. Bitte fachlich pruefen, bevor der Vorgang "
                "endgueltig abgelegt wird."
            )

        return body

    # ------------------------------------------------------------------ #
    # Einzeloperationen
    # ------------------------------------------------------------------ #

    async def _find_ritm(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """Lookup fuer den Upsert. Fehler werden bewusst NICHT geschluckt:
        ein stillschweigendes None wuerde als 'existiert nicht' interpretiert
        und ein Duplikat erzeugen."""
        result = await self._request(
            "GET",
            "/api/now/table/sc_req_item",
            params={
                "sysparm_query": f"correlation_id={correlation_id}^ORDERBYDESCsys_created_on",
                "sysparm_fields": "sys_id,number,state,stage,request",
                "sysparm_limit": 1,
                "sysparm_exclude_reference_link": "true",
            },
        )
        records = result.get("result") or []
        return records[0] if records else None

    async def _order_item(self, variables: Dict[str, str]) -> str:
        body: Dict[str, Any] = {"sysparm_quantity": "1", "variables": variables}
        if settings.SNOW_REQUESTED_FOR_SYS_ID:
            body["sysparm_requested_for"] = settings.SNOW_REQUESTED_FOR_SYS_ID

        result = (
            await self._request(
                "POST",
                f"/api/sn_sc/servicecatalog/items/{settings.SNOW_CATALOG_ITEM_SYS_ID}/order_now",
                json_body=body,
            )
        ).get("result") or {}

        # Bei aktiviertem Two-Step-Checkout verhaelt sich order_now wie
        # "in den Warenkorb legen" und liefert nur eine cart_id.
        if result.get("cart_id") and not result.get("request_id"):
            logger.info("Two-Step-Checkout erkannt. Sende submit_order nach.")
            result = (
                await self._request(
                    "POST", "/api/sn_sc/servicecatalog/cart/submit_order", json_body={}
                )
            ).get("result") or {}

        request_sys_id = result.get("request_id") or result.get("sys_id")
        if not request_sys_id:
            raise ServiceNowAPIError(f"order_now lieferte keine Request-ID: {result}")

        logger.info(
            f"Service Catalog Request {result.get('request_number') or request_sys_id} erzeugt."
        )
        return request_sys_id

    async def _resolve_ritm(self, request_sys_id: str) -> Dict[str, Any]:
        """ServiceNow erzeugt das RITM ueber die Workflow-Engine, teils
        verzoegert. Deshalb mehrere Versuche mit Backoff."""
        for delay in (0.0, 0.5, 1.0, 2.0):
            if delay:
                await asyncio.sleep(delay)
            result = await self._request(
                "GET",
                "/api/now/table/sc_req_item",
                params={
                    "sysparm_query": f"request={request_sys_id}",
                    "sysparm_fields": "sys_id,number",
                    "sysparm_limit": 1,
                    "sysparm_exclude_reference_link": "true",
                },
            )
            records = result.get("result") or []
            if records:
                return records[0]

        raise ServiceNowAPIError(
            f"Kein RITM zu Request {request_sys_id} gefunden. "
            f"Moeglicherweise ist am Katalogformular kein Workflow hinterlegt."
        )

    async def _patch_ritm(self, ritm_sys_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return (
            await self._request(
                "PATCH",
                f"/api/now/table/sc_req_item/{ritm_sys_id}",
                json_body=body,
                params={
                    "sysparm_fields": "sys_id,number,state,stage",
                    "sysparm_exclude_reference_link": "true",
                },
            )
        ).get("result") or {}

    async def _attach_full_text(self, ritm_sys_id: str, payload: ServiceNowPayload) -> bool:
        """Legt den ungekuerzten Befundtext als Anhang ab. Schlaegt das fehl
        (z. B. fehlende Berechtigung auf einer Shared Instance), wird das
        protokolliert, aber der Vorgang nicht abgebrochen."""
        content = payload.case.description
        if not content:
            return False

        cve_part = (payload.case.findingCVE or "").replace("/", "-").strip() or "details"
        file_name = f"mondoo_finding_{cve_part}.md"
        headers = await self._headers(content_type="text/markdown")

        try:
            response = await self.http_client.post(
                f"{self.base_url}/api/now/attachment/file",
                params={
                    "table_name": "sc_req_item",
                    "table_sys_id": ritm_sys_id,
                    "file_name": file_name,
                },
                content=content.encode("utf-8"),
                headers=headers,
                auth=self._basic_auth(),
            )
        except httpx.HTTPError as exc:
            logger.warning(f"Anhang konnte nicht uebertragen werden: {exc}")
            return False

        if response.status_code not in (200, 201):
            logger.warning(
                f"Anhang abgelehnt (HTTP {response.status_code}). "
                f"Pruefen, ob der Integrationsbenutzer Anhaenge schreiben darf."
            )
            return False

        logger.info(f"Vollstaendiger Befundtext als '{file_name}' angehaengt.")
        return True

    # ------------------------------------------------------------------ #
    # Einstiegspunkt
    # ------------------------------------------------------------------ #

    async def process_payload(self, payload: ServiceNowPayload) -> Dict[str, Any]:
        case = payload.case
        correlation_id = self._truncate(case.mrn, CORRELATION_ID_MAX)

        existing = await self._find_ritm(correlation_id)

        if existing:
            state = str(existing.get("state", ""))
            if state in TERMINAL_STATES:
                logger.info(
                    f"RITM {existing.get('number')} befindet sich im Endstatus (state={state}). "
                    f"Ereignis '{case.ticketState}' wird verworfen."
                )
                return {**existing, "action": "skipped"}

            logger.info(f"Bestehendes RITM {existing.get('number')} gefunden. Starte Update.")
            body = await self._build_task_fields(payload, is_initial=False)
            updated = await self._patch_ritm(existing["sys_id"], body)
            return {**updated, "action": "updated"}

        logger.info(f"Kein RITM zu '{correlation_id}' vorhanden. Lege neuen Request an.")
        request_sys_id = await self._order_item(self._build_variables(payload))
        ritm = await self._resolve_ritm(request_sys_id)

        body = await self._build_task_fields(payload, is_initial=True)
        updated = await self._patch_ritm(ritm["sys_id"], body)

        attached = await self._attach_full_text(ritm["sys_id"], payload)

        logger.info(f"RITM {updated.get('number') or ritm.get('number')} angelegt und befuellt.")
        return {
            **updated,
            "number": updated.get("number") or ritm.get("number"),
            "sys_id": ritm["sys_id"],
            "request_sys_id": request_sys_id,
            "attachment": attached,
            "action": "created",
        }