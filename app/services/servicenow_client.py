import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
import httpx

from app.core.config import settings
from app.core.exceptions import ServiceNowAPIError
from app.core.logging import logger
from app.models.schemas import ServiceNowPayload
from app.utils.text_cleaner import sanitize_url


class ServiceNowClient:
    def __init__(self, http_client: httpx.AsyncClient):
        self.http_client = http_client
        self.base_url = settings.SNOW_INSTANCE_URL.rstrip("/")
        self._oauth_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

    async def _get_auth_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if settings.SNOW_AUTH_MODE.lower() == "oauth":
            token = await self._get_oauth_token()
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _get_basic_auth(self) -> Optional[httpx.BasicAuth]:
        if settings.SNOW_AUTH_MODE.lower() != "oauth":
            return httpx.BasicAuth(settings.SNOW_USER, settings.SNOW_PASSWORD)
        return None

    async def _get_oauth_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self._oauth_token and self._token_expires_at and now < self._token_expires_at:
            return self._oauth_token

        token_url = f"{self.base_url}/oauth_token.do"
        data = {
            "grant_type": "password",
            "client_id": settings.SNOW_CLIENT_ID,
            "client_secret": settings.SNOW_CLIENT_SECRET,
            "username": settings.SNOW_USER,
            "password": settings.SNOW_PASSWORD,
        }

        try:
            response = await self.http_client.post(token_url, data=data)
            if response.status_code != 200:
                raise ServiceNowAPIError(
                    f"OAuth Token-Generierung fehlgeschlagen: {response.text}",
                    status_code=response.status_code,
                )

            token_data = response.json()
            self._oauth_token = token_data.get("access_token")
            expires_in = int(token_data.get("expires_in", 1800))
            self._token_expires_at = now + timedelta(seconds=expires_in - 60)
            return self._oauth_token
        except httpx.RequestError as exc:
            raise ServiceNowAPIError(f"Verbindungsfehler beim OAuth-Handshake: {exc}")

    def _extract_space_id(self, owner_mrn: str) -> Optional[str]:
        match = re.search(r"/spaces/([^/]+)", owner_mrn)
        return match.group(1) if match else None

    def _format_description_and_work_notes(self, payload: ServiceNowPayload) -> Tuple[str, str]:
        case = payload.case
        space_name = case.mondooSpace or "Unbekannt"
        clean_ticket_url = sanitize_url(case.ticket_url)

        desc_lines = [
            f"Mondoo Security Finding: {case.title}",
            f"Space: {space_name} | Finding-Typ: {case.ticketType}",
            f"CVE: {case.findingCVE} | CVSS: {case.cvssScore or 'N/A'} ({case.cvssRiskRating or 'N/A'})",
            f"Mondoo Ticket URL: {clean_ticket_url}",
            f"Betroffene Assets: {case.assetsCount}",
            "",
            "--- Asset Übersicht ---",
        ]

        work_notes_lines = ["--- Bereinigte Asset Remediation Liste ---"]
        for asset in case.remediations.table:
            clean_asset_url = sanitize_url(asset.asset_name_url)
            line = f"- {asset.asset_name_name} ({asset.platform}): {clean_asset_url}"
            work_notes_lines.append(line)
            if len("\n".join(desc_lines)) < 3500:
                desc_lines.append(line)

        description = "\n".join(desc_lines)[:3900]
        work_notes = "\n".join(work_notes_lines)
        return description, work_notes

    async def find_ritm_by_correlation_id(self, mrn: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/api/now/table/sc_req_item"
        headers = await self._get_auth_headers()
        params = {
            "sysparm_query": f"correlation_id={mrn}",
            "sysparm_limit": "1",
            "sysparm_fields": "sys_id,number,state,request,stage",
        }
        try:
            response = await self.http_client.get(
                url, headers=headers, params=params, auth=self._get_basic_auth()
            )
            if response.status_code == 200:
                results = response.json().get("result", [])
                return results[0] if results else None
            logger.error(f"ServiceNow Lookup-Fehler ({response.status_code}): {response.text}")
            return None
        except Exception as e:
            logger.error(f"Fehler bei ServiceNow RITM-Suche für {mrn}: {e}")
            return None

    async def create_ritm(self, payload: ServiceNowPayload) -> Dict[str, Any]:
        headers = await self._get_auth_headers()
        order_url = f"{self.base_url}/api/sn_sc/servicecatalog/items/{settings.SNOW_CATALOG_ITEM_SYS_ID}/order_now"
        order_payload = {
            "sysparm_quantity": "1",
            "requested_for": settings.SNOW_REQUESTED_FOR_SYS_ID,
            "variables": {},
        }

        logger.info(f"Trigger Service Catalog Order Now für Item {settings.SNOW_CATALOG_ITEM_SYS_ID}...")
        order_resp = await self.http_client.post(
            order_url, json=order_payload, headers=headers, auth=self._get_basic_auth()
        )

        if order_resp.status_code not in (200, 201):
            raise ServiceNowAPIError(
                f"Order Now Aufruf fehlgeschlagen ({order_resp.status_code}): {order_resp.text}",
                status_code=order_resp.status_code,
            )

        order_result = order_resp.json().get("result", {})
        request_id = order_result.get("request_id") or order_result.get("sys_id")
        if not request_id:
            raise ServiceNowAPIError("Keine request_id von Order Now API zurückgegeben.")

        # Zugehöriges RITM über Parent-Request ermitteln
        ritm_lookup_url = f"{self.base_url}/api/now/table/sc_req_item"
        ritm_resp = await self.http_client.get(
            ritm_lookup_url,
            headers=headers,
            params={"sysparm_query": f"request={request_id}", "sysparm_limit": "1"},
            auth=self._get_basic_auth(),
        )

        ritm_records = ritm_resp.json().get("result", [])
        if not ritm_records:
            raise ServiceNowAPIError(f"Kein RITM zu Request {request_id} gefunden.")

        ritm_sys_id = ritm_records[0]["sys_id"]
        return await self.update_ritm(ritm_sys_id, payload, is_initial=True)

    async def update_ritm(
        self, ritm_sys_id: str, payload: ServiceNowPayload, is_initial: bool = False
    ) -> Dict[str, Any]:
        case = payload.case
        headers = await self._get_auth_headers()
        patch_url = f"{self.base_url}/api/now/table/sc_req_item/{ritm_sys_id}"
        description, work_notes = self._format_description_and_work_notes(payload)

        space_id = self._extract_space_id(case.ownerMrn) or ""
        assignment_group_name = settings.ASSIGNMENTGROUP_MAP.get(
            space_id, "Mosca IT - Security"
        )

        update_body: Dict[str, Any] = {
            "short_description": case.title[:160],
            "urgency": case.urgency,
            "impact": case.impact,
            "assignment_group": assignment_group_name,
            "work_notes": f"[code]<pre>{work_notes}</pre>[/code]",
        }

        if is_initial:
            update_body["description"] = description
            update_body["correlation_id"] = case.mrn[:100]

        if case.ticketState in ("TYPE_DELETED", "closed", "RESOLVED"):
            # Fall A: Erfolgreich behoben oder Ausnahme genehmigt (Standard)
            update_body["state"] = "3"  # Closed Complete
            update_body["stage"] = "Completed"
            update_body["close_notes"] = (
                "Automatisierter Abschluss via Mondoo: "
                "Befund auf allen Zielsystemen behoben oder formale Ausnahme genehmigt."
            )


        params = {"sysparm_input_display_value": "true"}
        patch_resp = await self.http_client.patch(
            patch_url, json=update_body, headers=headers, params=params, auth=self._get_basic_auth()
        )

        if patch_resp.status_code != 200:
            raise ServiceNowAPIError(
                f"RITM Update fehlgeschlagen ({patch_resp.status_code}): {patch_resp.text}",
                status_code=patch_resp.status_code,
            )

        updated_record = patch_resp.json().get("result", {})
        logger.info(f"RITM {updated_record.get('number')} ({ritm_sys_id}) erfolgreich aktualisiert.")
        return updated_record

async def process_payload(self, payload: ServiceNowPayload) -> Dict[str, Any]:
        existing_ritm = await self.find_ritm_by_correlation_id(payload.case.mrn[:100])

        if existing_ritm:
            ritm_sys_id = existing_ritm["sys_id"]
            current_state = str(existing_ritm.get("state", ""))

            # Schutz vor Überschreiben bereits geschlossener Tickets (3=Complete, 4=Incomplete, 7=Closed)
            if current_state in ("3", "4", "7"):
                logger.info(
                    f"RITM {existing_ritm.get('number')} befindet sich bereits im Endstatus (State: {current_state}). "
                    f"Update für Event '{payload.case.ticketState}' wird verworfen."
                )
                return existing_ritm

            logger.info(f"Existierendes RITM gefunden: {existing_ritm.get('number')} -> Starte Update.")
            return await self.update_ritm(ritm_sys_id, payload, is_initial=False)
        else:
            logger.info("Kein RITM zu MRN gefunden. Lege neues RITM via Service Catalog an...")
            return await self.create_ritm(payload)