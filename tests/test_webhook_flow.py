"""Ende-zu-Ende: Webhook -> Parsing -> ServiceNow gegen Attrappen."""

import copy
import logging
import os
import time
import unittest

import httpx

import tests  # noqa: F401  (Dummy-Umgebung)
from app.main import app
from tests.fakes import (
    Delivery,
    FakeBackends,
    load_fixture,
    post_webhooks,
    signed_delivery,
)

# Knoten wie in der Antwort der gefilterten Findings-Abfrage: CVSS auf 0-100
CVE_NODE = {
    "__typename": "CveFinding",
    "mrn": "//vadvisor.api.mondoo.app/cves/CVE-2024-0056",
    "riskValue": 72,
    "rating": "HIGH",
    "cveCvss": {"value": 81, "rating": "HIGH"},
}
from tests.test_mapping import FORM_VARIABLES  # noqa: E402


class WebhookFlowTest(unittest.IsolatedAsyncioTestCase):
    async def test_created_vulnerability_orders_ritm(self) -> None:
        backends = FakeBackends(finding_nodes=[CVE_NODE])
        (response,) = await post_webhooks(
            backends, [load_fixture("case_created_vulnerability.json")]
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["action"], "created")
        (order,) = backends.find("servicenow", "POST", "/order_now")
        variables = order.body["variables"]
        self.assertEqual(list(variables), FORM_VARIABLES)
        self.assertEqual(variables["number_of_affected_assets"], "4")
        self.assertEqual(variables["urgency"], "2")
        self.assertEqual(
            variables["mondoo_title"],
            "Mondoo - [CRITICAL] CVE-2024-0056",
        )
        self.assertEqual(variables["cvss_risk_rating"], "HIGH")
        (patch,) = backends.find("servicenow", "PATCH", "/sc_req_item/")
        self.assertEqual(patch.body["short_description"], variables["mondoo_title"])
        self.assertEqual(patch.body["urgency"], variables["urgency"])
        self.assertEqual(patch.body["impact"], variables["impact"])
        self.assertNotIn("assignment_group", patch.body)
        self.assertEqual(
            patch.body["watch_list"], "usr-lars.siefert@mosca.com,usr-Marius Dollinger"
        )
        self.assertEqual(backends.find("servicenow", "GET", "sys_user_group"), [])
        self.assertNotIn("sysparm_requested_for", order.body)

    async def test_risk_from_api_takes_precedence_over_summary_text(self) -> None:
        payload = load_fixture("case_created_vulnerability.json")
        payload["body"]["content"]["description"] = (
            "## Summary\n\nThe combined risk is **high** because exploits exist."
        )
        critical = {**CVE_NODE, "riskValue": 100, "rating": "CRITICAL"}
        with_api = FakeBackends(finding_nodes=[critical])
        without_api = FakeBackends()

        await post_webhooks(with_api, [payload])
        await post_webhooks(without_api, [payload])

        (order,) = with_api.find("servicenow", "POST", "/order_now")
        variables = order.body["variables"]
        self.assertEqual(variables["mondoo_risk_rating"], "CRITICAL")
        self.assertEqual(variables["mondoo_risk_score"], "100")
        # Ohne Wert der API bleibt der Befundtext als Rueckfall
        (order,) = without_api.find("servicenow", "POST", "/order_now")
        self.assertEqual(order.body["variables"]["mondoo_risk_rating"], "HIGH")

    async def test_rejected_mondoo_query_is_logged_with_its_reason(self) -> None:
        receiver_logger = logging.getLogger("mondoo-receiver")
        receiver_logger.disabled = False
        try:
            with self.assertLogs(receiver_logger, level="ERROR") as captured:
                (response,) = await post_webhooks(
                    FakeBackends(mondoo_status=422),
                    [load_fixture("case_created_vulnerability.json")],
                )
        finally:
            receiver_logger.disabled = True

        # Die Bewertung ist optional; das Ticket entsteht trotzdem
        self.assertEqual(response.json()["action"], "created")
        (log,) = [m for m in captured.output if "abgebrochen" in m]
        self.assertIn('HTTP 422: Fields "cvss" conflict', log)
        self.assertEqual(log.count("conflict because"), 1)

    async def test_closed_event_closes_open_ritm(self) -> None:
        payload = load_fixture("case_closed_misconfiguration.json")
        mrn = payload["body"]["case"]["mrn"]
        open_ritm = {"sys_id": "ritm-1", "number": "RITM0000042", "state": "1"}
        backends = FakeBackends(ritms_by_correlation_id={mrn: [open_ritm]})

        (response,) = await post_webhooks(backends, [payload])

        self.assertEqual(response.json()["action"], "updated")
        (patch,) = backends.find("servicenow", "PATCH", "/sc_req_item/ritm-1")
        self.assertEqual(patch.body["state"], "3")
        self.assertTrue(patch.body["work_notes"].endswith("| Betroffene Assets: 5"))
        self.assertNotIn("assignment_group", patch.body)
        # Auch Fehlkonfigurationen werden abgefragt, gefiltert auf die Finding-MRN
        (lookup,) = [r for r in backends.requests if r.service == "mondoo"]
        self.assertEqual(
            lookup.body["variables"]["findingMrn"],
            "//policy.api.mondoo.app/queries/cis-microsoft-azure-foundations--8.3.2",
        )
        self.assertEqual(
            lookup.body["variables"]["scopeMrn"], payload["body"]["case"]["ownerMrn"]
        )

    async def test_end_of_life_is_reported_as_own_type(self) -> None:
        payload = load_fixture("case_created_vulnerability.json")
        case = payload["body"]["case"]
        advisory = "//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-WINDOWS-2012"
        case["vulnerabilityRefs"] = [
            {**case["vulnerabilityRefs"][0], "findingMrn": advisory}
        ]
        backends = FakeBackends()

        (response,) = await post_webhooks(backends, [payload])

        self.assertEqual(response.json()["ticket_type"], "end-of-life")
        (order,) = backends.find("servicenow", "POST", "/order_now")
        self.assertEqual(order.body["variables"]["finding_type"], "end-of-life")

    async def test_closed_event_without_ritm_is_skipped(self) -> None:
        backends = FakeBackends()
        (response,) = await post_webhooks(
            backends, [load_fixture("case_closed_misconfiguration.json")]
        )
        self.assertEqual(response.json()["action"], "skipped_closing_without_ritm")
        self.assertEqual(backends.find("servicenow", "POST", "/order_now"), [])

    async def test_token_and_user_lookups_are_shared_between_requests(self) -> None:
        first = load_fixture("case_created_vulnerability.json")
        second = copy.deepcopy(first)
        second["body"]["case"]["mrn"] += "-2"
        backends = FakeBackends(finding_nodes=[CVE_NODE])

        responses = await post_webhooks(backends, [first, second])

        self.assertEqual([r.json()["action"] for r in responses], ["created"] * 2)
        self.assertEqual(backends.token_fetches, 1)
        self.assertEqual(len(backends.find("servicenow", "GET", "sys_user")), 3)

    async def test_unauthenticated_deliveries_are_rejected_before_processing(
        self,
    ) -> None:
        payload = load_fixture("case_created_vulnerability.json")
        valid = signed_delivery(payload)
        other_secret = "whsec_" + "b3RoZXItc2lnbmluZy1zZWNyZXQtZm9yLXRlc3RzISE="
        without_signature = {
            k: v for k, v in valid.headers.items() if k != "webhook-signature"
        }
        rejected = {
            "ohne Auth-Header": signed_delivery(payload, auth_header_value=None),
            "falscher Auth-Header": signed_delivery(
                payload, auth_header_value="Bearer falsch"
            ),
            "fremdes Signing Secret": signed_delivery(payload, secret=other_secret),
            "veraenderter Body": Delivery(valid.body + b" ", valid.headers),
            "veralteter Zeitstempel": signed_delivery(
                payload, timestamp=int(time.time()) - 301
            ),
            "ohne Signatur": Delivery(valid.body, without_signature),
        }
        backends = FakeBackends()

        responses = await post_webhooks(backends, list(rejected.values()))

        for label, response in zip(rejected, responses):
            self.assertEqual(response.status_code, 401, label)
            self.assertEqual(response.json()["detail"], "Unauthorized", label)
        self.assertEqual(backends.requests, [])

    async def test_rejection_log_explains_cause_without_secret_values(self) -> None:
        payload = load_fixture("case_created_vulnerability.json")
        wrong_value = "Bearer falsches-token-4711"
        deliveries = [
            signed_delivery(
                payload, webhook_id="msg_diag", auth_header_value=wrong_value
            ),
            Delivery(b"{}", {"user-agent": "scanner/1.0"}),
        ]
        receiver_logger = logging.getLogger("mondoo-receiver")
        receiver_logger.disabled = False
        try:
            with self.assertLogs(receiver_logger, level="WARNING") as captured:
                await post_webhooks(FakeBackends(), deliveries)
        finally:
            receiver_logger.disabled = True

        rejections = [m for m in captured.output if "Webhook abgewiesen" in m]
        wrong_header, not_from_mondoo = rejections
        self.assertIn("Wert stimmt nicht", wrong_header)
        self.assertIn("Signatur: gueltig (webhook-id msg_diag)", wrong_header)
        self.assertIn("Auth-Header: fehlt", not_from_mondoo)
        self.assertIn("Signatur-Header fehlen", not_from_mondoo)
        self.assertIn("scanner/1.0", not_from_mondoo)
        expected_value = os.environ["MONDOO_WEBHOOK_AUTH_HEADER_VALUE"]
        for message in captured.output:
            self.assertNotIn("falsches-token-4711", message)
            self.assertNotIn(expected_value.split()[-1], message)

    async def test_servicenow_errors_are_reported_as_bad_gateway(self) -> None:
        payload = load_fixture("case_created_vulnerability.json")
        token_rejected = FakeBackends(token_status=401)
        lookup_forbidden = FakeBackends(lookup_status=403)
        receiver_logger = logging.getLogger("mondoo-receiver")
        receiver_logger.disabled = False
        try:
            with self.assertLogs(receiver_logger, level="ERROR") as captured:
                (token_response,) = await post_webhooks(token_rejected, [payload])
            (lookup_response,) = await post_webhooks(lookup_forbidden, [payload])
        finally:
            receiver_logger.disabled = True

        self.assertEqual(token_response.status_code, 502)
        self.assertEqual(lookup_response.status_code, 502)
        self.assertEqual(token_rejected.find("servicenow", "POST", "/order_now"), [])
        token_log = next(m for m in captured.output if "OAuth-Token" in m)
        self.assertIn("HTTP 401", token_log)
        self.assertIn("error_description='access_denied'", token_log)
        self.assertIn("Leerzeichen am Rand in: keine", token_log)
        for secret in ("SNOW_CLIENT_SECRET", "SNOW_PASSWORD"):
            self.assertNotIn(os.environ[secret], token_log)

    async def test_startup_logs_effective_configuration(self) -> None:
        receiver_logger = logging.getLogger("mondoo-receiver")
        receiver_logger.disabled = False
        try:
            with self.assertLogs(receiver_logger, level="INFO") as captured:
                await post_webhooks(FakeBackends(), [])
        finally:
            receiver_logger.disabled = True

        startup = next(m for m in captured.output if "Auth-Modus" in m)
        self.assertIn("https://dummy-instance.service-now.com", startup)
        self.assertIn("'oauth'", startup)
        self.assertIn("Angefordert fuer: angemeldeter Benutzer", startup)
        for secret in ("SNOW_PASSWORD", "MONDOO_WEBHOOK_AUTH_HEADER_VALUE"):
            self.assertNotIn(os.environ[secret], startup)

    async def test_rejected_order_logs_the_sent_body(self) -> None:
        receiver_logger = logging.getLogger("mondoo-receiver")
        receiver_logger.disabled = False
        try:
            with self.assertLogs(receiver_logger, level="ERROR") as captured:
                (response,) = await post_webhooks(
                    FakeBackends(order_status=400),
                    [load_fixture("case_created_vulnerability.json")],
                )
        finally:
            receiver_logger.disabled = True

        self.assertEqual(response.status_code, 502)
        header_log = next(m for m in captured.output if "Gesendete Header" in m)
        self.assertIn("'authorization': '<gesetzt>'", header_log)
        self.assertNotIn("cookie", header_log)
        order_log = next(m for m in captured.output if "order_now abgelehnt" in m)
        self.assertIn('"sysparm_quantity": "1"', order_log)
        self.assertIn('"mondoo_title": "Mondoo - [CRITICAL] CVE-2024-0056"', order_log)
        self.assertIn('"number_of_affected_assets": "4"', order_log)

    async def test_no_session_cookies_are_sent_to_servicenow(self) -> None:
        backends = FakeBackends(finding_nodes=[CVE_NODE])

        (response,) = await post_webhooks(
            backends, [load_fixture("case_created_vulnerability.json")]
        )

        self.assertEqual(response.json()["action"], "created")
        servicenow = [r for r in backends.requests if r.service == "servicenow"]
        self.assertGreater(len(servicenow), 1)
        self.assertEqual([r.cookie for r in servicenow], [None] * len(servicenow))

    async def test_authenticated_but_invalid_payloads(self) -> None:
        backends = FakeBackends()
        missing_mrn, not_json = await post_webhooks(
            backends,
            [{"body": {"case": {}}}, signed_delivery(b"kein json")],
        )
        self.assertEqual(missing_mrn.status_code, 422)
        self.assertEqual(not_json.status_code, 422)
        self.assertEqual(backends.requests, [])

    async def test_secret_in_url_path_is_no_longer_accepted(self) -> None:
        delivery = signed_delivery(load_fixture("case_created_vulnerability.json"))
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://t"
        ) as client:
            response = await client.post(
                "/webhook/mondoo/dummy-secret-segment",
                content=delivery.body,
                headers=delivery.headers,
            )
        self.assertIn(response.status_code, (404, 405))


if __name__ == "__main__":
    unittest.main()
