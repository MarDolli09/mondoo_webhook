"""Ende-zu-Ende: Webhook -> Parsing -> ServiceNow gegen Attrappen."""

import copy
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

CVSS_NODE = {
    "__typename": "CveFinding",
    "mrn": "//vadvisor.api.mondoo.app/cves/CVE-2024-0056",
    "cveCvss": {"value": 8.1, "rating": "HIGH"},
}
from tests.test_mapping import FORM_VARIABLES  # noqa: E402


class WebhookFlowTest(unittest.IsolatedAsyncioTestCase):
    async def test_created_vulnerability_orders_ritm(self) -> None:
        backends = FakeBackends(cvss_nodes=[CVSS_NODE])
        (response,) = await post_webhooks(
            backends, [load_fixture("case_created_vulnerability.json")]
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["action"], "created")
        (order,) = backends.find("servicenow", "POST", "/order_now")
        variables = order.body["variables"]
        self.assertEqual(list(variables), FORM_VARIABLES)
        self.assertEqual(variables["assets_count"], "4")
        self.assertEqual(variables["urgency"], "2")
        self.assertEqual(
            variables["mondoo_title"],
            "Mondoo - Mitigate vulnerability CVE-2024-0056 on multiple assets",
        )
        self.assertEqual(variables["cvss_rating"], "HIGH")
        (patch,) = backends.find("servicenow", "PATCH", "/sc_req_item/")
        self.assertEqual(patch.body["short_description"], variables["mondoo_title"])
        self.assertNotIn("urgency", patch.body)
        self.assertNotIn("assignment_group", patch.body)
        self.assertEqual(
            patch.body["watch_list"], "usr-lars.siefert@mosca.com,usr-Marius Dollinger"
        )
        self.assertEqual(backends.find("servicenow", "GET", "sys_user_group"), [])

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
        self.assertEqual([r for r in backends.requests if r.service == "mondoo"], [])

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
        backends = FakeBackends(cvss_nodes=[CVSS_NODE])

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
