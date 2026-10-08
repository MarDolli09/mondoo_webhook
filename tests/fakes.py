"""Attrappen fuer Mondoo und ServiceNow sowie End-to-End-Aufrufe des Webhooks."""

import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Optional, Union
from unittest import mock
from urllib.parse import parse_qsl

import httpx

from app.core.webhook_signature import decode_signing_secret, sign_delivery
from tests import FIXTURES

__all__ = [
    "Delivery",
    "FakeBackends",
    "RecordedRequest",
    "load_fixture",
    "post_webhooks",
    "signed_delivery",
]

MONDOO_ENDPOINT = "https://eu.api.mondoo.com/query"
WEBHOOK_PATH = "/webhook/mondoo"
SIGNING_SECRET = os.environ["MONDOO_WEBHOOK_SIGNING_SECRET"]
AUTH_HEADER_VALUE = os.environ["MONDOO_WEBHOOK_AUTH_HEADER_VALUE"]


@dataclass(frozen=True)
class Delivery:
    """Eine Zustellung, wie Mondoo sie sendet: roher Body und Header."""

    body: bytes
    headers: dict[str, str]


def signed_delivery(
    payload: Union[dict[str, Any], bytes],
    *,
    webhook_id: str = "msg_test_0001",
    timestamp: Optional[int] = None,
    secret: str = SIGNING_SECRET,
    auth_header_value: Optional[str] = AUTH_HEADER_VALUE,
) -> Delivery:
    """Signiert eine Zustellung nach Standard Webhooks.

    ``auth_header_value=None`` laesst den Auth-Header weg.
    """
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    sent_at = int(time.time()) if timestamp is None else timestamp
    headers = {
        "content-type": "application/json",
        "webhook-id": webhook_id,
        "webhook-timestamp": str(sent_at),
        "webhook-signature": sign_delivery(
            decode_signing_secret(secret), webhook_id, sent_at, body
        ),
    }
    if auth_header_value is not None:
        headers["Authorization"] = auth_header_value
    return Delivery(body=body, headers=headers)


def load_fixture(name: str) -> dict[str, Any]:
    """Laedt einen Beispiel-Payload aus ``tests/fixtures``."""
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return data


@dataclass
class RecordedRequest:
    """Ein an eine Attrappe gesendeter Request."""

    service: str
    method: str
    path: str
    params: dict[str, str]
    body: Any
    cookie: Optional[str] = None


@dataclass
class FakeBackends:
    """Antwortet wie Mondoo GraphQL und ServiceNow REST und zeichnet Requests auf."""

    ritms_by_correlation_id: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    finding_nodes: list[dict[str, Any]] = field(default_factory=list)
    # SCTASKs, die der Workflow zum neuen RITM anlegt (mit Assignment Group)
    catalog_tasks: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {
                "sys_id": "task-1",
                "number": "SCTASK0100001",
                "short_description": "Mondoo Vulnerability - Server",
                "assignment_group": "grp-server",
            }
        ]
    )
    requests: list[RecordedRequest] = field(default_factory=list)
    token_fetches: int = 0
    mondoo_status: int = 200
    token_status: int = 200
    lookup_status: int = 200
    order_status: int = 200
    task_status: int = 200
    # Ziele, die statt JSON eine HTML-Seite liefern: "mondoo", "token", "lookup"
    html_for: frozenset[str] = frozenset()

    def transport(self) -> httpx.MockTransport:
        """httpx-Transport, der alle Requests an diese Attrappen leitet."""
        return httpx.MockTransport(self._handle)

    def find(self, service: str, method: str, fragment: str) -> list[RecordedRequest]:
        """Aufgezeichnete Requests eines Dienstes, deren Pfad ``fragment`` enthaelt."""
        return [
            r
            for r in self.requests
            if r.service == service and r.method == method and fragment in r.path
        ]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        params = dict(parse_qsl(request.url.query.decode()))
        raw = request.content
        body: Any = None
        if raw:
            is_json = "json" in request.headers.get("content-type", "")
            body = json.loads(raw) if is_json else dict(parse_qsl(raw.decode()))

        if str(request.url).startswith(MONDOO_ENDPOINT):
            self.requests.append(RecordedRequest("mondoo", "POST", "", {}, body))
            return _html_page() if "mondoo" in self.html_for else self._findings()

        self.requests.append(
            RecordedRequest(
                "servicenow",
                request.method,
                request.url.path,
                params,
                body,
                cookie=request.headers.get("cookie"),
            )
        )
        if _html_target(request.url.path, params) in self.html_for:
            response = _html_page()
        else:
            response = self._servicenow(request.method, request.url.path, params, body)
        # ServiceNow setzt bei jedem Aufruf ein Sitzungs-Cookie.
        response.headers["set-cookie"] = "JSESSIONID=ABC123; Path=/; HttpOnly"
        return response

    def _findings(self) -> httpx.Response:
        if self.mondoo_status != 200:
            # So lehnt Mondoo eine Abfrage ab, die nicht zum Schema passt;
            # dieselbe Meldung kommt je betroffenem Fragmentpaar.
            conflict = {
                "message": 'Fields "cvss" conflict because they return '
                'conflicting types "CvssScore" and "CvssScore!".',
                "locations": [{"line": 25, "column": 13}],
                "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
            }
            return httpx.Response(
                self.mondoo_status, json={"errors": [conflict, conflict]}
            )
        findings = {
            "totalCount": len(self.finding_nodes),
            "edges": [{"node": node} for node in self.finding_nodes],
        }
        return httpx.Response(200, json={"data": {"findings": findings}})

    def _servicenow(
        self, method: str, path: str, params: dict[str, str], body: Any
    ) -> httpx.Response:
        query = params.get("sysparm_query", "")
        if path == "/oauth_token.do":
            return self._token()
        if self.lookup_status != 200 and query.startswith("correlation_id="):
            return httpx.Response(self.lookup_status, json={"error": "simuliert"})
        if path == "/api/now/table/sc_req_item" and query.startswith("correlation_id="):
            cid = query[len("correlation_id=") :].split("^ORDERBY")[0]
            records = self.ritms_by_correlation_id.get(cid, [])
            return httpx.Response(200, json={"result": records})
        if path == "/api/now/table/sc_req_item" and query.startswith("request="):
            ritm = {"sys_id": "ritm-new", "number": "RITM0100001"}
            return httpx.Response(200, json={"result": [ritm]})
        if path.startswith("/api/now/table/sc_task"):
            return self._catalog_tasks(method, path, query, body)
        if path == "/api/now/table/sys_user":
            identifier = query.split("^")[0].split("=", 1)[1]
            return httpx.Response(
                200, json={"result": [{"sys_id": f"usr-{identifier}"}]}
            )
        if path.endswith("/order_now"):
            if self.order_status != 200:
                order_error = {
                    "error": {
                        "message": "Security constraints prevent ordering of Item"
                    },
                    "status": "failure",
                }
                return httpx.Response(self.order_status, json=order_error)
            result = {"request_id": "req-new", "request_number": "REQ0100001"}
            return httpx.Response(200, json={"result": result})
        if method == "PATCH":
            sys_id = path.rsplit("/", 1)[1]
            state = (body or {}).get("state", "1")
            result = {"sys_id": sys_id, "number": "RITM0100001", "state": state}
            return httpx.Response(200, json={"result": result})
        return httpx.Response(404, json={"error": f"nicht gemockt: {method} {path}"})

    def _token(self) -> httpx.Response:
        self.token_fetches += 1
        if self.token_status != 200:
            oauth_error = {
                "error": "server_error",
                "error_description": "access_denied",
            }
            return httpx.Response(self.token_status, json=oauth_error)
        token = {"access_token": f"tok-{self.token_fetches}", "expires_in": 1800}
        return httpx.Response(200, json=token)

    def _catalog_tasks(
        self, method: str, path: str, query: str, body: Any
    ) -> httpx.Response:
        if self.task_status != 200:
            return httpx.Response(self.task_status, json={"error": "simuliert"})
        if method == "GET":
            tasks = list(self.catalog_tasks)
            # Wie ServiceNow: nur Tasks, deren Assignment Group schon gesetzt ist
            if "assignment_groupISNOTEMPTY" in query:
                tasks = [t for t in tasks if t.get("assignment_group")]
            if "active=true" in query:
                tasks = [t for t in tasks if t.get("active", "true") == "true"]
            return httpx.Response(200, json={"result": tasks})
        sys_id = path.rsplit("/", 1)[1]
        task = next(t for t in self.catalog_tasks if t["sys_id"] == sys_id)
        task.update(body or {})
        return httpx.Response(200, json={"result": task})


def _html_target(path: str, params: dict[str, str]) -> str:
    """Ziel eines ServiceNow-Requests im Sinne von ``FakeBackends.html_for``."""
    if path == "/oauth_token.do":
        return "token"
    if params.get("sysparm_query", "").startswith("correlation_id="):
        return "lookup"
    return ""


def _html_page() -> httpx.Response:
    """Antwort einer ruhenden Instanz: Status 200, aber HTML statt JSON."""
    return httpx.Response(
        200,
        text="<html><body>Instance hibernating</body></html>",
        headers={"content-type": "text/html"},
    )


async def post_webhooks(
    backends: FakeBackends,
    deliveries: Sequence[Union[dict[str, Any], Delivery]],
) -> list[httpx.Response]:
    """Startet die App mit Lifespan und sendet die Zustellungen nacheinander.

    Payloads (dict) werden gueltig signiert; ``Delivery`` wird unveraendert gesendet.
    """
    from app.main import app

    original_client = httpx.AsyncClient
    transport = backends.transport()

    class BackendClient(original_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    responses = []
    with mock.patch.object(httpx, "AsyncClient", BackendClient):
        async with app.router.lifespan_context(app):
            asgi = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with original_client(
                transport=asgi, base_url="http://testserver"
            ) as client:
                for index, item in enumerate(deliveries):
                    delivery = (
                        item
                        if isinstance(item, Delivery)
                        else signed_delivery(item, webhook_id=f"msg_test_{index:04d}")
                    )
                    response = await client.post(
                        WEBHOOK_PATH, content=delivery.body, headers=delivery.headers
                    )
                    responses.append(response)
    return responses
