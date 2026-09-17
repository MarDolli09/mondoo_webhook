"""Attrappen fuer Mondoo und ServiceNow sowie End-to-End-Aufrufe des Webhooks."""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Optional
from unittest import mock
from urllib.parse import parse_qsl

import httpx

from tests import FIXTURES

__all__ = ["FakeBackends", "RecordedRequest", "load_fixture", "post_webhooks"]

MONDOO_ENDPOINT = "https://eu.api.mondoo.com/query"
SECRET = "dummy-webhook-secret-000"


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


@dataclass
class FakeBackends:
    """Antwortet wie Mondoo GraphQL und ServiceNow REST und zeichnet Requests auf."""

    ritms_by_correlation_id: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    cvss_nodes: list[dict[str, Any]] = field(default_factory=list)
    requests: list[RecordedRequest] = field(default_factory=list)
    token_fetches: int = 0

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
            return self._findings_page()

        self.requests.append(
            RecordedRequest(
                "servicenow", request.method, request.url.path, params, body
            )
        )
        return self._servicenow(request.method, request.url.path, params, body)

    def _findings_page(self) -> httpx.Response:
        edges = [{"node": node} for node in self.cvss_nodes]
        page = {"pageInfo": {"hasNextPage": False, "endCursor": None}, "edges": edges}
        return httpx.Response(200, json={"data": {"findings": page}})

    def _servicenow(
        self, method: str, path: str, params: dict[str, str], body: Any
    ) -> httpx.Response:
        query = params.get("sysparm_query", "")
        if path == "/oauth_token.do":
            self.token_fetches += 1
            token = {"access_token": f"tok-{self.token_fetches}", "expires_in": 1800}
            return httpx.Response(200, json=token)
        if path == "/api/now/table/sc_req_item" and query.startswith("correlation_id="):
            cid = query[len("correlation_id=") :].split("^ORDERBY")[0]
            records = self.ritms_by_correlation_id.get(cid, [])
            return httpx.Response(200, json={"result": records})
        if path == "/api/now/table/sc_req_item" and query.startswith("request="):
            ritm = {"sys_id": "ritm-new", "number": "RITM0100001"}
            return httpx.Response(200, json={"result": [ritm]})
        if path == "/api/now/table/sys_user":
            identifier = query.split("^")[0].split("=", 1)[1]
            return httpx.Response(
                200, json={"result": [{"sys_id": f"usr-{identifier}"}]}
            )
        if path.endswith("/order_now"):
            result = {"request_id": "req-new", "request_number": "REQ0100001"}
            return httpx.Response(200, json={"result": result})
        if method == "PATCH":
            sys_id = path.rsplit("/", 1)[1]
            state = (body or {}).get("state", "1")
            result = {"sys_id": sys_id, "number": "RITM0100001", "state": state}
            return httpx.Response(200, json={"result": result})
        return httpx.Response(404, json={"error": f"nicht gemockt: {method} {path}"})


async def post_webhooks(
    backends: FakeBackends,
    payloads: Sequence[dict[str, Any]],
    secret: Optional[str] = None,
) -> list[httpx.Response]:
    """Startet die App mit Lifespan und sendet die Payloads nacheinander."""
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
                for payload in payloads:
                    response = await client.post(
                        f"/webhook/mondoo/{secret or SECRET}", json=payload
                    )
                    responses.append(response)
    return responses
