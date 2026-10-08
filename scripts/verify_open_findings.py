"""Prueft, ob die Mondoo-API offene Findings je Asset melden kann.

Grundlage fuer die geplante Pruefung bei TYPE_CLOSED: Ist ein Finding auf einem
Asset des Case noch offen (nicht behoben, keine Ausnahme)? Das Skript zaehlt je
Scope die Knoten fuer die Zustaende OPEN, CLOSED, EXCEPTION und ALL.

In Kudu SSH ausfuehren:

    python3 verify_open_findings.py <findingMrn> <assetMrn> [<assetMrn> ...]

Erwartung: Asset-MRN als Scope wird akzeptiert (kein Fehler, ALL >= 1);
behobenes Finding OPEN 0 / CLOSED 1, ausgenommenes OPEN 0 / EXCEPTION 1,
offenes OPEN 1.
"""

import json
import os
import sys
import urllib.error
import urllib.request

ENDPOINT = "https://eu.api.mondoo.com/query"
KEY = os.environ["MONDOO_API_KEY"]
STATES = ("OPEN", "CLOSED", "EXCEPTION", "ALL")

DOCUMENT = """
query OpenFindings(
  $scopeMrn: String!, $findingMrn: String!, $state: ScoreStateFilter!
) {
  findings(scopeMrn: $scopeMrn, first: 5, filter: {mrn: $findingMrn, state: $state}) {
    ... on FindingsConnection { totalCount edges { node { __typename } } }
    ... on RequestError { message }
    ... on NotFoundError { message }
  }
}
"""


def query(scope_mrn: str, finding_mrn: str, state: str) -> str:
    variables = {"scopeMrn": scope_mrn, "findingMrn": finding_mrn, "state": state}
    payload = json.dumps({"query": DOCUMENT, "variables": variables}).encode()
    request = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.load(response)
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}: {exc.read().decode()[:200]}"
    if body.get("errors"):
        return "FEHLER " + json.dumps(body["errors"])[:200]
    result = (body.get("data") or {}).get("findings") or {}
    if "message" in result:
        return f"Meldung: {result['message']}"
    types = sorted({e["node"].get("__typename") for e in result.get("edges") or []})
    return f"{result.get('totalCount')} ({', '.join(types) or '-'})"


def space_of(asset_mrn: str) -> str:
    """Space-MRN zur Asset-MRN, zum Vergleich mit dem bisherigen Scope."""
    space_id = asset_mrn.split("/spaces/", 1)[1].split("/", 1)[0]
    return f"//captain.api.mondoo.app/spaces/{space_id}"


if len(sys.argv) < 3:
    sys.exit(__doc__)

finding = sys.argv[1]
assets = sys.argv[2:]
print(f"Finding: {finding}")
for scope in [*assets, space_of(assets[0])]:
    print(f"\nScope {scope}")
    for state in STATES:
        print(f"  {state:<9} {query(scope, finding, state)}")
