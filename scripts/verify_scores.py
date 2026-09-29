"""Prueft die Abfrage aus app/services/mondoo/queries.py gegen die echte API.

In Kudu SSH ausfuehren:

    python3 verify_scores.py                         # Beispiel-Findings im Space
    python3 verify_scores.py <findingMrn> [scope ...] # ein Finding, beliebige Scopes
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

ENDPOINT = "https://eu.api.mondoo.com/query"
KEY = os.environ["MONDOO_API_KEY"]
# Dasselbe Limit wie HTTP_TIMEOUT_SECONDS der App
APP_TIMEOUT_SECONDS = 10.0

SPACE_MRN = "//captain.api.mondoo.app/spaces/eu-elastic-hodgkin-413342"
FINDINGS = [
    "//vadvisor.api.mondoo.app/cves/CVE-2026-23450",
    "//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-DOTNET-8",
    "//policy.api.mondoo.app/queries/cis-microsoft-azure-foundations--8.3.2",
]

if len(sys.argv) > 1:
    FINDINGS = [sys.argv[1]]
    SCOPES = sys.argv[2:] or [SPACE_MRN]
else:
    SCOPES = [SPACE_MRN]

DOCUMENT = """
query GetFindingScores($scopeMrn: String!, $findingMrn: String!, $first: Int!) {
  findings(scopeMrn: $scopeMrn, first: $first, filter: {mrn: $findingMrn}) {
    ... on FindingsConnection {
      totalCount
      edges {
        node {
          __typename
          ... on CveFinding {
            mrn
            riskValue
            rating
            cveCvss: cvss { value rating }
          }
          ... on AdvisoryFinding {
            mrn
            riskValue
            rating
            advisoryCvss: cvss { value rating }
          }
          ... on PackageFinding {
            mrn
            riskValue
            rating
            packageCvss: cvss { value rating }
          }
          ... on CheckFinding {
            mrn
            riskValue
            rating
          }
          ... on GenericFinding {
            mrn
            riskValue
            rating
          }
        }
      }
    }
    ... on RequestError { message }
    ... on NotFoundError { message }
  }
}
"""


def scores(node):
    """Dieselbe Ableitung wie app/services/mondoo/findings.py."""
    cvss = next(
        (node[k] for k in ("cveCvss", "advisoryCvss", "packageCvss") if node.get(k)),
        {},
    )
    value = cvss.get("value")
    cvss_score = None
    if isinstance(value, (int, float)) and value > 0:
        cvss_score = f"{(value / 10.0 if value > 10 else value):.1f}"
    rating = cvss.get("rating")
    if rating in (None, "NONE", "NONE - EOL") or not cvss_score:
        rating = None
    risk = node.get("riskValue")
    risk_score = str(round(risk)) if isinstance(risk, (int, float)) else None
    risk_rating = node.get("rating")
    if risk_rating in ("NONE", "NONE - EOL"):
        risk_rating = None
    return cvss_score, rating, risk_score, risk_rating


for finding_mrn, scope_mrn in [(f, s) for f in FINDINGS for s in SCOPES]:
    payload = json.dumps(
        {
            "query": DOCUMENT,
            "variables": {
                "scopeMrn": scope_mrn,
                "findingMrn": finding_mrn,
                "first": 100,
            },
        }
    ).encode()
    request = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    print(f"\n=== {finding_mrn}")
    print(f"  Scope: {scope_mrn}")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.load(response)
    except urllib.error.HTTPError as exc:
        print(f"  HTTP {exc.code}: {exc.read().decode(errors='replace')[:1000]}")
        continue
    elapsed = time.monotonic() - started

    note = " (App-Timeout ueberschritten!)" if elapsed > APP_TIMEOUT_SECONDS else ""
    print(f"  Dauer: {elapsed:.1f}s{note}")
    if body.get("errors"):
        print(f"  FEHLER: {json.dumps(body['errors'])[:400]}")
        continue
    findings = (body.get("data") or {}).get("findings") or {}
    if "message" in findings:
        print(f"  Union-Fehler: {findings['message']}")
        continue
    nodes = [e["node"] for e in findings.get("edges") or [] if e.get("node")]
    print(f"  totalCount={findings.get('totalCount')} Knoten={len(nodes)}")
    best = None
    for node in nodes:
        cvss_score, cvss_rating, risk_score, risk_rating = scores(node)
        if best is None or int(risk_score or 0) > int(best[2] or 0):
            best = (cvss_score, cvss_rating, risk_score, risk_rating)
        print(f"    {node.get('__typename')}: {json.dumps(node)[:160]}")
    if best:
        print(
            f"  -> Ticket: cvss_score={best[0]} cvss_risk_rating={best[1]} "
            f"mondoo_risk_score={best[2]} mondoo_risk_rating={best[3]}"
        )
