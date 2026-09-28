"""Prueft die Abfrage aus app/services/mondoo/queries.py gegen die echte API.

In Kudu SSH ausfuehren: python3 verify_scores.py
"""

import json
import os
import urllib.request

ENDPOINT = "https://eu.api.mondoo.com/query"
KEY = os.environ["MONDOO_API_KEY"]

SPACE_MRN = "//captain.api.mondoo.app/spaces/eu-elastic-hodgkin-413342"
FINDINGS = [
    "//vadvisor.api.mondoo.app/cves/CVE-2026-23450",
    "//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-DOTNET-8",
    "//policy.api.mondoo.app/queries/cis-microsoft-azure-foundations--8.3.2",
]

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
            cvss { value rating }
          }
          ... on AdvisoryFinding {
            mrn
            riskValue
            rating
            cvss { value rating }
          }
          ... on PackageFinding {
            mrn
            riskValue
            rating
            cvss { value rating }
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
    cvss = node.get("cvss") or {}
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


for finding_mrn in FINDINGS:
    payload = json.dumps(
        {
            "query": DOCUMENT,
            "variables": {
                "scopeMrn": SPACE_MRN,
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
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)

    print(f"\n=== {finding_mrn}")
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
