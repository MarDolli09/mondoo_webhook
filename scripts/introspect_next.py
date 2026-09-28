"""Klaert, welche weiteren Daten die Mondoo-API direkt liefern kann.

In Kudu SSH ausfuehren: python3 introspect_next.py
"""

import json
import os
import urllib.request

ENDPOINT = "https://eu.api.mondoo.com/query"
KEY = os.environ["MONDOO_API_KEY"]

# Typen, deren Felder interessieren
TYPES = [
    "Query",  # welche Wurzel-Abfragen es gibt (space, user, case, findings)
    "Space",  # Anzeigename statt CATEGORY_MAP
    "Author",  # Name/E-Mail zur createdBy-MRN statt USER_MAP
    "User",
    "FindingsFilter",  # mrns-Liste fuer eine Sammelabfrage
    "CveFinding",  # epss, riskFactors, cvss
    "AdvisoryFinding",  # zugehoerige CVEs
]

DOCUMENT = """
query Types($name: String!) {
  __type(name: $name) {
    name
    kind
    fields { name type { name kind ofType { name kind ofType { name } } } }
    inputFields { name type { name kind ofType { name kind ofType { name } } } }
  }
}
"""


def type_name(node):
    while node:
        if node.get("name"):
            return node["name"]
        node = node.get("ofType")
    return "?"


def query(name):
    payload = json.dumps({"query": DOCUMENT, "variables": {"name": name}}).encode()
    request = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


for name in TYPES:
    body = query(name)
    if body.get("errors"):
        print(f"\n=== {name}: FEHLER {json.dumps(body['errors'])[:200]}")
        continue
    info = (body.get("data") or {}).get("__type")
    if not info:
        print(f"\n=== {name}: existiert nicht")
        continue
    print(f"\n=== {name} ({info['kind']})")
    for field in (info.get("fields") or []) + (info.get("inputFields") or []):
        print(f"    {field['name']}: {type_name(field.get('type'))}")
