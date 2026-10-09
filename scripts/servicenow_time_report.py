"""Zeitbuchungen und Durchlaufzeiten der Mondoo-RITMs aus ServiceNow, nur lesend.

Liest ueber die Table API:
- die RITMs des Katalog-Items SNOW_CATALOG_ITEM_SYS_ID (opened_at, closed_at,
  Feld time_worked),
- deren SCTASKs (Gruppe, Zeitpunkte, Feld time_worked),
- deren Zeiteintraege aus task_time_worked (Zeit, Erfasser, Zeitpunkt, Kommentar).

Schreibt ritms.csv, sctasks.csv und zeitbuchungen.csv (Semikolon, Dezimalkomma,
UTF-8 mit BOM fuer Excel; Zeitpunkte in UTC). Erfasser werden standardmaessig
pseudonymisiert (Bearbeiter 1, 2, ...); --namen schreibt die echten Namen.

In Kudu SSH ausfuehren, die Zugangsdaten stehen dort als App-Einstellungen:

    python3 servicenow_time_report.py --ziel /home/data/zeiten [--seit 2026-10-01]

Voraussetzung: SNOW_USER darf sc_req_item, sc_task und task_time_worked lesen.
Ohne Leserecht auf task_time_worked bleibt zeitbuchungen.csv leer; dann den
CSV-Export der Liste aus der Oberflaeche nutzen. Die Feldnamen von
task_time_worked entsprechen dem Standard und sind auf der Instanz zu bestaetigen.
"""

import argparse
import base64
import csv
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

BASE_URL = os.environ["SNOW_INSTANCE_URL"].rstrip("/")
USER = os.environ["SNOW_USER"]
PASSWORD = os.environ["SNOW_PASSWORD"]
AUTH_MODE = os.environ.get("SNOW_AUTH_MODE", "basic").strip().lower()
CATALOG_ITEM = os.environ["SNOW_CATALOG_ITEM_SYS_ID"]

PAGE_SIZE = 200
IN_CHUNK = 50
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
# Dauerfelder speichert ServiceNow als Zeitpunkt ab 1970-01-01 00:00:00
DURATION_EPOCH = datetime(1970, 1, 1)

Record = dict[str, Any]


def authorization() -> str:
    if AUTH_MODE != "oauth":
        token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        return f"Basic {token}"
    form = {
        "grant_type": "password",
        "client_id": os.environ["SNOW_CLIENT_ID"],
        "client_secret": os.environ["SNOW_CLIENT_SECRET"],
        "username": USER,
        "password": PASSWORD,
    }
    request = urllib.request.Request(
        f"{BASE_URL}/oauth_token.do",
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return f"Bearer {json.load(response)['access_token']}"


def table(auth: str, name: str, query: str, fields: str) -> list[Record]:
    """Alle Datensaetze einer encoded query, seitenweise, mit Wert und Anzeige."""
    records: list[Record] = []
    offset = 0
    while True:
        params = urllib.parse.urlencode(
            {
                "sysparm_query": query,
                "sysparm_fields": fields,
                "sysparm_display_value": "all",
                "sysparm_exclude_reference_link": "true",
                "sysparm_limit": PAGE_SIZE,
                "sysparm_offset": offset,
            }
        )
        request = urllib.request.Request(
            f"{BASE_URL}/api/now/table/{name}?{params}",
            headers={"Authorization": auth, "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            page = json.load(response).get("result") or []
        records += page
        if len(page) < PAGE_SIZE:
            return records
        offset += PAGE_SIZE


def table_in(
    auth: str, name: str, field: str, ids: list[str], fields: str
) -> list[Record]:
    """Datensaetze, deren ``field`` in ``ids`` liegt, in Teilmengen abgefragt."""
    records: list[Record] = []
    for start in range(0, len(ids), IN_CHUNK):
        chunk = ",".join(ids[start : start + IN_CHUNK])
        records += table(auth, name, f"{field}IN{chunk}^ORDERBYsys_created_on", fields)
    return records


def value(record: Record, field: str) -> str:
    return str((record.get(field) or {}).get("value") or "")


def shown(record: Record, field: str) -> str:
    return str((record.get(field) or {}).get("display_value") or "")


def timestamp(text: str) -> Optional[datetime]:
    return datetime.strptime(text, TIMESTAMP_FORMAT) if text else None


def duration_seconds(record: Record, field: str) -> float:
    moment = timestamp(value(record, field))
    return (moment - DURATION_EPOCH).total_seconds() if moment else 0.0


def hours_between(start: str, end: str) -> Optional[float]:
    opened, closed = timestamp(start), timestamp(end)
    if not opened or not closed:
        return None
    return (closed - opened).total_seconds() / 3600


def number(amount: Optional[float]) -> str:
    return "" if amount is None else f"{amount:.2f}".replace(".", ",")


def write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ziel", default=".", help="Verzeichnis fuer die CSV-Dateien")
    parser.add_argument("--seit", help="nur RITMs ab diesem Datum (JJJJ-MM-TT)")
    parser.add_argument(
        "--namen", action="store_true", help="Erfasser nicht pseudonymisieren"
    )
    args = parser.parse_args()
    target = Path(args.ziel)
    target.mkdir(parents=True, exist_ok=True)
    auth = authorization()

    query = f"cat_item={CATALOG_ITEM}"
    if args.seit:
        query += f"^opened_at>=javascript:gs.dateGenerate('{args.seit}','00:00:00')"
    ritms = table(
        auth,
        "sc_req_item",
        f"{query}^ORDERBYopened_at",
        "sys_id,number,state,opened_at,closed_at,time_worked",
    )
    tasks = table_in(
        auth,
        "sc_task",
        "request_item",
        [value(r, "sys_id") for r in ritms],
        "sys_id,number,request_item,assignment_group,state,opened_at,closed_at,time_worked",
    )
    try:
        entries = table_in(
            auth,
            "task_time_worked",
            "task",
            [value(t, "sys_id") for t in tasks],
            "task,user,time_worked,time_in_seconds,comments,sys_created_on",
        )
    except urllib.error.HTTPError as exc:
        print(
            f"task_time_worked nicht lesbar (HTTP {exc.code}). "
            f"CSV-Export der Liste nutzen."
        )
        entries = []

    ritm_number = {value(r, "sys_id"): value(r, "number") for r in ritms}
    task_by_id = {value(t, "sys_id"): t for t in tasks}
    pseudonyms: dict[str, str] = {}

    def recorder(entry: Record) -> str:
        name = shown(entry, "user") or value(entry, "user")
        if args.namen:
            return name
        return pseudonyms.setdefault(name, f"Bearbeiter {len(pseudonyms) + 1}")

    booked_per_task: dict[str, float] = {}
    entry_rows = []
    for entry in entries:
        task = task_by_id.get(value(entry, "task"), {})
        seconds_text = value(entry, "time_in_seconds")
        seconds = (
            float(seconds_text)
            if seconds_text
            else duration_seconds(entry, "time_worked")
        )
        task_id = value(entry, "task")
        booked_per_task[task_id] = booked_per_task.get(task_id, 0.0) + seconds
        entry_rows.append(
            [
                ritm_number.get(value(task, "request_item"), ""),
                value(task, "number"),
                recorder(entry),
                value(entry, "sys_created_on"),
                number(seconds / 60),
                shown(entry, "comments"),
            ]
        )

    booked_per_ritm: dict[str, float] = {}
    task_rows = []
    for task in tasks:
        task_id, ritm_id = value(task, "sys_id"), value(task, "request_item")
        booked = booked_per_task.get(task_id, 0.0)
        booked_per_ritm[ritm_id] = booked_per_ritm.get(ritm_id, 0.0) + booked
        task_rows.append(
            [
                ritm_number.get(ritm_id, ""),
                value(task, "number"),
                shown(task, "assignment_group"),
                shown(task, "state"),
                value(task, "opened_at"),
                value(task, "closed_at"),
                number(
                    hours_between(value(task, "opened_at"), value(task, "closed_at"))
                ),
                number(duration_seconds(task, "time_worked") / 60),
                number(booked / 60),
            ]
        )

    ritm_rows = []
    for ritm in ritms:
        ritm_id = value(ritm, "sys_id")
        ritm_rows.append(
            [
                value(ritm, "number"),
                shown(ritm, "state"),
                value(ritm, "opened_at"),
                value(ritm, "closed_at"),
                number(
                    hours_between(value(ritm, "opened_at"), value(ritm, "closed_at"))
                ),
                sum(1 for t in tasks if value(t, "request_item") == ritm_id),
                number(duration_seconds(ritm, "time_worked") / 60),
                number(booked_per_ritm.get(ritm_id, 0.0) / 60),
            ]
        )

    write_csv(
        target / "ritms.csv",
        [
            "RITM",
            "Status",
            "Geoeffnet (UTC)",
            "Geschlossen (UTC)",
            "Durchlauf (h)",
            "SCTASKs",
            "Feld time_worked (min)",
            "Summe Zeiteintraege (min)",
        ],
        ritm_rows,
    )
    write_csv(
        target / "sctasks.csv",
        [
            "RITM",
            "SCTASK",
            "Gruppe",
            "Status",
            "Geoeffnet (UTC)",
            "Geschlossen (UTC)",
            "Durchlauf (h)",
            "Feld time_worked (min)",
            "Summe Zeiteintraege (min)",
        ],
        task_rows,
    )
    write_csv(
        target / "zeitbuchungen.csv",
        ["RITM", "SCTASK", "Erfasser", "Zeitpunkt (UTC)", "Minuten", "Kommentar"],
        entry_rows,
    )
    print(
        f"{len(ritms)} RITMs, {len(tasks)} SCTASKs, {len(entries)} Zeiteintraege "
        f"-> {target.resolve()}"
    )


if __name__ == "__main__":
    main()
