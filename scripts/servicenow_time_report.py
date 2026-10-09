"""Zeitbuchungen, Statuswechsel und Durchlaufzeiten der Mondoo-RITMs, nur lesend.

Liest ueber die Table API:
- die RITMs des Katalog-Items SNOW_CATALOG_ITEM_SYS_ID (opened_at, closed_at,
  closed_by, Feld time_worked),
- deren SCTASKs (Gruppe, Zeitpunkte, closed_by, Feld time_worked),
- deren Zeiteintraege aus task_time_worked (Zeit, Erfasser, Zeitpunkt, Kommentar),
- die Statuswechsel von RITMs und SCTASKs aus sys_audit (Feld state).

Schreibt ritms.csv, sctasks.csv, zeitbuchungen.csv und statuswechsel.csv
(Semikolon, Dezimalkomma, UTF-8 mit BOM fuer Excel; Zeitpunkte in UTC).

closed_at haelt nach einem Wiedereroeffnen den ersten Abschluss. Deshalb
rechnet sctasks.csv aus den Statuswechseln die Wiedereroeffnungen, den letzten
Abschluss und die offene Zeit (Summe aller Abschnitte ausserhalb eines
Endstatus). Die Rolle ergibt sich aus der Reihenfolge: der erste SCTASK eines
RITM ist der Behebungs-SCTASK, spaetere sind Pruef-SCTASKs.

Personen werden pseudonymisiert (Bearbeiter 1, 2, ...); --namen schreibt die
echten Namen. Die Middleware (SNOW_USER) und "system" bleiben erkennbar.

In Kudu SSH ausfuehren, die Zugangsdaten stehen dort als App-Einstellungen:

    python3 servicenow_time_report.py --ziel /home/data/zeiten [--seit 2026-10-01]

Fuer eine andere Instanz die Variablen beim Aufruf ueberschreiben, z. B.
SNOW_INSTANCE_URL=... SNOW_CATALOG_ITEM_SYS_ID=... python3 ...

Voraussetzung: SNOW_USER darf sc_req_item, sc_task, task_time_worked, sys_user
und sys_audit lesen. Fehlt das Recht auf task_time_worked oder sys_audit,
bleiben die zugehoerigen Spalten leer und das Skript meldet es.
"""

import argparse
import base64
import csv
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
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
CLOSED_STATES = frozenset({"3", "4", "7"})
STATE_LABELS = {
    "-5": "Pending",
    "1": "Open",
    "2": "Work in Progress",
    "3": "Closed Complete",
    "4": "Closed Incomplete",
    "7": "Closed Skipped",
}
AUDIT_FIELDS = "documentkey,tablename,oldvalue,newvalue,user,sys_created_on"

RITM_HEADER = [
    "RITM",
    "Status",
    "Geoeffnet (UTC)",
    "Geschlossen (UTC)",
    "Durchlauf (h)",
    "Geschlossen von",
    "SCTASKs",
    "Feld time_worked (min)",
    "Summe Zeiteintraege (min)",
]
TASK_HEADER = [
    "RITM",
    "SCTASK",
    "Rolle",
    "Gruppe",
    "Status",
    "Geoeffnet (UTC)",
    "closed_at (UTC)",
    "Durchlauf bis closed_at (h)",
    "Geschlossen von",
    "Wiedereroeffnungen",
    "Letzter Abschluss (UTC)",
    "Offene Zeit (h)",
    "Feld time_worked (min)",
    "Summe Zeiteintraege (min)",
]
ENTRY_HEADER = ["RITM", "SCTASK", "Erfasser", "Zeitpunkt (UTC)", "Minuten", "Kommentar"]
CHANGE_HEADER = ["Tabelle", "Nummer", "RITM", "Von", "Nach", "Zeitpunkt (UTC)", "Durch"]

Record = dict[str, Any]
Rows = list[list[Any]]


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
    auth: str, name: str, field_name: str, ids: list[str], fields: str, where: str = ""
) -> list[Record]:
    """Datensaetze, deren ``field_name`` in ``ids`` liegt, in Teilmengen abgefragt."""
    records: list[Record] = []
    for start in range(0, len(ids), IN_CHUNK):
        chunk = ",".join(ids[start : start + IN_CHUNK])
        query = f"{where}{field_name}IN{chunk}^ORDERBYsys_created_on"
        records += table(auth, name, query, fields)
    return records


def readable(label: str, fetch: Callable[[], list[Record]]) -> Optional[list[Record]]:
    """Fuehrt eine Abfrage aus; ``None``, wenn das Leserecht fehlt."""
    try:
        return fetch()
    except urllib.error.HTTPError as exc:
        print(f"{label} nicht lesbar (HTTP {exc.code}); Spalten bleiben leer.")
        return None


def value(record: Record, field_name: str) -> str:
    return str((record.get(field_name) or {}).get("value") or "")


def shown(record: Record, field_name: str) -> str:
    return str((record.get(field_name) or {}).get("display_value") or "")


def timestamp(text: str) -> Optional[datetime]:
    return datetime.strptime(text, TIMESTAMP_FORMAT) if text else None


def duration_seconds(record: Record, field_name: str) -> float:
    moment = timestamp(value(record, field_name))
    return (moment - DURATION_EPOCH).total_seconds() if moment else 0.0


def hours_between(start: str, end: str) -> Optional[float]:
    opened, closed = timestamp(start), timestamp(end)
    if not opened or not closed:
        return None
    return (closed - opened).total_seconds() / 3600


def number(amount: Optional[float]) -> str:
    return "" if amount is None else f"{amount:.2f}".replace(".", ",")


def phases(
    task: Record, events: list[Record]
) -> tuple[Optional[float], int, Optional[datetime]]:
    """Offene Zeit (h), Wiedereroeffnungen und letzter Abschluss eines SCTASK.

    Offene Zeit ist die Summe aller Abschnitte ausserhalb eines Endstatus;
    ``None``, solange der Task offen ist.
    """
    start = timestamp(value(task, "opened_at"))
    open_seconds, reopens, last_close, is_open = 0.0, 0, None, True
    for event in events:
        moment = timestamp(value(event, "sys_created_on"))
        closing = value(event, "newvalue") in CLOSED_STATES
        if is_open and closing and moment and start:
            open_seconds += (moment - start).total_seconds()
            last_close, is_open = moment, False
        elif not is_open and not closing:
            reopens, start, is_open = reopens + 1, moment, True
    return (None if is_open else open_seconds / 3600), reopens, last_close


def write_csv(path: Path, header: list[str], rows: Rows) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(header)
        writer.writerows(rows)


@dataclass
class Report:
    """Gelesene Datensaetze; ``None``, wenn eine Tabelle nicht lesbar ist."""

    ritms: list[Record]
    tasks: list[Record]
    entries: Optional[list[Record]]
    audits: Optional[list[Record]]
    users: list[Record]
    ritm_number: dict[str, str] = field(default_factory=dict)
    task_by_id: dict[str, Record] = field(default_factory=dict)
    events_by_doc: dict[str, list[Record]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.ritm_number = {value(r, "sys_id"): value(r, "number") for r in self.ritms}
        self.task_by_id = {value(t, "sys_id"): t for t in self.tasks}
        for event in self.audits or []:
            key = value(event, "documentkey")
            self.events_by_doc.setdefault(key, []).append(event)


def fetch(auth: str, since: Optional[str]) -> Report:
    query = f"cat_item={CATALOG_ITEM}"
    if since:
        query += f"^opened_at>=javascript:gs.dateGenerate('{since}','00:00:00')"
    ritms = table(
        auth,
        "sc_req_item",
        f"{query}^ORDERBYopened_at",
        "sys_id,number,state,opened_at,closed_at,closed_by,time_worked",
    )
    ritm_ids = [value(r, "sys_id") for r in ritms]
    tasks = table_in(
        auth,
        "sc_task",
        "request_item",
        ritm_ids,
        "sys_id,number,request_item,assignment_group,state,opened_at,closed_at,"
        "closed_by,time_worked",
    )
    task_ids = [value(t, "sys_id") for t in tasks]
    entries = readable(
        "task_time_worked",
        lambda: table_in(
            auth,
            "task_time_worked",
            "task",
            task_ids,
            "task,user,time_worked,time_in_seconds,comments,sys_created_on",
        ),
    )
    audits = readable(
        "sys_audit",
        lambda: table_in(
            auth,
            "sys_audit",
            "documentkey",
            ritm_ids + task_ids,
            AUDIT_FIELDS,
            where="fieldname=state^",
        ),
    )
    # sys_audit nennt den Benutzernamen, Referenzfelder den Anzeigenamen
    logins = ({USER} | {value(a, "user") for a in audits or []}) - {"", "system"}
    users = table_in(
        auth, "sys_user", "user_name", sorted(logins), "sys_id,user_name,name"
    )
    return Report(ritms, tasks, entries, audits, users)


class People:
    """Middleware und "system" bleiben erkennbar, Personen werden pseudonymisiert."""

    def __init__(self, users: list[Record], real_names: bool) -> None:
        self._name_by_login = {value(u, "user_name"): value(u, "name") for u in users}
        self._middleware_ids = {
            value(u, "sys_id") for u in users if value(u, "user_name") == USER
        }
        self._real_names = real_names
        self._pseudonyms: dict[str, str] = {}

    def label(self, name: str, sys_id: str = "", login: str = "") -> str:
        if login == USER or (sys_id and sys_id in self._middleware_ids):
            return f"Middleware ({USER})"
        if not name or name.lower() == "system" or self._real_names:
            return name
        return self._pseudonyms.setdefault(
            name, f"Bearbeiter {len(self._pseudonyms) + 1}"
        )

    def of_reference(self, record: Record, field_name: str) -> str:
        return self.label(shown(record, field_name), value(record, field_name))

    def of_audit(self, event: Record) -> str:
        login = value(event, "user")
        return self.label(self._name_by_login.get(login, login), login=login)


def entry_rows(report: Report, people: People) -> tuple[Rows, dict[str, float]]:
    rows: Rows = []
    booked_per_task: dict[str, float] = {}
    for entry in report.entries or []:
        task_id = value(entry, "task")
        task = report.task_by_id.get(task_id, {})
        seconds_text = value(entry, "time_in_seconds")
        if seconds_text:
            seconds = float(seconds_text)
        else:
            seconds = duration_seconds(entry, "time_worked")
        booked_per_task[task_id] = booked_per_task.get(task_id, 0.0) + seconds
        rows.append(
            [
                report.ritm_number.get(value(task, "request_item"), ""),
                value(task, "number"),
                people.of_reference(entry, "user"),
                value(entry, "sys_created_on"),
                number(seconds / 60),
                shown(entry, "comments"),
            ]
        )
    return rows, booked_per_task


def task_rows(
    report: Report, people: People, booked_per_task: dict[str, float]
) -> tuple[Rows, dict[str, float], dict[str, int]]:
    rows: Rows = []
    booked_per_ritm: dict[str, float] = {}
    count_per_ritm: dict[str, int] = {}
    for task in sorted(report.tasks, key=lambda t: value(t, "opened_at")):
        task_id, ritm_id = value(task, "sys_id"), value(task, "request_item")
        booked = booked_per_task.get(task_id, 0.0)
        booked_per_ritm[ritm_id] = booked_per_ritm.get(ritm_id, 0.0) + booked
        role = "Behebung" if count_per_ritm.get(ritm_id, 0) == 0 else "Pruefung"
        count_per_ritm[ritm_id] = count_per_ritm.get(ritm_id, 0) + 1
        open_hours: Optional[float] = None
        reopens: Any = ""
        last_close: Optional[datetime] = None
        if report.audits is not None:
            events = report.events_by_doc.get(task_id, [])
            open_hours, reopens, last_close = phases(task, events)
        opened, closed = value(task, "opened_at"), value(task, "closed_at")
        rows.append(
            [
                report.ritm_number.get(ritm_id, ""),
                value(task, "number"),
                role,
                shown(task, "assignment_group"),
                shown(task, "state"),
                opened,
                closed,
                number(hours_between(opened, closed)),
                people.of_reference(task, "closed_by"),
                reopens,
                last_close.strftime(TIMESTAMP_FORMAT) if last_close else "",
                number(open_hours),
                number(duration_seconds(task, "time_worked") / 60),
                number(booked / 60) if report.entries is not None else "",
            ]
        )
    return rows, booked_per_ritm, count_per_ritm


def ritm_rows(
    report: Report,
    people: People,
    booked_per_ritm: dict[str, float],
    count_per_ritm: dict[str, int],
) -> Rows:
    rows: Rows = []
    for ritm in report.ritms:
        ritm_id = value(ritm, "sys_id")
        opened, closed = value(ritm, "opened_at"), value(ritm, "closed_at")
        booked = booked_per_ritm.get(ritm_id, 0.0) / 60
        rows.append(
            [
                value(ritm, "number"),
                shown(ritm, "state"),
                opened,
                closed,
                number(hours_between(opened, closed)),
                people.of_reference(ritm, "closed_by"),
                count_per_ritm.get(ritm_id, 0),
                number(duration_seconds(ritm, "time_worked") / 60),
                number(booked) if report.entries is not None else "",
            ]
        )
    return rows


def change_rows(report: Report, people: People) -> Rows:
    rows: Rows = []
    for event in report.audits or []:
        doc = value(event, "documentkey")
        task = report.task_by_id.get(doc)
        ritm_id = value(task, "request_item") if task else doc
        number_text = value(task, "number") if task else report.ritm_number.get(doc, "")
        old, new = value(event, "oldvalue"), value(event, "newvalue")
        rows.append(
            [
                "SCTASK" if task else "RITM",
                number_text,
                report.ritm_number.get(ritm_id, ""),
                STATE_LABELS.get(old, old),
                STATE_LABELS.get(new, new),
                value(event, "sys_created_on"),
                people.of_audit(event),
            ]
        )
    return rows


def count(records: Optional[list[Record]]) -> str:
    return "-" if records is None else str(len(records))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ziel", default=".", help="Verzeichnis fuer die CSV-Dateien")
    parser.add_argument("--seit", help="nur RITMs ab diesem Datum (JJJJ-MM-TT)")
    parser.add_argument(
        "--namen", action="store_true", help="Personen nicht pseudonymisieren"
    )
    args = parser.parse_args()
    target = Path(args.ziel)
    target.mkdir(parents=True, exist_ok=True)

    report = fetch(authorization(), args.seit)
    people = People(report.users, args.namen)
    entries, booked_per_task = entry_rows(report, people)
    tasks, booked_per_ritm, count_per_ritm = task_rows(report, people, booked_per_task)
    ritms = ritm_rows(report, people, booked_per_ritm, count_per_ritm)
    write_csv(target / "ritms.csv", RITM_HEADER, ritms)
    write_csv(target / "sctasks.csv", TASK_HEADER, tasks)
    write_csv(target / "zeitbuchungen.csv", ENTRY_HEADER, entries)
    write_csv(target / "statuswechsel.csv", CHANGE_HEADER, change_rows(report, people))
    print(
        f"{len(report.ritms)} RITMs, {len(report.tasks)} SCTASKs, "
        f"{count(report.entries)} Zeiteintraege, {count(report.audits)} "
        f"Statuswechsel -> {target.resolve()}"
    )


if __name__ == "__main__":
    main()
