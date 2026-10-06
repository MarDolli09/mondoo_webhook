# Mondoo → ServiceNow Webhook

Nimmt Case-Ereignisse aus Mondoo entgegen, reichert sie um CVSS- und
Risk-Werte aus der Mondoo GraphQL-API an und legt dazu Requested Items (RITM)
über den ServiceNow Service Catalog an oder pflegt bestehende.

## Ablauf

1. `POST /webhook/mondoo` prüft vor jeder Verarbeitung den Auth-Header und die
   Signatur nach [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks)
   (`webhook-id`, `webhook-timestamp`, `webhook-signature`, HMAC-SHA256,
   höchstens 5 Minuten Zeitabweichung). Jeder Fehler ergibt 401 ohne Begründung;
   der Grund steht im Log.
2. `MondooWebhookEvent` liest den Payload (mit oder ohne `body`-Hülle).
3. `CaseParser` bestimmt den Finding-Typ, fragt die Bewertung des Findings
   über `findings(filter: {mrn})` im Scope des Space ab (ein Request je
   Finding, ein Knoten je betroffenem Asset, es gilt das höchste Risiko) und
   priorisiert: Mondoo Risk Rating → CVSS-Rating → Schweregrad-Tag im Titel →
   Default.
4. `ServiceNowClient` sucht das RITM über `correlation_id` (= Case-MRN) und
   * bestellt ein neues Katalogformular, wenn keines existiert,
   * aktualisiert bzw. schließt ein offenes RITM (Close → State 3, Delete → 7),
   * verwirft Ereignisse zu RITMs im Endstatus.
5. Je Webhook entsteht ein JSON-Telemetriedatensatz
   (`mondoo_to_servicenow_processed`) mit `correlation_id` und `case_mrn`.

Der Tickettitel lautet `Mondoo - [SCHWEREGRAD] <Finding>`: „Mitigate
vulnerability“ bzw. „Mitigate advisory“ und das Asset am Ende („on SUBVWBN“,
„on multiple assets“) entfallen, z. B. wird
`[CRITICAL] Mitigate advisory MONDOO-EOL-DOTNET-6 on multiple assets` zu
`Mondoo - [CRITICAL] MONDOO-EOL-DOTNET-6`. Er steht nur in der Short
Description des RITM; eine Katalogvariable dafür gibt es nicht.
Assignment Groups setzt ServiceNow selbst.

## ServiceNow-Mapping

Katalogformular „Mondoo Vulnerability“ (`order_now`), Reihenfolge wie im Formular:

| Formularfeld | Variable | Wert |
|---|---|---|
| CVE | `cve` | CVE aus dem Titel, sonst ` / ` |
| CVSS Score / CVSS Risk Rating | `cvss_score` / `cvss_risk_rating` | aus `cvss.value`/`cvss.rating` des Findings; die API liefert 0–100 (98 = 9.8), 0 bedeutet kein CVSS |
| Mondoo Risk Rating / Score | `mondoo_risk_rating` / `mondoo_risk_score` | aus `riskValue`/`rating` des Findings (Skala 0–100), nur ohne API-Wert aus der AI-Summary |
| Urgency / Impact | `urgency` / `impact` | `1` (Critical) bis `4` (Low), aus Mondoo Risk Rating, sonst CVSS-Rating, sonst Titel |
| Mondoo Space | `mondoo_space` | Auswahlwert laut `SPACE_CHOICE_MAP`, z. B. `space_server`; daraus bestimmt der Workflow die Assignment Group |
| Finding type | `finding_type` | `vulnerability`, `advisories`, `end-of-life`, `misconfiguration`, `other` |
| Mondoo Ticket URL | `mondoo_ticket_url` | Link auf den Case in Mondoo |
| Number of affected assets | `number_of_affected_assets` | `assetsCount`, sonst Anzahl Assets aus den Refs |
| Created by | `created_by` | Name laut `USER_MAP`, MRN oder `Mondoo-Drift` |
| Mondoo MRN | `mondoo_mrn` | Case-MRN (in ServiceNow per „Map to field“ → `correlation_id`) |

RITM-Felder per PATCH nach der Bestellung: `state` (1), `correlation_id`,
`short_description` (= Titel), `urgency`/`impact` (wie die Katalogvariablen),
`opened_by` (`mosca.rest`), `watch_list`, `work_notes`.

Danach bekommt der SCTASK den Tickettitel: Der Workflow legt ihn mit
„Mondoo Vulnerability - <Space>“ an und bestimmt daraus die Assignment Group.
Die App sucht bis zu rund 10 s nach Tasks zum RITM mit gesetzter Assignment
Group und ersetzt nur diesen Workflow-Text; die Logzeile nennt, nach wie vielen
Sekunden die Gruppe gesetzt war. Gelingt das nicht, bleibt der Task
unverändert (WARNING im Log), das RITM ist davon nicht betroffen.
Folgeereignisse aktualisieren `work_notes`,
bei ermittelter Priorität `urgency`/`impact` und schließen bei Close/Delete.

## Architektur

```
app/api        HTTP-Endpunkt, Authentifizierung, Lifespan/Startpunkt, Telemetrie
app/services   processing (Anwendungsablauf) · parsing (CaseParser)
               mondoo (Bewertungen) · servicenow (RITM, SCTASK)
app/domain     Fachregeln ohne I/O, Ports FindingScoresLookup / TicketSynchronizer
app/models     Eingangsmodell (Mondoo) und NormalizedCase
app/core       Konfiguration, Stammdaten, Logging, Ausnahmen
```

Diagramme (Systemkontext, Schichten, Verteilung, Domäne, Klassen, Sequenz,
Aktivität, Zustände, Prioritätskaskade, Datenabbildung, Sicherheit):
[docs/DIAGRAMME.md](docs/DIAGRAMME.md), jeweils als PNG und als draw.io-Datei.

Ablauf je Zustellung: `app/api/webhook.py` authentifiziert und dekodiert,
`WebhookProcessor` (`app/services/processing`) klassifiziert, normalisiert über
`CaseParser` und synchronisiert über den Port `TicketSynchronizer`; das Ergebnis
ist ein `SyncOutcome` (Aktion, Ticketnummer). Das ServiceNow-Teilsystem trennt
den Transport (`transport.py`: Anmeldung, Retry, Fehlerabbildung) von den
Ressourcen (`request_items`, `catalog_tasks`, `catalog`, `users`).

Importregeln (durch `tests/test_architecture.py` geprüft):

* Abhängigkeiten zeigen nur nach unten, der Importgraph ist azyklisch.
* Teilsysteme (`app.api`, `app.services.*`) werden von außen nur über ihre
  `__init__.py` importiert.
* `app.domain` und `app.models` sind ohne Umgebungsvariablen importierbar.
* Die Teilsysteme unter `app.services` lesen weder `settings` noch
  `master_data`; `app/api/dependencies.py` übergibt ihnen `ServiceNowConfig`
  bzw. `ParsingConfig`.

## Betrieb in Azure

* Startbefehl: `gunicorn app.main:app -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --timeout 600`
* App Setting `SCM_DO_BUILD_DURING_DEPLOYMENT=true`, deployt wird der Inhalt des
  Repository-Stamms (`app/`, `main.py`, `requirements.txt` direkt unter `wwwroot`).
* `MONDOO_WEBHOOK_SIGNING_SECRET` und `MONDOO_WEBHOOK_AUTH_HEADER_VALUE` als
  Key-Vault-Referenzen; die Werte müssen exakt denen der Mondoo-Integration entsprechen.
* Mondoo-Integration: URL `https://<host>/webhook/mondoo` (ohne abschließenden `/`),
  „Sign deliveries“ und „Send an authentication header“ aktiv.

## Logs

Eine Zeile je Schritt, z. B.:

```
[INFO] [a18f4807] Webhook empfangen (webhook-id 2054dd9f-…)
[INFO] [a18f4807] Ereignis TYPE_CREATED, vulnerability, 57 Assets: [CRITICAL] Mitigate vulnerability CVE-2026-62818 on multiple assets
[INFO] [a18f4807] Mondoo-Bewertung CVE-2026-62818 (CveFinding, 70 Assets im Space): CVSS 8.8 (HIGH), Risk 100 (CRITICAL)
[INFO] [a18f4807] Ticketdaten: Space Server, urgency/impact 1/1 aus Mondoo Risk CRITICAL
[INFO] [a18f4807] Kein RITM zum Case vorhanden, bestelle neuen Request.
[INFO] [a18f4807] Service Catalog Request REQ0038907 erzeugt.
[INFO] [a18f4807] RITM0043072 angelegt (Status Offen): Mondoo - [CRITICAL] CVE-2026-62818
[INFO] [a18f4807] SCTASK0042543: 'Mondoo Vulnerability - Server' durch Tickettitel ersetzt (Gruppe nach 1.3 s gefunden).
```

* `[a18f4807]` sind die ersten 8 Zeichen der Correlation-ID; damit findet man
  alle Zeilen eines Requests. Den Zeitstempel setzt Azure.
* Je Webhook ein JSON-Datensatz `mondoo_to_servicenow_processed`, je Request
  `request_completed` (Methode, Pfad, Status, Dauer).
* `LOG_LEVEL=DEBUG` ergänzt Details (normalisierter Case, Header der ersten
  Zustellung, aufgelöste Benutzer). `[ERROR]` im Zeilenformat nutzt die
  Log-Alarmregel in Azure.

## Konfiguration

Technische Einstellungen: `app/core/config.py`. Fachliche Stammdaten
(Spaces, Benutzer, Prioritäten, Finding-Typen): `app/core/master_data.py`.
Feste Organisationsdaten der Anbindung (technischer Benutzer, feste
Beobachter): `app/services/servicenow/constants.py`. Vorlage aller Variablen:
`.env.example`.

## Entwicklung

Produktiv läuft Python 3.11 (Azure App Service); der Code ist ab Python 3.9 lauffähig.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python main.py                                  # lokal starten
.venv/bin/python -m unittest discover -s tests -t .       # Tests (Dummy-Umgebung)
ruff format . && ruff check . && mypy                     # Standards (pyproject.toml)
```

Die Tests laden `tests/.env.test` (Dummy-Werte) und simulieren Mondoo und
ServiceNow; es werden keine externen Systeme aufgerufen. Anwendungslogs im
Testlauf: `TEST_LOGS=1`. Die Suite läuft unter Linux, macOS und Windows; unter
Windows wird dafür `tzdata` mitinstalliert (Marker in `requirements.txt`).
