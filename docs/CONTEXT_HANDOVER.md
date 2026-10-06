# Project Context Handover

Stand: 02.10.2026, Commit `dbf30e3` (übersichtlichere Logs, siehe Abschnitt 3
„Logs 01.10.“; Deployment noch nicht bestätigt) auf dem deployten
Architektur-Refactoring `462f566`. Sequenzdiagramm samt Azure-Ressourcen
(`73f3942`), Klassendiagramm (`837f0d2`), Domänenmodell (`ac5dd95`),
Schichtenmodell (`03a6761`), Prioritätskaskade (`7eafd14`), sechs weitere
Diagramme für die Arbeit (`befe63a`), der BPMN-Soll-Prozess mit zwei SCTASKs
und der frühere Ist-Prozess als BPMN (beide 05.10.); Übersicht in
`docs/DIAGRAMME.md`. Laut Test vom 01.10. funktionieren Anlegen und Schließen von
Tickets (auch automatisch) wie erwartet; nach dem Refactoring im Betrieb
bestätigt: Anlegen samt SCTASK-Titel (RITM0043072). Ob der SCTASK die richtige
Assignment Group trägt, steht in der Checkliste noch offen. **E-Mail-Alarmierung
bei Fehlern ist eingerichtet** (Abschnitt 5, „Alarmierung"). Stand vor dem
Refactoring gesichert im Branch `backup/pre-cleanup-2026-10-01` (`d936cef`).

## 1. Executive Summary & Project Goal

Der Dienst nimmt Webhooks von **Mondoo** (Security-Findings) entgegen und führt sie
in **ServiceNow** als Requested Items (RITM) über den Service Catalog.

Ablauf je Zustellung:

1. `POST /webhook/mondoo` prüft Auth-Header und Standard-Webhooks-Signatur.
2. Der Payload wird normalisiert, der Finding-Typ bestimmt (vulnerability,
   advisories, end-of-life, misconfiguration, other) und um Bewertungen aus der
   Mondoo GraphQL-API angereichert.
3. Über die `correlation_id` (= Case-MRN) wird ein bestehendes RITM gesucht und
   angelegt, aktualisiert, geschlossen oder das Ereignis verworfen.

Ziel des aktuellen Arbeitspakets: Die Kette läuft seit dem 28.09. vollständig
gegen die Testinstanz `bmsptest`. Die gefilterte GraphQL-Abfrage je Finding ist
seit dem 29.09. deployt, wurde aber am selben Tag von Mondoo mit HTTP 422
abgelehnt (Schemaänderung, Abschnitt 3); Tickets entstanden ohne CVSS/Risk. Der
Fix ist seit dem 29.09. deployt. Offen sind die Umstellung auf OAuth, der
Livegang gegen `bmsp` und die weitere Ablösung von Textparsing und Stammdaten
durch die API (siehe Abschnitte 5 und 6).

## 2. Tech Stack & Architecture Decisions

**Laufzeit:** Python (lokal 3.9.6, Azure App Service 3.11.15), FastAPI 0.128.8,
Uvicorn 0.39.0 unter Gunicorn 23.0.0, httpx 0.28.1, Pydantic 2.13.5,
pydantic-settings 2.11.0. Werkzeuge: ruff und mypy (Konfiguration in
`pyproject.toml`), Tests mit `unittest` aus der Standardbibliothek.

**Schichten**, Abhängigkeiten zeigen nur nach unten:

```
app/api        HTTP-Endpunkt, Authentifizierung, Lifespan/Startpunkt, Telemetrie
app/services   processing (Anwendungsablauf) · parsing (CaseParser)
               mondoo (Bewertungen) · servicenow (RITM, SCTASK)
app/domain     Fachregeln ohne I/O, Ports (abstrakte Schnittstellen)
app/models     Eingangsmodell (Mondoo) und NormalizedCase
app/core       Konfiguration, Stammdaten, Logging, Ausnahmen, Signaturprüfung
```

**Konventionen** (durch `tests/test_architecture.py` geprüft):

- Der Importgraph ist azyklisch, es gibt keine Aufwärtskanten.
- Teilsysteme (`app.api`, `app.services.*`) werden von außen nur über ihre
  `__init__.py` importiert. `app.core`, `app.domain` und `app.models` sind
  Basispakete; jedes Modul legt seine Schnittstelle über `__all__` fest.
- `app.domain` und `app.models` sind ohne Umgebungsvariablen importierbar.
- Abhängigkeitsumkehr über zwei Ports in `app/domain/ports.py`:
  `FindingScoresLookup` (Mondoo) und `TicketSynchronizer` (ServiceNow, liefert
  ein typisiertes `SyncOutcome` mit `SyncAction`).

**Muster:**

- Konfiguration über pydantic-settings, Validierung beim Start (fail fast).
  Technisches in `core/config.py`, Fachdaten in `core/master_data.py`. **Die
  Teilsysteme unter `app/services` lesen weder `settings` noch
  `master_data`**; `app/api/dependencies.py` übergibt ihnen `ServiceNowConfig`
  bzw. `ParsingConfig` und den API-Key (geprüft in `tests/test_architecture.py`).
  `settings` lesen sonst nur `app/main.py`, `app/api/authentication.py` und
  `app/core/logging.py`.
- Geteilte Ressourcen (`WebhookProcessor` mit Parser und ServiceNow-Client,
  Header-Stichprobe, Signaturprüfer) entstehen im Lifespan und kommen per
  FastAPI-Dependency; Token und Referenz-Cache stecken im ServiceNow-Client.
- ServiceNow: `transport.py` (Anmeldung, Retry, Fehlerabbildung, `poll`) ist
  von den Ressourcen getrennt (`request_items`, `catalog_tasks`, `catalog`,
  `users`), gebündelt in `ServiceNowAPI`.
- Fehler nachgelagerter Systeme ergeben immer **502**, nie deren Statuscode.
- Logs: eine Zeile je Schritt, Format `[LEVEL] [<Correlation-ID, 8 Zeichen>]
  Meldung`, ohne eigenen Zeitstempel (den setzt Azure). Details nur mit
  `LOG_LEVEL=DEBUG`. Nie Geheimwerte; die volle Correlation-ID steht in
  `request_completed` und im Telemetriedatensatz.

## 3. Active Task & Current State

**Funktionsfähig:** Ende-zu-Ende gegen `bmsptest` mit `SNOW_AUTH_MODE=basic`.
Tickets werden angelegt, aktualisiert und geschlossen. 67 Tests, ruff und mypy
sind grün, auch unter Windows.

**Logs 01.10.** (Commit `dbf30e3`). Ein Webhook ergibt rund 10 statt
rund 45 Zeilen im Protokollstream. Format `[INFO] [a18f4807] …` statt
`2026-10-01 14:45:51 [INFO] mondoo-receiver (webhook.py:31) [<UUID>]: …`. Der
mehrzeilige „BEREINIGTE PAYLOAD“ (in Azure 28 Zeilen ohne Correlation-ID) und
die drei Prioritätszeilen sind ersetzt durch eine Zeile
`Ticketdaten: Space Server, urgency/impact 1/1 aus Mondoo Risk CRITICAL`. Die
Mondoo-Zeile nennt nur noch die Finding-ID und „Assets im Space“, die
RITM-Zeile den Tickettitel. Auf DEBUG verschoben: Header-Stichprobe,
aufgelöste Benutzer, Ref-Reduktion, „gefunden. Starte Update“, Risk-Quelle API,
normalisierter Case (einzeilig). Neu: Einstellung `LOG_LEVEL` (Default INFO;
für Details in Azure vorübergehend `DEBUG` setzen, die App startet dann neu),
`request_completed` mit Methode, Pfad und Status. Unverändert: alle
WARNING-/ERROR-Texte bis auf die doppelte Vorsilbe („RITM RITM…“,
„SCTASK SCTASK…“), Telemetriedatensatz, alle Texte der Log-Alarmregel. Golden
Master: Requests, Antworten und Wartezeiten identisch, 619 → 390 Logzeilen in
26 Szenarien.

**Refactoring 01.10.** (nach dem Architektur-Review, Commit `462f566`,
deployt). Umgesetzt: typisiertes Port-Ergebnis `SyncOutcome` (W1),
Konfiguration nur noch über den Startpunkt injiziert (W2), `ServiceNowAPI` in
Transport und Ressourcen zerlegt (W3), Antworten ohne JSON ergeben 502 statt
500 (W4), lange Funktionen zerlegt (W5), Anwendungsablauf `WebhookProcessor` in
`app/services/processing` (W6), `PrioritySource`-Enum und unveränderliches
`NormalizedCase` (W7), plattformunabhängige Tests (W8), `FindingTypeProfile`
entfernt (I1), Logtext „Priority Mapping via Rating“ (I2), Begründung für den
breiten Fang im Mondoo-Client und toter Zweig entfernt (I3), Kapselung (I4),
ServiceNow-Organisationsdaten nach `servicenow/constants.py` (I5), gemeinsames
`poll` (I6), `DeliveryContext` für die Telemetrie (I7). Offen: I8
(Python-Zielversion, CI).

Abgesichert mit einem Golden-Master-Vergleich: 26 Szenarien (Anlegen, Update,
Close, Delete, Fehlerpfade, SCTASK, Abweisungen), 191 ausgehende Requests,
alle Antworten, Logzeilen und Wartezeiten vor und nach dem Umbau verglichen.
Requests sind identisch; bewusst geändert sind nur die 502 bei Antworten ohne
JSON (samt Fehlerlog mit Ursache) und der Logtext „Priority Mapping via
Rating“. Bei unveränderter Alarmierung: Jeder dieser Fehler schreibt weiterhin
eine `[ERROR]`-Zeile. `parse_duration_ms` in der Telemetrie misst jetzt ab dem
Start der Verarbeitung, also ohne Dekodieren und Validieren des Payloads
(Unterschied: wenige Millisekunden).

**Vorfall 29.09.: Mondoo lehnt die Abfrage ab.** Nach dem Deployment von
`cf166b1` blieben `cvss_*` und `mondoo_risk_*` in allen Tickets leer (z. B.
RITM0043011, CVE-2026-31431). Log:
`Abfrage fuer … abgebrochen: … HTTP 422: Fields "cvss" conflict because they
return conflicting types "CvssScore" and "CvssScore!"` (`GRAPHQL_VALIDATION_FAILED`).
Mondoo deklariert `cvss` inzwischen je Finding-Typ unterschiedlich (einmal
Pflichtfeld, sonst optional); gleichnamige Felder in überlappenden Fragmenten
müssen aber denselben Typ haben. Die ganze Abfrage scheitert, für jedes Finding.
Am 28.09. lief dieselbe Abfrage noch, das Schema hat sich also über Nacht
geändert. Die Anreicherung ist optional, deshalb entstanden die Tickets trotzdem,
nur ohne Werte.

**Fix (Commit `7e4b3c5`, deployt 29.09.):**

- `app/services/mondoo/queries.py`: `cvss` je Typ unter eigenem Alias
  (`cveCvss`, `advisoryCvss`, `packageCvss`; Konstante `CVSS_FIELDS`).
- `app/services/mondoo/findings.py`: liest CVSS über `CVSS_FIELDS`.
- `app/services/mondoo/api.py`: Bei HTTP-Fehlern und `errors` im Rumpf werden
  alle GraphQL-Meldungen dedupliziert protokolliert (bis 2000 Zeichen), statt
  den Rumpf nach 400 Zeichen abzuschneiden.
- `app/services/parsing/case_parser.py`: **Risk aus der API vor dem Befundtext**
  (Entscheidung 29.09.). Der Text griff „The combined risk is **high**
  because…" als `HIGH` ohne Score ab, obwohl Mondoo 100/CRITICAL meldete. Der
  Text gilt nur noch als Rückfall, mit Warnung im Log.
- `scripts/verify_scores.py`: nimmt Finding-MRN und Scopes als Argumente, misst
  die Dauer, gibt bei HTTP-Fehlern den Antwortrumpf aus; Abfrage mit Aliasen.
- Tests: Regressionstest „`cvss` nur mit Alias", Ende-zu-Ende-Test für 422
  (Ticket entsteht, Grund im Log), Test „API vor Text".

**Nach dem Deployment geprüft** (29.09., gegen 09:17):

| RITM | Finding (Typ) | CVSS | Risk | Priorität über |
|---|---|---|---|---|
| RITM0043012 | `CVE-2026-53131` (`CveFinding`, API: 6 Assets, Case: 5) | 9.4 (CRITICAL) | 100 (CRITICAL) | `cvss` → 1/1 |
| RITM0043014 | `cis-microsoft-azure-foundations--6.1.1.4` (`CheckFinding`, 10 Assets) | leer | 100 (CRITICAL) | `mondoo_risk` → 1/1 |
| RITM0043015 | `MONDOO-EOL-NUMPY-1-26` (`AdvisoryFinding`, 1 Asset) | leer | 100 (CRITICAL) | `mondoo_risk` → 1/1 |

CVSS fehlt bei Fehlkonfiguration und End-of-Life zu Recht, siehe „Bewusste
Entscheidungen". Die Bewertung dauert 0,4–0,8 s je Webhook.

**Davor geändert** (Commits `4e19628`, `cf166b1` und `a33c94a`, seit 29.09.
deployt):

- `app/domain/scores.py` (ersetzt `cvss.py`): `FindingScores` mit vier Werten,
  `normalize_cvss_score` (Eingabe 0–100, Ausgabe 0–10) und
  `normalize_risk_score` (0–100). Vorher wurde ein fehlendes CVSS durch den Risk
  Score ersetzt (Risk 89 erschien als „CVSS 8.9").
- `app/services/mondoo/queries.py`: eine Abfrage
  `findings(scopeMrn, first, filter: {mrn})` statt der paginierten Suche über
  alle Findings des Scope. Ein Request je Finding statt bis zu 50 Seiten.
- `app/services/mondoo/api.py`: `fetch_finding_nodes` liefert die Knoten und
  `totalCount` statt `FindingsPage` mit Cursor.
- `app/services/mondoo/client.py`: kein Seitendurchlauf, kein Zeitbudget; die
  Knoten (einer je betroffenem Asset) werden über `highest_scores` zum höchsten
  Risiko verdichtet.
- `app/services/mondoo/findings.py`: CVSS ausschließlich aus `cvss.value` /
  `cvss.rating`, Risk aus `riskValue`/`rating`. `baseValue` bleibt ungenutzt, es
  liegt auf der Risk-Skala (CheckFinding: 100).
- `app/services/parsing/case_parser.py`: gefragt wird im Scope des Space
  (`ownerMrn`), nicht je Asset. Alle Finding-Typen werden abgefragt, auch
  Fehlkonfigurationen.
- Entfallen: `MONDOO_GRAPHQL_MAX_PAGES`, `CVSS_SEARCH_BUDGET_SECONDS`,
  `CVSS_SEARCH_LOG_INTERVAL`, `CVSS_MAX_FINDING_ATTEMPTS` (ersetzt durch
  `MONDOO_MAX_FINDING_LOOKUPS`, Standard 5), `PaginationLimitExceededError`,
  `SearchBudgetExceededError`, `CVSS_RATING_THRESHOLDS`,
  `calculate_rating_from_score`, `FindingTypeProfile.resolves_scores`, das Feld
  `found_on_page`.

**Zuletzt geprüft** (gefilterte Abfrage gegen die echte API, Scope = Space-MRN;
die ersten drei am 28.09. ohne Aliase, die letzte am 29.09. mit Aliasen):

| Finding | `totalCount` | `riskValue` / `rating` | `cvss` |
|---|---|---|---|
| `//vadvisor.api.mondoo.app/cves/CVE-2026-23450` | 6 | 97 / `CRITICAL` | `{value: 98, rating: CRITICAL}` |
| `//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-DOTNET-8` | 3 | 89 / `HIGH` | `{value: 0, rating: NONE}` |
| `//policy.api.mondoo.app/queries/cis-microsoft-azure-foundations--8.3.2` | 5 | 100 / `CRITICAL` | kein Feld (`CheckFinding`) |
| `//vadvisor.api.mondoo.app/cves/CVE-2026-31431` | 5 | 85, 85, 85, 91, 100 / höchstes `CRITICAL` | `cveCvss: {value: 78, rating: HIGH}` |

Für CVE-2026-31431 ergibt das im Ticket CVSS 7.8 (HIGH) und Risk 100 (CRITICAL),
genau wie in der Mondoo-Oberfläche. Dauer 1,7 s (App-Timeout 10 s).

Daraus folgt: **CVSS kommt auf der Skala 0–100** (98 entspricht 9.8), `0` heißt
„kein CVSS", `totalCount` ist die Anzahl betroffener Assets und die API liefert
je Asset einen Knoten. Die Rating-Stufe für Risk 100 heißt in der API `CRITICAL`,
nicht „Mission-Critical".

## 4. Key Files & Code References

| Pfad | Aufgabe |
|---|---|
| `app/api/webhook.py` | Endpunkt `POST /webhook/mondoo`: dekodieren, `WebhookProcessor` aufrufen, Telemetrie, Antwort |
| `app/api/authentication.py` | Auth-Header und Signaturprüfung, 401 mit Diagnose im Log |
| `app/api/dependencies.py` | Startpunkt: Lifespan, Aufbau der Teilsysteme aus `settings`/`master_data`, Startprotokoll |
| `app/api/telemetry.py` | Telemetriedatensatz (`DeliveryContext`), Header-Stichprobe |
| `app/core/config.py` | Technische Einstellungen samt Startvalidierung |
| `app/core/master_data.py` | Spaces, Benutzer, Prioritäten, Finding-Typen (per Umgebungsvariable überschreibbar) |
| `app/core/webhook_signature.py` | Standard-Webhooks-Signatur (HMAC-SHA256) |
| `app/core/logging.py` | Zeilenformat, Secret-Maskierung, Correlation-ID, `LOG_LEVEL` |
| `app/domain/scores.py` | CVSS- und Risk-Skalen, Ergebnistyp `FindingScores` |
| `app/domain/ports.py` | Ports `FindingScoresLookup`, `TicketSynchronizer`; Ergebnis `SyncOutcome`/`SyncAction` |
| `app/domain/priority.py` | Urgency/Impact samt Herkunft (`PrioritySource`) |
| `app/domain/finding_types.py` | Klassifikation, Typ im Ticket (`reported_finding_type`) |
| `app/domain/case_text.py` | Auswertung der AI-Summary, Tickettitel ohne „Mitigate …“ und ohne Asset |
| `app/domain/identifiers.py` | MRNs, Space-IDs, Identitäten, Mondoo-Links |
| `app/models/mondoo.py` | Eingangsmodell des Webhooks |
| `app/models/case.py` | `NormalizedCase` als interne Zwischenform |
| `app/services/processing/processor.py` | `WebhookProcessor`: klassifizieren, normalisieren, synchronisieren, Laufzeiten |
| `app/services/parsing/case_parser.py` | Klassifikation, Anreicherung, Normalisierung |
| `app/services/parsing/config.py` | `ParsingConfig` (Zuordnungstabellen, Grenzen) |
| `app/services/mondoo/queries.py` | GraphQL-Abfrage `findings(filter: {mrn})`, `cvss` je Typ mit Alias (`CVSS_FIELDS`) |
| `app/services/mondoo/api.py` | GraphQL-Transport, Union-Fehler, GraphQL-Meldungen fürs Log |
| `app/services/mondoo/client.py` | Abfrage je Finding, höchstes Risiko über alle Assets |
| `app/services/mondoo/findings.py` | Auswertung einzelner Finding-Knoten |
| `app/services/servicenow/mapping.py` | Tickettitel, Katalogvariablen und RITM-Felder |
| `app/services/servicenow/client.py` | Anlegen, Aktualisieren, Schließen, SCTASK-Titel |
| `app/services/servicenow/config.py` | `ServiceNowConfig` (Zugang, Katalog-Item, Benutzerzuordnung) |
| `app/services/servicenow/constants.py` | Organisationsdaten (technischer Benutzer, Beobachter), Zustände, Pfade, Wartezeiten |
| `app/services/servicenow/api.py` | `ServiceNowAPI`: bündelt die Ressourcen auf einem Transport |
| `app/services/servicenow/transport.py` | REST-Aufrufe mit Retry, Fehlerabbildung (502), `poll` |
| `app/services/servicenow/request_items.py` · `catalog_tasks.py` · `catalog.py` · `users.py` | Ressourcen `sc_req_item`, `sc_task`, `order_now`, `sys_user` |
| `tests/fakes.py` | Attrappen für Mondoo und ServiceNow (auch HTML statt JSON), Ende-zu-Ende-Aufrufe |
| `tests/test_architecture.py` | Architekturregeln als Test |
| `tests/.env.test` | Dummy-Umgebung für Tests und Audits |
| `scripts/verify_scores.py` | Führt die Produktionsabfrage gegen die echte API aus; optional `<findingMrn> [scope …]`, misst die Dauer |
| `scripts/introspect_next.py` | Introspektion für die offenen GraphQL-Kandidaten |
| `README.md` | Ablauf, Mapping-Tabelle, Betrieb in Azure |
| `docs/sequence-diagram.drawio` | Sequenzdiagramm (Stand 02.10.) mit allen Azure-Ressourcen der Ressourcengruppe als Lebenslinien bzw. im Kopf (App Service samt Plan, Key Vault, Log Analytics, Warnungsregeln, Aktionsgruppe): App-Start, Zustellung, Bewertung, RITM und SCTASK, Alarmierung; editierbar in draw.io |
| `docs/sequence-diagram.png` | Vorschau des Sequenzdiagramms; nach Änderungen in draw.io neu exportieren |
| `docs/class-diagram.drawio` | Klassendiagramm (Stand 02.10., 51 Klassen) nach Paketen api, services, domain, models, core; Ports blau; Kanten an den Klassen verankert, editierbar in draw.io |
| `docs/class-diagram.png` | Vorschau des Klassendiagramms; nach Änderungen am Code oder in draw.io neu exportieren |
| `docs/domain-model.drawio` | Domänenmodell (Stand 02.10., 25 Begriffe): Bereiche Mondoo, Middleware, ServiceNow; Assoziationen mit Leserichtung und Multiplizitäten, Geschäftsregeln als Notizen; Kernaussage Case 1 : 0..1 RITM über `correlation_id` |
| `docs/domain-model.png` | Vorschau des Domänenmodells; nach Änderungen in draw.io neu exportieren |
| `docs/layer-model.drawio` | Schichtenmodell (Stand 02.10.) im Stil des eigenen Entwurfs: 1. Erfassung (Mondoo), 2. Vermittlung (App Service nach Code-Paketen api, services, domain/models, core, dazu Key Vault, Log Analytics, Warnungsregeln, Aktionsgruppe), 3. Ziel (ServiceNow) |
| `docs/layer-model.png` | Vorschau des Schichtenmodells; nach Änderungen in draw.io neu exportieren |
| `docs/priority-cascade.drawio` | Kaskadenmodell der Prioritätsermittlung (Stand 02.10.) im Stil des eigenen Entwurfs: Risk-Herkunft (API, sonst KI-Text), Stufen Mondoo Risk → CVSS → Titel-Tag → Default 3/3, Übernahme in ServiceNow (Update mit Quelle Default lässt Urgency/Impact unverändert) |
| `docs/priority-cascade.png` | Vorschau der Prioritätskaskade; nach Änderungen in draw.io neu exportieren |
| `docs/DIAGRAMME.md` | Abbildungsverzeichnis aller 13 Diagramme mit Titel, Inhalt und passendem Kapitel der Arbeit |
| `docs/bpmn-process.drawio` | BPMN-2.0-Soll-Prozess (05.10., zweite Fassung nach Entwurf des Nutzers): Bahnen IT-Sicherheit, ServiceNow, System-Owner, Middleware bewusst ausgeblendet; Behebungs-SCTASK, Prüf-SCTASK („Closed Complete“ schließt das RITM, „Closed Incomplete“ legt einen Nacharbeits-SCTASK an), Ausnahmen (voll über Behebungs- und Prüf-SCTASK, teilweise und abgelehnt zurück in die Behebung), Eskalation; Formen der draw.io-BPMN-Palette |
| `docs/bpmn-process.png` | Vorschau des BPMN-Prozesses; nach Änderungen in draw.io neu exportieren |
| `docs/bpmn-as-is-process.drawio` | BPMN-2.0-Ist-Prozess vor der Integration (05.10., Nachbau des Entwurfs des Nutzers): Mondoo als zugeklappter Pool mit Nachrichtenflüssen, Bahnen IT-Sicherheit und Software-Owner/Admin; Report sichten, Kritikalität bewerten, Meldung per E-Mail/Teams, Behebung, Rückmeldung, Schließen; Notiz zum ungenutzten ServiceNow-Formular |
| `docs/bpmn-as-is-process.png` | Vorschau des Ist-Prozesses; nach Änderungen in draw.io neu exportieren |
| `docs/system-context.*`, `deployment.*`, `ticket-states.*`, `activity-errors.*`, `data-mapping.*`, `security.*` | Weitere Diagramme für die Arbeit (02.10.): Systemkontext, UML-Verteilung, Ticket-Zustände, Aktivität mit Fehlerbehandlung, Datenabbildung, Sicherheitsarchitektur |

## 5. Open Issues, Edge Cases & Constraints

**Offene Punkte**

- **Schemaänderungen bei Mondoo fallen erst beim Webhook auf.** Der Vorfall vom
  29.09. zeigte sich nur als leere Felder im Ticket, der Grund stand im Log als
  ERROR. Die Anreicherung ist bewusst optional, deshalb gibt es keinen 502.
  Eine Startprüfung (siehe „Betrieb" unten) hätte ihn beim Deployment sichtbar
  gemacht.
- **Tickets ohne Werte:** RITMs, die zwischen dem Deployment von `cf166b1` und
  dem Fix entstanden sind (bekannt: RITM0043011 zu Case `3Jzgf1…`, außerdem der
  Case `3JzhsQ0…` von 08:20), haben leere `cvss_*`/`mondoo_risk_*`-Felder. Ob
  ein späteres Update-Ereignis sie füllt, ist nicht geprüft; ggf. manuell
  nachtragen.
- **OAuth auf `bmsptest` scheitert** (`access_denied`). Benutzer und Passwort
  stimmen dort (Basic Auth funktioniert), Client-ID und Client Secret stammen
  aus Prod und gelten auf der Testinstanz nicht. Gegen Prod liefert derselbe
  Aufruf ein Token.
- **Variablennamen sind instanzabhängig.** Die App verwendet die Namen des
  Formulars auf `bmsptest` (`cve`, `cvss_risk_rating`, `mondoo_risk_rating`,
  `mondoo_risk_score`, `mondoo_ticket_url`, `number_of_affected_assets`,
  `created_by`). Die ursprüngliche Mapping-Tabelle nannte andere. Vor dem
  Livegang muss das Formular auf Prod geprüft werden.
- **Urgency/Impact beim Anlegen falsch** (beobachtet 29.09.): Neue RITMs stehen
  auf Impact 3 - Low / Priority 4 - Low, obwohl die Katalogvariablen
  `urgency`/`impact` = 1 sind. Die Variablen haben auf `bmsptest` kein „Map to
  field", und der PATCH nach der Bestellung lässt Urgency/Impact bewusst weg
  (`build_create_fields`, Annahme vom 17.09., nie geprüft). Erst ein
  Update-Ereignis setzt die Felder (`build_update_fields`). **Umgesetzt am
  29.09. (`c80a5e8`):** `build_create_fields` sendet
  `urgency`/`impact` wie die Katalogvariablen, immer, auch bei Quelle
  `default`. Updates lassen die Felder bei Quelle `default` weiterhin
  unberührt, damit manuelle Änderungen erhalten bleiben. Im Betrieb bestätigt
  am 01.10. (RITM0043065): „Impact 2 - Medium was 3 - Low“ eine Sekunde nach
  der Bestellung. Die Priority bleibt laut Aktivität bei 4 - Low, weil
  ServiceNow sie am RITM nicht aus Urgency/Impact berechnet. Das ist ein
  Admin-Thema in ServiceNow und wird von der App nicht angefasst (01.10.).
  Noch offen: „Map to field" in ServiceNow, damit die Werte schon bei der
  Bestellung stehen.
- **Neuen Space anbinden.** Am 30.09. erledigt für den Space *Server*
  (`eu-nifty-mendeleev-113214`): eigene Webhook-Integration „ServiceNow“ auf
  denselben Endpunkt, mit demselben Signing Secret und Auth-Header. Die
  Zustellung um 16:59 (Ortszeit) scheiterte noch mit der alten Konfiguration.
  Nach der Korrektur um 17:05 kam das Ticket von 17:06 durch. Bewährte
  Schritte:
  1. Diagnose: Jeder Request schreibt `request_completed` mit Methode, Pfad
     und Status. Zustellungen an `/webhook/mondoo` zeigen zusätzlich
     `Webhook empfangen` oder `Webhook abgewiesen` (Grund in der Zeile).
     `{"status":"online",…}` liefert nur `GET /`. Mondoo zeigt
     Fehlschläge in der Integration unter „Most Recent Activity“
     („webhook delivery failed“), in Ortszeit, Log Analytics dagegen in UTC.
     Bei den Zeiten auf „Last Modified“ der Integration achten.
     Kommt gar nichts an, hat Mondoo nichts gesendet: kein Case-Ereignis im
     Space, Case läuft über eine andere Integration, oder die Integration ist
     fehlerhaft. Unter „External Tickets“ zeigt Mondoo „Webhook <UUID>“, nicht
     die RITM-Nummer. Die UUID ist die `webhook-id` der Anlage-Zustellung
     (steht in `Webhook empfangen (webhook-id …)`); darüber findet man im Log
     Correlation-ID und RITM (bestätigt 06.10., z. B. 207B7E0F… = RITM0043079).
     **Fehlt die UUID** trotz HTTP 200, hat Mondoo die Antwort vermutlich nicht
     abgewartet (siehe Checkliste, „Zeitgrenze bei Mondoo“).
  2. `MONDOO_API_KEY` braucht Lesezugriff auf den neuen Space, sonst Ticket
     ohne CVSS/Risk plus ERROR und Alarm.
  3. Space muss in der EU-Region liegen (`eu-…`), der GraphQL-Endpunkt ist
     fest `eu.api.mondoo.com`.
  4. Anzeigename in `CATEGORY_MAP` und Auswahlwert der Katalogvariable
     „Mondoo Space“ in `SPACE_CHOICE_MAP` (`app/core/master_data.py`)
     ergänzen; die Auswahl muss es im Formular samt Gruppe im Workflow geben.
     Fehlt der Eintrag, schreibt die App ERROR (Alarm), der SCTASK landet bei
     der ersten Auswahl (Azure).
- **Ausnahmen in Mondoo und Ticket-Abschluss.** Test am 30.09.: Ticket
  „[CRITICAL] Mitigate vulnerability CVE-2026-64564 on Testserver-Ubuntu“
  (18:07), danach Ausnahme „Test“ (exception-3, Risk Accepted, unbefristet,
  18:09 genehmigt). Ergebnis: **Die Ausnahme nimmt das Finding sofort aus dem
  Ticket (0 Findings, 0 Assets, 0/0 fixed); Mondoo schließt das leere Ticket
  danach automatisch, aber mit Verzögerung.** Ende-zu-Ende bestätigt:
  RITM0043042 (angelegt 18:07:42), `TYPE_CLOSED` von Mondoo um 16:20:05Z
  (18:20 Ortszeit, rund 11 min nach der Freigabe), RITM um 18:20:06 auf
  *Closed Complete* mit Arbeitsnotiz „CVSS: - (-) | Betroffene Assets: 0“. Ob
  die Verzögerung vom Scan-Intervall oder einer periodischen Neubewertung
  kommt, ist offen (letzter Scan des Assets 17:40). Manuelles Schließen
  ist nicht nötig, eine Automatik in der Middleware auch nicht. Hintergrund: Mondoo
  schließt Cases laut Release 11.22 automatisch, wenn alle Findings „resolved“
  sind (Integration: „Automatically close tickets“ aktiv). Ob eine Ausnahme als
  resolved zählt und wann Mondoo das neu bewertet (Recalculate bzw. nächster
  cnspec-Scan), ist nicht dokumentiert. Der Fortschritt zählt behobene Assets,
  eine Ausnahme ändert ihn vermutlich nicht. Laut Mondoo-Doku (Exceptions
  Overview): Bei Risk Accepted, Workaround und False Positive läuft die
  Prüfung weiter, das Finding zählt nur nicht zum Score. Bei Disable läuft die
  Prüfung nicht mehr; für Schwachstellen fachlich unpassend. Neue Ausnahmen
  stehen standardmäßig auf „Needs review“ und wirken erst nach Freigabe
  (Space-Einstellung). Nach Ablauf der Frist zählt das Finding wieder; wegen
  „Automatically create tickets: disabled“ entsteht dann kein neues Ticket.
  Verbindliche Antwort nur über den Mondoo-Support. Die Middleware reagiert nur
  auf `TYPE_CLOSED`; die Abschlussnotiz nennt Ausnahmen bereits.
- **Feld *Mondoo Title* im Katalogformular entfernen.** Die App sendet
  `mondoo_title` seit 01.10. nicht mehr (siehe „Bewusste Entscheidungen“). Im
  Formular auf `bmsptest` und vor dem Livegang auf `bmsp` muss das Feld noch
  gelöscht werden, sonst bleibt es in jedem RITM leer.
- **Short Description des Catalog Task** („Mondoo Vulnerability - <Space>“,
  z. B. „… - Server“) setzt ein Workflow aus der Katalogvariable
  `mondoo_space`. **Ein weiterer Workflow bestimmt daraus die Assignment
  Group**, der Text darf beim Anlegen also nicht geändert werden. Plan des
  Vorgesetzten (01.10.): Task normal anlegen lassen und die Short Description
  kurz danach mit dem Tickettitel des RITM überschreiben. **Umgesetzt am 01.10.
  (noch nicht deployt):** `ServiceNowClient._retitle_catalog_tasks` sucht nach
  dem RITM-PATCH `sc_task` mit `request_item` = RITM und
  `assignment_groupISNOTEMPTY` (Wartezeiten `CATALOG_TASK_LOOKUP_DELAYS` =
  0/1/2/3 s, also maximal rund 6 s) und ersetzt nur Short Descriptions, die mit
  `CATALOG_TASK_WORKFLOW_TITLE_PREFIX` („Mondoo Vulnerability“) beginnen.
  Kein zugeordneter Task oder ein Fehler (etwa 403): WARNING, RITM und
  Webhook-Antwort bleiben unberührt. Nur beim Anlegen; Updates fassen den Task
  nicht an. Beim Admin weiterhin bestätigen lassen: Rechte von `mosca.rest`
  auf `sc_task`, Zeitpunkt der Gruppenzuordnung (innerhalb der 6 s?), keine
  Neuberechnung der Gruppe bei Änderung der Short Description. Bisheriger Stand dazu: Der Flow/Workflow des
  Katalogelements setzt den Text, nicht die App. Die App
  schreibt nur `sc_req_item` (Short Description = Tickettitel per PATCH
  nach der Bestellung). Seit `mondoo_title` entfallen ist, kann der Flow den
  Mondoo-Titel nicht übernehmen: Er läuft bei der Bestellung, also vor dem
  PATCH. Der Task behält den festen Text. Wege, den Titel in den Task zu
  bringen (offen, 01.10.): (A) Business Rules in ServiceNow, eine auf
  `sc_req_item` (Short Description an Tasks weitergeben) und eine auf `sc_task`
  (beim Anlegen vom RITM übernehmen), empfohlen und Admin-Thema; (B)
  `mondoo_title` als verstecktes Feld zurück, mit „Map to field“ auf Short
  Description, dann nutzt der Flow den Titel; (C) die App ändert `sc_task`
  selbst, nicht empfohlen (Task existiert evtl. noch nicht, Schreibrecht
  nötig, Flow kann überschreiben).
- **Zweistufige SCTASKs (Soll-Prozess, 05.10.):** Bearbeitet wird der
  SCTASK, nicht das RITM. Schließt der System-Owner/Admin seinen SCTASK, legt
  der Workflow automatisch einen zweiten SCTASK für die IT-Sicherheit an
  („Behebung abgeschlossen, bereit zur Prüfung“). Erst wenn dieser zweite Task
  geschlossen ist, schließt sich das RITM bzw. darf die IT-Sicherheit das
  Ticket in Mondoo schließen. Voraussetzung ist, dass Mondoo die Behebung
  sieht (z. B. 0/1 → 1/1 fixed); dann schließt Mondoo das Ticket zum nächsten
  Scan auch selbst und löst `TYPE_CLOSED` aus. **Konflikt mit der App:**
  `build_update_fields` setzt bei `TYPE_CLOSED` das RITM auf 3 (bei
  `TYPE_DELETED` auf 7), unabhängig von offenen SCTASKs. Schließt Mondoo das
  Ticket, bevor der Prüf-SCTASK erledigt ist, umgeht die App die Prüfung.
  Entscheidung offen: bei offenen SCTASKs nur Arbeitsnotiz statt Abschluss,
  oder das Schließen ganz dem Workflow überlassen. Den zweiten SCTASK fasst
  die App nicht an (sie sucht nur direkt nach der Anlage). Festgelegt im
  BPMN-Prozess (05.10.): Die IT-Sicherheit setzt einen nicht bestandenen
  Prüf-SCTASK auf „Closed Incomplete“, der Workflow legt dann einen
  Nacharbeits-SCTASK für den Admin an; nur „Closed Complete“ schließt das
  RITM. Bei einer vollständig genehmigten Ausnahme schließt der Admin seinen
  SCTASK, danach läuft die normale Prüfung.
- **`mondoo_mrn` ohne „Map to field"**: Die `correlation_id` setzt erst der PATCH
  nach der Bestellung. Schlägt der fehl, entsteht beim nächsten Ereignis ein
  zweites Ticket.
- **Rating-Stufen:** Die Oberfläche zeigt für Risk 100 „Mission-Critical", die
  API liefert `CRITICAL`. `PRIORITY_MAP` deckt damit alle beobachteten Stufen ab.
- **Ein Knoten je Asset:** Die gefilterte Abfrage liefert bis zu
  `NODES_PER_FINDING` (100) Knoten. Bei mehr betroffenen Assets protokolliert der
  Client, wie viele bewertet wurden; es gilt das höchste Risiko der ersten Seite.
- **Scope ist der Space**, nicht das einzelne Asset. Der Wert entspricht damit
  dem, was die Mondoo-Oberfläche zum Finding zeigt, kann aber Assets umfassen,
  die nicht am Case hängen. Beobachtet am 29.09. bei CVE-2026-53131: Die API
  meldet 6 Assets, der Case umfasst 5. `number_of_affected_assets` kommt aus
  dem Case und stimmt; das höchste Risiko kann aber von dem fremden Asset
  stammen. Möglicher Ausweg: je Knoten die Asset-MRN mit abfragen und auf die
  `scopeMrn`s des Case filtern (Feldname per Introspektion klären).

**Wo die API weiteres Textparsing und Stammdaten ersetzen könnte**

Analyse vom 28.09. Die Latenz liegt nach der Umstellung auf der ServiceNow-Seite
(Token, `sys_user`, `order_now`, `PATCH`); Mondoo ist ein Request. Die folgenden
Punkte bringen deshalb Sauberkeit, nicht Geschwindigkeit.

Ohne Schemaprüfung umsetzbar:

1. **Kein Lookup bei Close/Delete** (`case_parser.py`): Die Bewertung wird auch
   dann geholt, wenn das RITM ohnehin geschlossen wird. Der Wert steckt nur in
   der Work-Note (`CVSS: -`) und in `urgency`/`impact`, die beim Abschluss
   belanglos sind. Spart einen Request pro Abschluss.
2. **CVE aus der Finding-MRN** statt Regex auf den Titel (`extract_cve`). Die
   MRN enthält die Kennung (`/cves/CVE-2024-0056`); ein Titel ohne CVE liefert
   heute nur den Platzhalter `" / "`.
3. ~~**Risk aus der API** statt aus der AI-Summary~~ **Umgesetzt am 29.09.**
   (`7e4b3c5`): Die API hat Vorrang, `extract_risk_from_summary` ist nur noch
   Rückfall. Die Regex-Muster bleiben dafür bestehen.
4. **Ticket-URL konstruieren** statt aus dem Fußtext der Beschreibung zu lesen
   (`extract_ticket_url`); die Konstruktion existiert schon als Rückfall.

Erst nach `scripts/introspect_next.py` entscheidbar:

5. **Space-Anzeigename** über die API statt `CATEGORY_MAP` (9 fest verdrahtete
   Space-IDs). Ein unbekannter Space landet heute als `eu-…-123456` im Ticket.
6. **Benutzername/E-Mail zur `createdBy`-MRN** statt `USER_MAP` (3 Einträge).
   Mit der E-Mail wird auch der ServiceNow-Lookup eindeutig.
7. **`filter: {mrns: [...]}`** für alle Findings eines Case in einem Request
   statt bis zu `MONDOO_MAX_FINDING_LOOKUPS` Aufrufen.
8. **`epss { probability }` und `riskFactors`** als zusätzliche
   Priorisierungsgrundlage; braucht neue Formularfelder.
9. **CVEs eines Advisory**, damit das Feld `cve` bei Advisory-Tickets nicht leer
   bleibt.

Betrieb: Eine Startprüfung gegen die API würde einen falschen `MONDOO_API_KEY`
beim Deployment sichtbar machen statt erst beim ersten Webhook.

**Bewusste Entscheidungen**

- **Keine Assets im Ticket.** Die Asset-Tabelle entfällt; nur die Anzahl wird
  übertragen. Damit entfallen auch die GraphQL-Abfragen nach Asset-Namen.
- **Keine Assignment Group.** Setzt ServiceNow selbst.
- **End-of-Life** wird als eigener `finding_type` gemeldet, nicht als Advisory.
- **`sysparm_requested_for`** wird nur bei gesetztem `SNOW_REQUESTED_FOR_SYS_ID`
  gesendet; sonst trägt ServiceNow den angemeldeten Benutzer ein.
- **Kein Wiedereinspielschutz über `webhook-id`.** Retries behalten laut
  Spezifikation dieselbe ID; das Zeitfenster von 5 Minuten genügt, da die
  Synchronisierung über die `correlation_id` ohnehin idempotent ist.
- **Referenz-Cache ohne Ablaufzeit.** Der Schlüsselraum ist durch die
  konfigurierten Benutzer begrenzt; Änderungen in ServiceNow wirken erst nach
  einem Neustart.
- **Alle Finding-Typen werden abgefragt.** Mit der gefilterten Abfrage kostet
  das einen Request, deshalb erhalten auch Fehlkonfigurationen ihr Risk Rating
  aus der API.
- **Risk aus der API vor dem Befundtext** (29.09.). Der KI-Text ist Fließtext
  und wich im geprüften Fall ab („combined risk is **high**" gegenüber
  100/CRITICAL in der API). Der Text nennt zwar das Case-Risiko, die API das
  Finding-Risiko im Space-Scope, maßgeblich ist aber der Wert der API.
- **`cvss` immer mit Alias je Typ abfragen.** Ohne Alias lehnt Mondoo die
  Abfrage ab (Vorfall 29.09.); ein Test in `tests/test_domain.py` sichert das ab.
  Neue Fragmente mit Feldern, die es in mehreren Typen gibt, brauchen im
  Zweifel ebenfalls einen Alias.
- **Mondoo-Risk vor CVSS** (01.10.): Urgency/Impact kommen zuerst aus dem
  Mondoo Risk Rating, dann aus dem CVSS-Rating, dann aus dem Tag im Titel,
  sonst Default (`determine_priority`). Anlass: RITM0043065 hatte Titel
  `[CRITICAL]` und Risk 100/CRITICAL, wegen CVSS 7.8/HIGH aber nur 2/2. Ein
  Rating ohne Eintrag in `PRIORITY_MAP` (etwa `NONE`) wird übersprungen.
- **Keine Katalogvariable `mondoo_title`** (01.10.): Der Titel steht nur in der
  Short Description des RITM (PATCH nach der Bestellung). Versuch mit
  RITM0043065 bestätigt, dass `order_now` ohne die Variable funktioniert.
  Folgen: Der Catalog Task kann den Mondoo-Titel nicht übernehmen; scheitert
  der PATCH, hat das RITM keinen Mondoo-Titel.
- **Tickettitel** (01.10.): `Mondoo - [SCHWEREGRAD] <Finding>`. Das
  Schweregrad-Tag bleibt; „Mitigate vulnerability“ (Vulnerabilities) bzw.
  „Mitigate advisory“ (Advisories, End-of-Life) direkt dahinter entfällt
  (`strip_mitigate_phrase`, `1531f67`). Bei allen Typen entfällt außerdem das
  Asset am Ende samt „on“ (`strip_asset_suffix`), getrennt am **letzten**
  „ on “, damit Prüfungen wie „Ensure 'Turn on …' is set to …“ vollständig
  bleiben. Beispiel: `[CRITICAL] Mitigate advisory MONDOO-EOL-ORACLE-JDK-18 on
  SUBVWBN` → `Mondoo - [CRITICAL] MONDOO-EOL-ORACLE-JDK-18`. Welche Assets
  betroffen sind, steht nur noch in `number_of_affected_assets` und in Mondoo.
  Gilt nur für neue RITMs, Updates ändern die Short Description bestehender
  RITMs nicht.
- **Kein CVSS bei End-of-Life, auch wenn die Mondoo-Oberfläche 10.0 zeigt.**
  Bei `MONDOO-EOL-NUMPY-1-26` zeigt die CVSS-Kachel „10.0", das Info-Fenster
  daneben aber „No CVSS data available for this vulnerability or advisory".
  Die 10.0 ist der Risk Score 100 geteilt durch 10; die API liefert für
  EOL-Advisories `cvss.value` 0 / `NONE`. Einen Risk Score als CVSS
  einzutragen, wurde mit `4e19628` bewusst abgeschafft.
- **`baseValue`/`baseRating` bleiben ungenutzt.** Sie liegen auf der Risk-Skala;
  beim `CheckFinding` steht dort 100, was als CVSS 10.0 falsch wäre.
- **Python 3.9-kompatibel**, obwohl Azure 3.11 fährt, weil die lokale
  Entwicklungsumgebung noch 3.9 nutzt.

**Alarmierung** (eingerichtet 29.09., Abonnement
`MOS-lz-MondooSecurity-prod-gwc`, Ressourcengruppe `rg-mondoo-servicenow-prod-gwc`)

| Bestandteil | Name | Zweck |
|---|---|---|
| Aktionsgruppe | `ag-mondoo-webhook-mail` (Kurzname `webhook-mail`) | eine E-Mail-Adresse |
| Metrikalarm | „Mondoo-Webhook HTTP 5xx" | `Http5xx > 0`, 5 min; ServiceNow-Fehler (502) und unerwartete Fehler (500) |
| Protokollsuche-Alarm | „Mondoo-Webhook - Fehler im Log" | Tabellenzeilen > 0, 5 min; zusätzlich Fehler mit HTTP 200 wie der Mondoo-422 |
| Diagnoseeinstellung | `diag-console-to-log-analytics` → `log-mondoo-webhook` | nur „App Service Console Logs" |

Beide Regeln: Schweregrad 2, automatisch auflösen. Abfrage der Log-Regel
(Stand 30.09.; die erste Fassung mit `has` griff bei `"Handled Exception [5"`
nie, weil `has` nur ganze Begriffe vergleicht und „5" in „[502]" keiner ist):

```
AppServiceConsoleLogs
| where ResultDescription contains_cs "[ERROR]"
    or ResultDescription contains_cs "[CRITICAL]"
    or ResultDescription contains_cs "Traceback"
    or ResultDescription contains_cs "Handled Exception [5"
    or ResultDescription contains_cs "Handled Exception [422]"
    or (ResultDescription contains_cs "Webhook abgewiesen"
        and ResultDescription !contains_cs "Signatur-Header fehlen")
| project TimeGenerated, ResultDescription
```

Abgedeckt: jede 5xx-Antwort (Metrik, unabhängig vom Log), jede `[ERROR]`-Zeile
(auch bei HTTP 200), Gunicorn-`[CRITICAL]` (z. B. `WORKER TIMEOUT`), Tracebacks
ohne `[ERROR]` (z. B. Startabbruch bei fehlerhaften Einstellungen), 422
(Payload von Mondoo nicht lesbar, sonst nur WARNING) und 401 **mit**
Standard-Webhooks-Headern. Letzteres ist praktisch immer Mondoo mit
veraltetem Signing Secret oder Auth-Header: Alle Zustellungen würden
abgewiesen, ohne Ticket und ohne 5xx.

Nicht abgedeckt, bewusst: 404/405 und 401 **ohne** Webhook-Header
(„Signatur-Header fehlen", Scanner aus dem Internet; ein Alarm auf die Metrik
„Http 4xx" wäre Dauerrauschen und kann Mondoo nicht von Bots unterscheiden)
sowie WARNING-Zeilen. Nicht abgedeckt, offen: Wenn gar nichts ankommt (Mondoo sendet nicht mehr, App komplett
ausgefallen), entsteht weder Fehler noch Log-Zeile. Absicherung wäre der
App-Service-Integritätscheck auf `/` plus Alarm auf „Health check status".
Pro Störung kommt eine Mail („ausgelöst" und „behoben"), nicht pro Fehler.

- **Alarmkette testen**, ohne Fehler auszulösen: vorübergehend zwei Regeln mit
  derselben Aktionsgruppe anlegen: Metrik `Requests > 0` und Log-Abfrage
  `AppServiceConsoleLogs | where ResultDescription contains_cs
  "request_completed"`. Dann die Startseite `/` der App im Browser aufrufen.
  Die Mails kommen nach ca. 5–10 bzw. 10–15 min. Test-Regeln danach löschen,
  sonst lösen die Azure-eigenen Aufrufe laufend Mails aus. Keine falschen
  Zugangsdaten zum Testen verwenden (geteiltes ServiceNow-Konto, Neustart der
  App).
- **Kosten** (Größenordnung, Listenpreise regional verschieden): Log-Regel
  alle 5 min ca. 1,50 USD/Monat (alle 15 min ca. 0,50 USD), Metrikalarm
  höchstens ca. 0,10 USD, E-Mails frei (1.000/Monat), Aufnahme ins Log
  Analytics ca. 2,30–2,80 USD/GB bei geschätzt < 0,1 GB/Monat (erste 5 GB je
  Abrechnungskonto frei), Aufbewahrung 30 Tage im Preis, Abfragen frei.
  Zusammen ca. 1,50–2 USD/Monat. Ist-Werte: Arbeitsbereich → „Nutzung und
  geschätzte Kosten" bzw. Kostenanalyse auf die Ressourcengruppe. Kein
  Tageslimit setzen: Bei Erreichen stoppt die Aufnahme und die Log-Regel wird
  blind.
- Die Spalte `Level` steht bei allen Konsolenzeilen auf „Informational"; gefiltert
  wird deshalb über den Text `[ERROR]` im Log-Format. **Wer das Log-Format in
  `app/core/logging.py` ändert, muss die Abfrage anpassen.** `tests/test_logging.py`
  prüft, dass `[ERROR]` erhalten bleibt.
- Jede Log-Zeile ist eine eigene Zeile in der Tabelle (Tracebacks also mehrere);
  Startmeldungen erscheinen doppelt, weil Gunicorn zwei Worker startet.
- Log Analytics erfasst erst ab der Einrichtung und mit einigen Minuten Verzug;
  die E-Mail der Log-Regel kommt etwa 5–10 min nach dem Fehler.
- Die App-Ressource heißt `app-mondoo-servicenow-webhook-prod`, spricht aber
  derzeit `bmsptest` an. Beim Livegang bzw. bei getrennten Umgebungen die
  Regeln für jede App-Ressource anlegen.

**Betriebliche Randbedingungen**

- Instanz-URL, Katalog-sys_id, Client-ID, Client Secret und Passwort gehören
  immer zusammen zu einer Instanz und müssen gemeinsam umgestellt werden.
- Key-Vault-Referenzen werden beim Start aufgelöst; nach Änderungen ist ein
  Neustart nötig.
- Deployment über Oryx mit komprimierter Ausgabe: In `wwwroot` liegen
  `oryx-manifest.toml` und `output.tar.zst`, nicht der Quellcode.
- Die Testinstanz nutzt ein Konto, das auch Kollegen verwenden. Wiederholte
  Fehlversuche können es sperren.
- **Logs in Kudu SSH durchsuchen:** `grep -h "<Suchtext>"
  /home/LogFiles/*docker*.log | tail -20`. Schneller als der Log-Stream, um die
  Zeilen zu einer Correlation-ID zu finden.
- **Skripte in Kudu SSH:** Beim Einfügen per Heredoc wird die Anzeige langer
  Texte zerstückelt, der Inhalt kann dabei beschädigt werden. Immer die ganze
  Datei kopieren (Strg+A) und mit `md5sum` gegen den lokalen Stand prüfen
  (`tr -d '\r' < scripts/verify_scores.py | md5sum`).
- **Lokale Entwicklung unter Windows** (venv mit Python 3.11): `requirements.txt`
  installiert unter Windows `tzdata` mit (für `ZoneInfo("Europe/Berlin")`); ein
  bestehendes venv braucht einmal `pip install -r requirements.txt`. Die
  Unterprozess-Tests geben über `tests.isolated_env` die Windows-Basisvariablen
  (`SYSTEMROOT`, `SYSTEMDRIVE`, …) weiter; seit 01.10. ist die Suite auch unter
  Windows grün. ruff und mypy sind nicht im venv installiert. Die Arbeitskopie
  nutzt CRLF (`core.autocrlf=true`).

## 6. Next Immediate Steps (Checkliste)

- [x] Commits `cf166b1` und `a33c94a` deployen (29.09.). Ergebnis: Mondoo
      lehnt die Abfrage mit 422 ab, siehe Abschnitt 3.
- [x] Fix vom 29.09. committen und deployen (`7e4b3c5`). End-of-Life geprüft
      (RITM0043015: CVSS leer, Risk 100 CRITICAL).
- [x] CVE-Ticket geprüft (RITM0043012: CVSS 9.4, Risk 100, beide CRITICAL).
- [x] Fehlkonfigurations-Ticket geprüft (RITM0043014: Risk 100 CRITICAL aus der
      API, CVSS leer).
- [ ] Optional: Bewertung auf die Assets des Case beschränken statt auf den
      ganzen Space (siehe „Scope ist der Space" in Abschnitt 5).
- [ ] RITMs ohne Werte aus der Zeit zwischen Deployment und Fix nachtragen
      (RITM0043011 und der Case `3JzhsQ0…`).
- [ ] Startprüfung der Mondoo-Abfrage beim Start der App (z. B. einmal
      `GET_FINDING_SCORES_QUERY` gegen den Space): Ein 422 oder ein falscher
      `MONDOO_API_KEY` fiele dann beim Deployment auf.
- [ ] Obsolete App-Settings in Azure entfernen (werden wegen `extra="ignore"`
      stillschweigend übergangen, sind aber irreführend):
      `MONDOO_GRAPHQL_MAX_PAGES`, `CVSS_SEARCH_BUDGET_SECONDS`,
      `CVSS_SEARCH_LOG_INTERVAL`, `CVSS_MAX_FINDING_ATTEMPTS`,
      `CVSS_RATING_THRESHOLDS` und `MONDOO_AUTH_HEADER` (falscher Name, die App
      liest `MONDOO_WEBHOOK_AUTH_HEADER`).
- [ ] `scripts/introspect_next.py` ausführen und anhand der Ausgabe über die
      Punkte 5 bis 9 aus Abschnitt 5 entscheiden.
- [ ] Punkte 1, 2 und 4 aus Abschnitt 5 umsetzen (kein Lookup beim Abschluss,
      CVE aus der MRN, Ticket-URL konstruieren). Punkt 3 ist erledigt.
- [ ] OAuth auf `bmsptest` klären: Eintrag in der Application Registry prüfen
      oder neu anlegen, Werte im Key Vault hinterlegen, dann
      `SNOW_AUTH_MODE=oauth`.
- [ ] Vor dem Livegang das Katalogformular auf `bmsp` prüfen: sys_id und
      Variablennamen. Bei Abweichung die Zuordnung konfigurierbar machen.
- [ ] „Map to field" für `mondoo_mrn` auf `correlation_id` aktivieren.
- [x] Urgency/Impact beim Anlegen (`c80a5e8`) im Betrieb bestätigt
      (RITM0043065, 01.10.).
- [x] Priority am RITM (bleibt 4 - Low): Admin-Thema in ServiceNow, nicht
      Teil der App (01.10.).
- [x] Priorisierung entschieden: Mondoo-Risk vor CVSS (01.10.). Nach dem
      Deployment an einem neuen RITM prüfen, z. B. Risk CRITICAL bei CVSS
      HIGH → Urgency/Impact 1.
- [x] E-Mail-Alarmierung bei Fehlern eingerichtet (Abschnitt 5,
      „Alarmierung").
- [x] E-Mail-Adresse der Aktionsgruppe bestätigt („Überprüft", 30.09.).
- [ ] Abfrage der Log-Regel in Azure auf die `contains_cs`-Fassung inklusive
      der 401-Bedingung umstellen (Abschnitt 5, „Alarmierung"). Vorher zählen,
      wie viele Abweisungen mit bzw. ohne Webhook-Header vorkommen.
- [ ] Beim ersten echten Alarm prüfen, dass die Mail mit Link zu den
      Log-Zeilen ankommt.
- [ ] Optional: Integritätscheck des App Service auf `/` aktivieren und Alarm
      auf „Health check status" anlegen (Totalausfall, keine Zustellungen).
- [x] Zweiten Space anbinden (Space *Server*, 30.09.; API-Key gilt für die
      ganze Organisation, Space steht bereits in `CATEGORY_MAP`).
- [x] Ausnahme getestet (30.09.): Finding verschwindet sofort aus dem
      Ticket, Mondoo schließt das leere Ticket mit Verzögerung automatisch.
- [x] RITM zum Test-Ticket (RITM0043042, CVE-2026-64564) per `TYPE_CLOSED`
      geschlossen, rund 11 min nach Freigabe der Ausnahme (30.09.).
- [ ] Prozess festlegen (Termin Vorgesetzter): Umgang mit abgelaufenen
      Ausnahmen (Finding zählt wieder, aber kein automatisches neues Ticket).
- [ ] Zweistufige SCTASKs (Abschnitt 5): entscheiden, ob die App bei
      `TYPE_CLOSED`/`TYPE_DELETED` das RITM trotz offener SCTASKs schließen
      darf; im Workflow umsetzen lassen: „Closed Incomplete“ am Prüf-SCTASK
      legt einen Nacharbeits-SCTASK an, nur „Closed Complete“ schließt das
      RITM (siehe BPMN-Prozess).
- [x] BPMN-Prozess an den Ist-Stand angepasst (05.10., `docs/bpmn-process.*`):
      SCTASKs, automatische Schritte, Abschluss durch Mondoo. Bei einer
      Entscheidung zum RITM-Abschluss (Punkt oben) das Gateway „RITM bereits
      geschlossen?“ im Diagramm nachziehen.
- [ ] Protokollstream zeigt seit 30.09. „No new trace“, obwohl Log Analytics
      Einträge hat: *App Service-Protokolle* (Anwendungsprotokollierung
      Dateisystem) prüfen.
- [x] `request_completed` um Methode, Pfad (maskiert) und Statuscode ergänzt
      (01.10., Abschnitt 3 „Logs 01.10.“).
- [x] `mondoo_title` aus dem Code gestrichen (01.10.).
- [ ] Feld *Mondoo Title* aus dem Katalogformular entfernen (`bmsptest`, vor
      dem Livegang `bmsp`).
- [x] SCTASK-Titel nach der Gruppenzuordnung überschreiben, in der App
      umgesetzt (01.10., Abschnitt 5, „Short Description des Catalog Task“).
- [ ] Beim Admin bestätigen lassen: Rechte von `mosca.rest` auf `sc_task`,
      Gruppenzuordnung innerhalb von ~6 s, keine Neuberechnung bei geänderter
      Short Description. Erster Nachweis im Betrieb (01.10.): RITM0043072,
      `SCTASK0042543: 'Mondoo Vulnerability - Azure' durch Tickettitel
      ersetzt`. **Auffällig:** Der Case kam aus dem Space *Server*, der
      Workflow-Text nennt aber *Azure*. Assignment Group dieses SCTASK prüfen
      und klären, woraus der Workflow den Space liest.
      **Seit 06.10. kein Titel mehr:** SCTASK0042545 (RITM0043075) behält
      „Mondoo Vulnerability - Azure“, am 01.10. klappte es noch (z. B.
      SCTASK0042537). Der Code ist seit `dbf30e3` (01.10.) unverändert, dort
      änderten sich nur Logtexte; die Ursache liegt also in ServiceNow oder in
      der Zeit bis zur Gruppenzuordnung. Klären über die Logzeile zum RITM:
      „durch Tickettitel ersetzt“ (danach von ServiceNow überschrieben,
      SCTASK-Verlauf prüfen), „Kein SCTASK mit Assignment Group“ (Gruppe nicht
      binnen 6 s gesetzt) oder „nicht gesetzt: HTTP …“ (Rechte auf `sc_task`).
      Im SCTASK-Verlauf keine spätere Änderung durch ServiceNow (06.10.).
      **Wartezeit auf 10 s erhöht (06.10.)** (`CATALOG_TASK_LOOKUP_DELAYS`);
      beide Logzeilen nennen jetzt die Wartezeit („Gruppe nach … s gefunden“
      bzw. „nach … s“). Sequenzdiagramm auf „≤ 10 s“ nachgezogen.
      **Ergebnis nach dem Deployment (06.10., 07:44 UTC):** RITM0043077,
      `SCTASK0042547: 'Mondoo Vulnerability - Azure' durch Tickettitel ersetzt
      (Gruppe nach 1.2 s gefunden)`, Case aus dem Space *Azure*, Text also
      richtig. 1,2 s hätten auch die alten 6 s gereicht.
      **Ursache bei RITM0043075 belegt (Log Analytics, 05.10. 19:11 UTC):**
      RITM angelegt 19:11:04.6, `Kein SCTASK mit Assignment Group zu
      RITM0043075 gefunden` um 19:11:10.96, also volle 6 s ohne Gruppe. Der
      Workflow braucht für die Gruppe also zeitweise länger als 6 s; die 10 s
      sind die Lösung, solange er unter 10 s bleibt (Zeitpunkt der Gruppe im
      Verlauf von SCTASK0042545 prüfen). Antwort an Mondoo nach 13,8 s mit
      HTTP 200. **Zweiter Fall „Azure“ für einen Server-Case:** Ticketdaten
      „Space Server“ (CVE-2026-63073 auf Testserver-Ubuntu), Workflow-Text
      „Mondoo Vulnerability - Azure“. Damit landen Server-Befunde womöglich bei
      der Azure-Gruppe (REQ-M07); Zuweisungsgruppe von SCTASK0042545 prüfen und
      mit dem Admin klären, woraus der Workflow den Space liest.
- [ ] **Testreihe über alle neun Spaces (06.10., 09:22–09:32 UTC):** 19
      Tickets in Mondoo eröffnet, alle als RITM angelegt (RITM0043078–96, HTTP
      200, Bewertung und Priorität korrekt, zwei parallele Zustellungen ohne
      Probleme). **Routing:** Der Workflow-Text lautet bei *jedem* Space
      „Mondoo Vulnerability - Azure“ (Windows-Clients, Domänen, Defender,
      Grafana, IP-Adressen, M365, VMware, vorher Server); die Middleware meldet
      jeweils den richtigen Space. **Ursache gefunden (06.10.):** Der Workflow
      bestimmt die Gruppe über eine Auswahlliste mit Werten wie
      `space_server`, `space_windows_clients` (Beschriftung „Server“, „Windows
      Clients“); die App schickte den Anzeigenamen aus `CATEGORY_MAP`
      („Server“). Unbekannte Werte landen bei der ersten Auswahl „Azure“; nur
      Azure-Cases waren deshalb zufällig richtig. **Fix (`527105c`):** neue
      Stammdaten `SPACE_CHOICE_MAP` (Space-ID → Auswahlwert), `mondoo_space`
      erhält den Auswahlwert; fehlt ein Space, ERROR und Anzeigename wie
      bisher. **Anzeige im Ticket (06.10., RITM0043097):** Die Variable
      `mondoo_space` ist im Formular ein Textfeld, keine Auswahl; der SCTASK
      zeigt deshalb `space_vmware` statt „VMware“. Soll die Beschriftung
      erscheinen, muss der Admin die Variable auf eine Auswahl (Select Box)
      mit genau diesen Werten umstellen; die App schickt den Wert unverändert
      weiter, der Workflow bleibt gleich. Die Anzeigenamen der App in Logs und
      Telemetrie („Windows-Clients“, „Domänen“) weichen von den
      Beschriftungen ab. Nach
      dem Deployment je Space ein Ticket eröffnen und mit der Prüfabfrage
      „Routing“ (Chat 06.10.) gegenprüfen; erwartet wird z. B. „Mondoo
      Vulnerability - Server“. Bereits angelegte SCTASKs außerhalb von Azure
      (Server ab RITM0043040, Testreihe RITM0043078–96) tragen vermutlich die
      Azure-Gruppe; prüfen und bei Bedarf von Hand umhängen.
- [ ] **Zeitgrenze bei Mondoo prüfen:** CVE-2026-59564 (RITM0043078,
      Antwort nach 6,6 s) zeigt in Mondoo nach 5 min kein External Ticket,
      die Zustellungen mit 2,7–4,6 s schon. Vermutlich wartet Mondoo nur rund
      5 s auf die Antwort. Gegenprobe in Mondoo: RITM0043087 (5,8 s, Grafana),
      RITM0043077 (6,2 s, Azure), RITM0043075 (13,8 s, Server) und „Most Recent
      Activity“ der Integration. Bestätigt sich das, den SCTASK-Titel nach der
      Antwort an Mondoo setzen (Hintergrundaufgabe) statt die Antwort zu
      verzögern.
- [ ] **SCTASK-Titel bei RITM0043076** (06.10. 07:00 UTC, Azure) nicht
      gesetzt, Verarbeitung 15,8 s. Lief noch mit 6 s (vor `2a91e74`, Commit
      07:29 UTC). Wie RITM0043075 (05.10. 19:11) war es das erste Ticket nach
      längerer Pause; danach stand die Gruppe nach 0,1–3,3 s. Muster
      beobachten: Fehlt der Titel beim ersten Ticket nach einer Pause auch mit
      10 s, Business Rule (A) oder Hintergrundaufgabe mit längerer Wartezeit.
- [ ] **Telemetrie-Auswertung:** Für die Übergabezeit nach
      `mondoo_event == "TYPE_CREATED"` filtern (entfernt RITM0043045, eine
      Folgezustellung). Bleiben 58 Zustellungen. RITM0043026–28 (30.09.,
      12:13–12:15 UTC, Azure) sind echte Anlage-Zustellungen, kamen aber 18
      bis 66 min nach der Ticketanlage an. Ursache offen: Mondoo verspätet oder
      erster Versuch gescheitert und später wiederholt (dann gibt es für
      dieselbe `webhook-id` frühere Logzeilen). Ohne sie (n = 55):
      Übergabezeit Median 33,6 s, Mittel 34,1 s, Max 66,5 s; mit ihnen Median
      34,1 s, Mittel 183,5 s. 53 von 58 unter 60 s. „Most Recent Activity“
      der Integration zeigt noch keine Daten (06.10.).
- [ ] In ServiceNow „Map to field" für die Variablen `urgency` → Urgency und
      `impact` → Impact aktivieren (`bmsptest` und vor dem Livegang `bmsp`).
- [x] Architektur-Review und Refactoring W1–W8, I1–I7 (01.10., Abschnitt 3
      „Refactoring 01.10.“).
- [x] Refactoring committet (`462f566`) und deployt; Anlegen samt SCTASK-Titel
      im Betrieb bestätigt (RITM0043072, 01.10.).
- [ ] Logs-Änderung (`dbf30e3`) deployen, dann im Protokollstream je einmal
      Anlegen, Update und Schließen ansehen (je rund 10 Zeilen).
- [ ] I8: Python-Zielversion festlegen (läuft lokal auf dem Mac noch 3.9?)
      und eine CI-Pipeline mit ruff, mypy, Tests und Abdeckung einrichten.
- [ ] Optional: Backup-Branch pushen
      (`git push origin backup/pre-cleanup-2026-10-01`), bisher nur lokal.
- [ ] Optional: Getrennte Ressourcengruppen oder ein Deployment-Slot für Test
      und Prod, damit Einstellungen nicht gegeneinander getauscht werden müssen.
