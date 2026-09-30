# Project Context Handover

Stand: 29.09.2026, Commit `c80a5e8`. Der Fix für die von Mondoo abgelehnte
Abfrage (Abschnitt 3) ist **deployt und für alle drei Finding-Typen geprüft**
(CVE, Fehlkonfiguration, End-of-Life). Urgency/Impact beim Anlegen ist
committet, die Prüfung am neuen RITM steht aus. **E-Mail-Alarmierung bei
Fehlern ist eingerichtet** (Abschnitt 5, „Alarmierung").

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
app/api        HTTP-Endpunkt, Authentifizierung, Lifespan, Telemetrie
app/services   mondoo (Bewertungen) · parsing (CaseParser) · servicenow (RITM)
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
  `FindingScoresLookup` (Mondoo) und `TicketSynchronizer` (ServiceNow).

**Muster:**

- Konfiguration über pydantic-settings, Validierung beim Start (fail fast).
  Technisches in `core/config.py`, Fachdaten in `core/master_data.py`.
- Geteilte Ressourcen (HTTP-Client, ServiceNow-Auth, Referenz-Cache,
  Signaturprüfer) entstehen im Lifespan und kommen per FastAPI-Dependency.
- Fehler nachgelagerter Systeme ergeben immer **502**, nie deren Statuscode.
- Logs enthalten nie Geheimwerte; die Correlation-ID steht in jeder Zeile.

## 3. Active Task & Current State

**Funktionsfähig:** Ende-zu-Ende gegen `bmsptest` mit `SNOW_AUTH_MODE=basic`.
Tickets werden angelegt, aktualisiert und geschlossen. 53 Tests, ruff und mypy
sind grün (zu den 9 Windows-Ausfällen in `test_config` siehe Abschnitt 5).

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
| `app/api/webhook.py` | Endpunkt `POST /webhook/mondoo`, Ablaufsteuerung, Telemetrie |
| `app/api/authentication.py` | Auth-Header und Signaturprüfung, 401 mit Diagnose im Log |
| `app/api/dependencies.py` | Lifespan, geteilte Ressourcen, Startprotokoll der Einstellungen |
| `app/api/telemetry.py` | Telemetriedatensatz, Header-Stichprobe |
| `app/core/config.py` | Technische Einstellungen samt Startvalidierung |
| `app/core/master_data.py` | Spaces, Benutzer, Prioritäten, Finding-Typen, feste Beobachter |
| `app/core/webhook_signature.py` | Standard-Webhooks-Signatur (HMAC-SHA256) |
| `app/core/logging.py` | Secret-Maskierung, Correlation-ID |
| `app/domain/scores.py` | CVSS- und Risk-Skalen, Ergebnistyp `FindingScores` |
| `app/domain/priority.py` | Urgency/Impact samt Herkunft |
| `app/domain/finding_types.py` | Klassifikation und Verarbeitungsprofile je Typ |
| `app/domain/case_text.py` | Auswertung der AI-Summary, Titel ohne Schweregrad-Tag |
| `app/domain/identifiers.py` | MRNs, Space-IDs, Identitäten, Mondoo-Links |
| `app/models/mondoo.py` | Eingangsmodell des Webhooks |
| `app/models/case.py` | `NormalizedCase` als interne Zwischenform |
| `app/services/parsing/case_parser.py` | Klassifikation, Anreicherung, Normalisierung |
| `app/services/mondoo/queries.py` | GraphQL-Abfrage `findings(filter: {mrn})`, `cvss` je Typ mit Alias (`CVSS_FIELDS`) |
| `app/services/mondoo/api.py` | GraphQL-Transport, Union-Fehler, GraphQL-Meldungen fürs Log |
| `app/services/mondoo/client.py` | Abfrage je Finding, höchstes Risiko über alle Assets |
| `app/services/mondoo/findings.py` | Auswertung einzelner Finding-Knoten |
| `app/services/servicenow/mapping.py` | Katalogvariablen und RITM-Felder |
| `app/services/servicenow/client.py` | Anlegen, Aktualisieren, Schließen |
| `app/services/servicenow/api.py` | REST-Aufrufe mit Retry und Fehlerdiagnose |
| `tests/fakes.py` | Attrappen für Mondoo und ServiceNow, Ende-zu-Ende-Aufrufe |
| `tests/test_architecture.py` | Architekturregeln als Test |
| `tests/.env.test` | Dummy-Umgebung für Tests und Audits |
| `scripts/verify_scores.py` | Führt die Produktionsabfrage gegen die echte API aus; optional `<findingMrn> [scope …]`, misst die Dauer |
| `scripts/introspect_next.py` | Introspektion für die offenen GraphQL-Kandidaten |
| `README.md` | Ablauf, Mapping-Tabelle, Betrieb in Azure |

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
  unberührt, damit manuelle Änderungen erhalten bleiben. Noch offen: „Map to
  field" in ServiceNow, damit die Werte schon bei der Bestellung stehen; ob
  ServiceNow die Priority am RITM aus Urgency/Impact neu berechnet.
- **Short Description des Catalog Task** („Mondoo Vulnerability - Windows
  Clients") setzt der Flow/Workflow des Katalogelements, nicht die App. Die App
  schreibt nur `sc_req_item` (Short Description = `Mondoo - <Titel>` per PATCH
  nach der Bestellung). Soll der Task den Mondoo-Titel tragen, im Flow die
  Katalogvariable `mondoo_title` verwenden, nicht die Short Description des RITM:
  Der Flow läuft bei der Bestellung, also vor dem PATCH.
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
  `app/core/logging.py` ändert, muss die Abfrage anpassen.**
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
- **Lokale Entwicklung unter Windows** (venv mit Python 3.11): Im venv fehlt
  `tzdata`, ohne das `ZoneInfo("Europe/Berlin")` scheitert. Die 9
  Unterprozess-Tests in `tests/test_config.py` scheitern dort mit `WinError
  10106`, auch ohne Codeänderung. ruff und mypy sind nicht im venv installiert.
  Die Arbeitskopie nutzt CRLF (`core.autocrlf=true`).

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
- [ ] Urgency/Impact beim Anlegen (Abschnitt 5, `c80a5e8`): deployen, dann an
      einem neuen RITM prüfen, dass Impact/Urgency sofort den Variablen
      entsprechen und ob Priority mitzieht.
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
- [ ] In ServiceNow „Map to field" für die Variablen `urgency` → Urgency und
      `impact` → Impact aktivieren (`bmsptest` und vor dem Livegang `bmsp`).
- [ ] Optional: Getrennte Ressourcengruppen oder ein Deployment-Slot für Test
      und Prod, damit Einstellungen nicht gegeneinander getauscht werden müssen.
