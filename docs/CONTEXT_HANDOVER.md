# Project Context Handover

Stand: 29.09.2026, Commit `a33c94a`. Arbeitsverzeichnis sauber, alle Änderungen
committet, **Deployment nach Azure noch offen**.

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
gegen die Testinstanz `bmsptest`. Die Mondoo-Abfrage ist auf einen gefilterten
GraphQL-Aufruf je Finding umgestellt (committet, noch nicht deployt). Offen sind
das Deployment dieser Umstellung, die Umstellung auf OAuth, der Livegang gegen
`bmsp` und die weitere Ablösung von Textparsing und Stammdaten durch die API
(siehe Abschnitte 5 und 6).

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
Tickets werden angelegt, aktualisiert und geschlossen. 50 Tests, ruff und mypy
sind grün.

**Zuletzt geändert** (Commits `4e19628`, `cf166b1` und `a33c94a`, alle noch
**nicht deployt**):

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
- `app/services/parsing/case_parser.py`: Risk-Werte zuerst aus der AI-Summary,
  sonst aus der API; gefragt wird im Scope des Space (`ownerMrn`), nicht je
  Asset. Alle Finding-Typen werden abgefragt, auch Fehlkonfigurationen.
- Entfallen: `MONDOO_GRAPHQL_MAX_PAGES`, `CVSS_SEARCH_BUDGET_SECONDS`,
  `CVSS_SEARCH_LOG_INTERVAL`, `CVSS_MAX_FINDING_ATTEMPTS` (ersetzt durch
  `MONDOO_MAX_FINDING_LOOKUPS`, Standard 5), `PaginationLimitExceededError`,
  `SearchBudgetExceededError`, `CVSS_RATING_THRESHOLDS`,
  `calculate_rating_from_score`, `FindingTypeProfile.resolves_scores`, das Feld
  `found_on_page`.

**Zuletzt geprüft** (gefilterte Abfrage gegen die echte API, Scope = Space-MRN):

| Finding | `totalCount` | `riskValue` / `rating` | `cvss` |
|---|---|---|---|
| `//vadvisor.api.mondoo.app/cves/CVE-2026-23450` | 6 | 97 / `CRITICAL` | `{value: 98, rating: CRITICAL}` |
| `//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-DOTNET-8` | 3 | 89 / `HIGH` | `{value: 0, rating: NONE}` |
| `//policy.api.mondoo.app/queries/cis-microsoft-azure-foundations--8.3.2` | 5 | 100 / `CRITICAL` | kein Feld (`CheckFinding`) |

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
| `app/services/mondoo/queries.py` | GraphQL-Abfrage `findings(filter: {mrn})` |
| `app/services/mondoo/api.py` | GraphQL-Transport, Union-Fehler der Antwort |
| `app/services/mondoo/client.py` | Abfrage je Finding, höchstes Risiko über alle Assets |
| `app/services/mondoo/findings.py` | Auswertung einzelner Finding-Knoten |
| `app/services/servicenow/mapping.py` | Katalogvariablen und RITM-Felder |
| `app/services/servicenow/client.py` | Anlegen, Aktualisieren, Schließen |
| `app/services/servicenow/api.py` | REST-Aufrufe mit Retry und Fehlerdiagnose |
| `tests/fakes.py` | Attrappen für Mondoo und ServiceNow, Ende-zu-Ende-Aufrufe |
| `tests/test_architecture.py` | Architekturregeln als Test |
| `tests/.env.test` | Dummy-Umgebung für Tests und Audits |
| `scripts/verify_scores.py` | Führt die Produktionsabfrage gegen die echte API aus |
| `scripts/introspect_next.py` | Introspektion für die offenen GraphQL-Kandidaten |
| `README.md` | Ablauf, Mapping-Tabelle, Betrieb in Azure |

## 5. Open Issues, Edge Cases & Constraints

**Offene Punkte**

- **OAuth auf `bmsptest` scheitert** (`access_denied`). Benutzer und Passwort
  stimmen dort (Basic Auth funktioniert), Client-ID und Client Secret stammen
  aus Prod und gelten auf der Testinstanz nicht. Gegen Prod liefert derselbe
  Aufruf ein Token.
- **Variablennamen sind instanzabhängig.** Die App verwendet die Namen des
  Formulars auf `bmsptest` (`cve`, `cvss_risk_rating`, `mondoo_risk_rating`,
  `mondoo_risk_score`, `mondoo_ticket_url`, `number_of_affected_assets`,
  `created_by`). Die ursprüngliche Mapping-Tabelle nannte andere. Vor dem
  Livegang muss das Formular auf Prod geprüft werden.
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
  die nicht am Case hängen.

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
3. **Risk aus der API** statt aus der AI-Summary (`extract_risk_from_summary`,
   vier Regex-Muster für drei Markdown-Formate). Offene Entscheidung: Der Text
   nennt das **Case**-Risiko, die API das **Finding**-Risiko im Space-Scope. In
   den geprüften Fällen identisch (EOL 89/HIGH), bei mehreren Findings je Case
   nicht zwingend.
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
- **`baseValue`/`baseRating` bleiben ungenutzt.** Sie liegen auf der Risk-Skala;
  beim `CheckFinding` steht dort 100, was als CVSS 10.0 falsch wäre.
- **Python 3.9-kompatibel**, obwohl Azure 3.11 fährt, weil die lokale
  Entwicklungsumgebung noch 3.9 nutzt.

**Betriebliche Randbedingungen**

- Instanz-URL, Katalog-sys_id, Client-ID, Client Secret und Passwort gehören
  immer zusammen zu einer Instanz und müssen gemeinsam umgestellt werden.
- Key-Vault-Referenzen werden beim Start aufgelöst; nach Änderungen ist ein
  Neustart nötig.
- Deployment über Oryx mit komprimierter Ausgabe: In `wwwroot` liegen
  `oryx-manifest.toml` und `output.tar.zst`, nicht der Quellcode.
- Die Testinstanz nutzt ein Konto, das auch Kollegen verwenden. Wiederholte
  Fehlversuche können es sperren.

## 6. Next Immediate Steps (Checkliste)

- [ ] Commits `cf166b1` und `a33c94a` deployen und im Log prüfen: `Bewertung
      fuer //… (CveFinding, 6 Assets) -> CVSS 9.8 (CRITICAL), Risk 97
      (CRITICAL)`. Für eine Fehlkonfiguration muss jetzt ebenfalls ein
      Risk-Wert erscheinen.
- [ ] Nach dem Deployment im Ticket prüfen: `cvss_score`/`cvss_risk_rating` bei
      CVEs gefüllt, bei End-of-Life leer, `mondoo_risk_score`/`_rating` überall
      gefüllt.
- [ ] Obsolete App-Settings in Azure entfernen (werden wegen `extra="ignore"`
      stillschweigend übergangen, sind aber irreführend):
      `MONDOO_GRAPHQL_MAX_PAGES`, `CVSS_SEARCH_BUDGET_SECONDS`,
      `CVSS_SEARCH_LOG_INTERVAL`, `CVSS_MAX_FINDING_ATTEMPTS`,
      `CVSS_RATING_THRESHOLDS` und `MONDOO_AUTH_HEADER` (falscher Name, die App
      liest `MONDOO_WEBHOOK_AUTH_HEADER`).
- [ ] `scripts/introspect_next.py` ausführen und anhand der Ausgabe über die
      Punkte 5 bis 9 aus Abschnitt 5 entscheiden.
- [ ] Punkte 1, 2 und 4 aus Abschnitt 5 umsetzen (kein Lookup beim Abschluss,
      CVE aus der MRN, Ticket-URL konstruieren). Zu Punkt 3 (Risk aus der API
      statt aus der AI-Summary) steht die Entscheidung noch aus.
- [ ] OAuth auf `bmsptest` klären: Eintrag in der Application Registry prüfen
      oder neu anlegen, Werte im Key Vault hinterlegen, dann
      `SNOW_AUTH_MODE=oauth`.
- [ ] Vor dem Livegang das Katalogformular auf `bmsp` prüfen: sys_id und
      Variablennamen. Bei Abweichung die Zuordnung konfigurierbar machen.
- [ ] „Map to field" für `mondoo_mrn` auf `correlation_id` aktivieren.
- [ ] Optional: Getrennte Ressourcengruppen oder ein Deployment-Slot für Test
      und Prod, damit Einstellungen nicht gegeneinander getauscht werden müssen.
