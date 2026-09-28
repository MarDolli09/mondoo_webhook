# Project Context Handover

Stand: 28.09.2026, Commit `4e19628`. Arbeitsverzeichnis sauber, alle Änderungen committet.

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
gegen die Testinstanz `bmsptest`. Offen sind die Umstellung auf OAuth, der
Livegang gegen `bmsp` und eine Optimierung der Mondoo-Abfrage.

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
Tickets werden angelegt, aktualisiert und geschlossen. 49 Tests, ruff und mypy
sind grün.

**Zuletzt geändert** (Commit `4e19628`, noch **nicht deployt**): Trennung von
CVSS und Mondoo Risk Score.

- `app/domain/scores.py` (ersetzt `cvss.py`): `FindingScores` mit vier Werten,
  `normalize_cvss_score` (0–10) und `normalize_risk_score` (0–100).
- `app/services/mondoo/findings.py`: `extract_finding_scores` liest CVSS nur aus
  dem CVSS-Objekt bzw. `baseValue`/`baseRating`, Risk aus `riskValue`/`riskScore`
  und `rating`. Vorher wurde ein fehlendes CVSS durch den Risk Score ersetzt und
  dieser durch zehn geteilt (Risk 89 erschien als „CVSS 8.9").
- `app/services/parsing/case_parser.py`: Risk-Werte zuerst aus der AI-Summary,
  sonst aus der API. Priorisierung unverändert: CVSS-Rating, dann Risk Rating,
  dann Titel-Präfix, dann Default.
- `app/models/case.py`, `app/api/telemetry.py`: Feld `cvss_found_on_page` heißt
  jetzt `found_on_page`.

**Zuletzt geprüft:** Die Introspektion der Mondoo-API ergab, dass `findings`
einen `filter: FindingsFilter` mit `mrn`/`mrns` akzeptiert. Ein Testskript zur
Bestätigung liegt bereit (siehe Abschnitt 6).

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
| `app/services/mondoo/queries.py` | GraphQL-Abfrage (aktuell paginierte Suche) |
| `app/services/mondoo/findings.py` | Auswertung einzelner Finding-Knoten |
| `app/services/servicenow/mapping.py` | Katalogvariablen und RITM-Felder |
| `app/services/servicenow/client.py` | Anlegen, Aktualisieren, Schließen |
| `app/services/servicenow/api.py` | REST-Aufrufe mit Retry und Fehlerdiagnose |
| `tests/fakes.py` | Attrappen für Mondoo und ServiceNow, Ende-zu-Ende-Aufrufe |
| `tests/test_architecture.py` | Architekturregeln als Test |
| `tests/.env.test` | Dummy-Umgebung für Tests und Audits |
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
- **Rating-Stufen:** Mondoo zeigt für Risk 100 „Mission-Critical". Fehlt die
  Stufe in `PRIORITY_MAP`, greift bei Findings ohne CVSS der Titel-Fallback.

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
- **Fehlkonfigurationen fragen die Mondoo-API nicht ab** (`resolves_scores=False`),
  weil die heutige Suche zu teuer ist. Mit dem Filter aus Abschnitt 6 entfällt
  der Grund.
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

- [ ] Commit `4e19628` deployen und im Log prüfen: `Bewertung auf Seite N
      geladen … -> CVSS 9.8 (CRITICAL), Risk 100 (…)`. Die tatsächliche
      Rating-Stufe notieren und bei Bedarf in `PRIORITY_MAP` ergänzen.
- [ ] `filter_test.py` in Kudu SSH ausführen und prüfen, ob
      `findings(filter: {mrn: …})` das Finding direkt liefert und ob die
      Space-MRN als Scope genügt.
- [ ] Bei Erfolg die paginierte Suche durch eine gefilterte Abfrage ersetzen
      (`queries.py`, `api.py`, `client.py`); `MONDOO_GRAPHQL_MAX_PAGES`,
      `CVSS_SEARCH_BUDGET_SECONDS`, `CVSS_SEARCH_LOG_INTERVAL` und
      `CVSS_MAX_FINDING_ATTEMPTS` entfallen, `resolves_scores` für
      `misconfiguration` aktivieren.
- [ ] OAuth auf `bmsptest` klären: Eintrag in der Application Registry prüfen
      oder neu anlegen, Werte im Key Vault hinterlegen, dann
      `SNOW_AUTH_MODE=oauth`.
- [ ] Vor dem Livegang das Katalogformular auf `bmsp` prüfen: sys_id und
      Variablennamen. Bei Abweichung die Zuordnung konfigurierbar machen.
- [ ] „Map to field" für `mondoo_mrn` auf `correlation_id` aktivieren.
- [ ] Optional: Getrennte Ressourcengruppen oder ein Deployment-Slot für Test
      und Prod, damit Einstellungen nicht gegeneinander getauscht werden müssen.
