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
   priorisiert: CVSS-Rating → Mondoo Risk Rating → Schweregrad-Tag im Titel →
   Default.
4. `ServiceNowClient` sucht das RITM über `correlation_id` (= Case-MRN) und
   * bestellt ein neues Katalogformular, wenn keines existiert,
   * aktualisiert bzw. schließt ein offenes RITM (Close → State 3, Delete → 7),
   * verwirft Ereignisse zu RITMs im Endstatus.
5. Je Webhook entsteht ein JSON-Telemetriedatensatz
   (`mondoo_to_servicenow_processed`) mit `correlation_id` und `case_mrn`.

Der Tickettitel lautet `Mondoo - <Mondoo-Titel ohne [CRITICAL] usw.>`.
Assignment Groups setzt ServiceNow selbst.

## ServiceNow-Mapping

Katalogformular „Mondoo Vulnerability“ (`order_now`), Reihenfolge wie im Formular:

| Formularfeld | Variable | Wert |
|---|---|---|
| Mondoo Title | `mondoo_title` | `Mondoo - <Titel ohne Schweregrad-Tag>` |
| CVE | `cve` | CVE aus dem Titel, sonst ` / ` |
| CVSS Score / CVSS Risk Rating | `cvss_score` / `cvss_risk_rating` | aus `cvss.value`/`cvss.rating` des Findings; die API liefert 0–100 (98 = 9.8), 0 bedeutet kein CVSS |
| Mondoo Risk Rating / Score | `mondoo_risk_rating` / `mondoo_risk_score` | aus `riskValue`/`rating` des Findings (Skala 0–100), nur ohne API-Wert aus der AI-Summary |
| Urgency / Impact | `urgency` / `impact` | `1` (Critical) bis `4` (Low) |
| Mondoo Space | `mondoo_space` | Anzeigename laut `CATEGORY_MAP` |
| Finding type | `finding_type` | `vulnerability`, `advisories`, `end-of-life`, `misconfiguration`, `other` |
| Mondoo Ticket URL | `mondoo_ticket_url` | Link auf den Case in Mondoo |
| Number of affected assets | `number_of_affected_assets` | `assetsCount`, sonst Anzahl Assets aus den Refs |
| Created by | `created_by` | Name laut `USER_MAP`, MRN oder `Mondoo-Drift` |
| Mondoo MRN | `mondoo_mrn` | Case-MRN (in ServiceNow per „Map to field“ → `correlation_id`) |

RITM-Felder per PATCH nach der Bestellung: `state` (1), `correlation_id`,
`short_description` (= Titel), `opened_by` (`mosca.rest`), `watch_list`,
`work_notes`. Urgency und Impact übernimmt ServiceNow aus dem Request.
Folgeereignisse aktualisieren `work_notes`,
bei ermittelter Priorität `urgency`/`impact` und schließen bei Close/Delete.

## Architektur

```
app/api        HTTP-Endpunkt, Lifespan, Abhängigkeiten, Telemetrie
app/services   mondoo (Findings-Abfrage) · parsing (CaseParser) · servicenow (RITM)
app/domain     Fachregeln ohne I/O, Schnittstellen FindingScoresLookup / TicketSynchronizer
app/models     Eingangsmodell (Mondoo) und NormalizedCase
app/core       Konfiguration, Stammdaten, Logging, Ausnahmen
```

Importregeln (durch `tests/test_architecture.py` geprüft):

* Abhängigkeiten zeigen nur nach unten, der Importgraph ist azyklisch.
* Teilsysteme (`app.api`, `app.services.*`) werden von außen nur über ihre
  `__init__.py` importiert.
* `app.domain` und `app.models` sind ohne Umgebungsvariablen importierbar.

## Betrieb in Azure

* Startbefehl: `gunicorn app.main:app -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --timeout 600`
* App Setting `SCM_DO_BUILD_DURING_DEPLOYMENT=true`, deployt wird der Inhalt des
  Repository-Stamms (`app/`, `main.py`, `requirements.txt` direkt unter `wwwroot`).
* `MONDOO_WEBHOOK_SIGNING_SECRET` und `MONDOO_WEBHOOK_AUTH_HEADER_VALUE` als
  Key-Vault-Referenzen; die Werte müssen exakt denen der Mondoo-Integration entsprechen.
* Mondoo-Integration: URL `https://<host>/webhook/mondoo` (ohne abschließenden `/`),
  „Sign deliveries“ und „Send an authentication header“ aktiv.

## Konfiguration

Technische Einstellungen: `app/core/config.py`. Fachliche Stammdaten
(Spaces, Benutzer, Prioritäten, Finding-Typen, feste Beobachter):
`app/core/master_data.py`. Vorlage aller Variablen: `.env.example`.

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
Testlauf: `TEST_LOGS=1`.
