# Befunde aus den Integrationstests

Vorlage für den Anhang der Arbeit. Aufgenommen sind nur **beobachtete**
Befunde mit Instanz, Datum, Beleg und Fallzahl. Deutungen, Annahmen und offene
Tests stehen getrennt darunter. Zeiten in UTC (Ortszeit = UTC + 2 h).
`bmsptest` ist die Test-, `bmsp` die Produktivinstanz von ServiceNow; die Zeilen
sind je Instanz getrennt, damit Testbestand und Produktion in Kap. 6 nicht
vermischt werden.

Vorschlag für die Beschriftung: *Tab. X: Beobachtete Befunde der
Integrationstests, getrennt nach Instanz (Eigene Darstellung)*.

| Nr. | Aussage | Instanz | Datum | Beleg | n |
|---|---|---|---|---|---|
| B1 | Der Webhook nennt nicht, wer ein Ticket geschlossen hat; `createdBy` ist auch bei `TYPE_CLOSED` der Ersteller des Case. | Mondoo → Middleware | 30.09.–08.10.2026 | Telemetrie in Log Analytics; darunter RITM0043042, das Mondoo selbst geschlossen hat | 40 Cases |
| B2 | Beim Schließen sendet Mondoo `TYPE_UPDATED` mit Status `CASE_CLOSED` und rund 2 s später `TYPE_CLOSED`. | Mondoo → Middleware | 09.10.2026 | App-Log 07:38:25 und 07:38:27 (Case `3KQ4MJgc…`, RITM0043103) | 1 |
| B3 | Fehlte auf der Zielinstanz das RITM, legte die Middleware beim `UPDATED` ein neues an und schloss es beim `TYPE_CLOSED` wieder (Fehler, im Code behoben). | bmsp | 08.10.2026 | RITM0049383/0049384: angelegt 11:09:07/11:09:14, geschlossen 11:09:11/11:09:17, `closed_by` = `mosca.rest` | 2 |
| B4 | Nach einer Ausnahme mit Bereich „1 CVE“ (alle Assets im Space) schließt Mondoo das Ticket selbst, rund 11 min nach der Freigabe. | Mondoo, bmsptest | 30.09.2026 | `exception-3`, RITM0043042, `TYPE_CLOSED` 16:20:05 | 1 |
| B5 | Nach Ausnahmen mit Bereich „1 CVE on 1 asset“ (Risk Accepted, False Positive) bleibt das Ticket offen, auch nach dem nächsten Scan; das Asset bleibt „Affected“. | Mondoo, bmsptest | 08.–09.10.2026 | `exception-5` (19:37), `exception-6` (21:31), Case `3KQ4MJgc…`, RITM0043103, Scan 20:53 | 1 Ticket |
| B6 | Die Findings-Abfrage je Asset liefert vor der Ausnahme `OPEN 1`, danach `OPEN 0 / EXCEPTION 1`; der Space-Scope umfasst weitere Assets. | Mondoo-API | 08.10.2026 | `scripts/verify_open_findings.py`, CVE-2024-27025 auf zscalermuc01 | 1 |
| B7 | Ein SCTASK lässt sich ohne gebuchte Zeit nicht schließen (HTTP 403, Geschäftsregel „MSC - Book task time to close“). | bmsptest | 09.10.2026 | App-Log 07:38:28, SCTASK0042572 | 1 |
| B8 | Gebucht wird jeweils Sekunden vor dem Schließen des SCTASK. | bmsptest | 09.10.2026 | `task_time_worked` und `closed_at`: SCTASK0042574, 0042576, 0042577 | 3 |
| B9 | Gebucht wird jeweils Sekunden vor dem Schließen des SCTASK. | bmsp | 08.10.2026 | `task_time_worked` und `closed_at`: SCTASK0048981, 0048987, 0048990 | 3 |
| B10 | Das Feld „Time worked“ an SCTASK und RITM bleibt 0, obwohl Zeiteinträge vorliegen (Lesesicht `mosca.rest`). | bmsptest | 09.10.2026 | `servicenow_time_report.py`: SCTASK0042574/76/77, RITM0043105/06 | 3 SCTASKs |
| B11 | Das Feld „Time worked“ an SCTASK und RITM bleibt 0, obwohl Zeiteinträge vorliegen (Lesesicht `mosca.rest`). | bmsp | 09.10.2026 | `servicenow_time_report.py`: SCTASK0048981/87/90, RITM0049380/85 | 3 SCTASKs |
| B12 | Der Prüf-SCTASK entsteht erst nach dem Schließen des Behebungs-SCTASK, 1 s danach. | bmsptest | 09.10.2026 | SCTASK0042574 → 0042575 (09:11:41/42), 0042576 → 0042577 (10:01:06/07) | 2 |
| B13 | Der Prüf-SCTASK entsteht erst nach dem Schließen des Behebungs-SCTASK, 2 s danach, in „Mosca IT - Security“. | bmsp | 08.10.2026 | SCTASK0048981 → 0048987 (11:08:06/08), 0048990 → 0048991 (11:11:33/35) | 2 |
| B14 | Der Workflow legt den Prüf-SCTASK auch an einem bereits geschlossenen RITM an. | bmsp | 08.10.2026 | RITM0049380: RITM geschlossen 11:05:45, Behebungs-SCTASK 11:08:06, Prüf-SCTASK 11:08:08 | 1 |
| B15 | Das Wiederöffnen des Behebungs-SCTASK geschieht von Hand; nach dem erneuten Schließen entsteht kein zweiter Prüf-SCTASK. | bmsptest | 09.10.2026 | Aktivitäts-Screenshots RITM0043106 (Wiederöffnen 10:03:56) und ein weiterer Test-RITM (Nummer ergänzen) | 2 |
| B16 | `closed_at` behält nach dem Wiederöffnen den ersten Abschluss. | bmsptest | 09.10.2026 | SCTASK0042576: `closed_at` 10:01:06, erneut geschlossen nach der Buchung um 10:05:12 | 1 |
| B17 | Mit dem Schließen des Prüf-SCTASK schließt „System“ in derselben Sekunde das RITM; der REQ meldet „Automatically Closed as all Line Items were complete“. | bmsptest | 09.10.2026 | RITM0043106, 10:06:04 (Screenshots) | 1 |
| B18 | Jedes von der Middleware geschlossene RITM hinterlässt einen offenen SCTASK. | bmsptest | 01.–09.10.2026 | `closed_by` = `mosca.rest`: RITM0043045–0043073, 0043103, 0043104 | 27 von 27 |
| B19 | Personen schließen RITMs auch bei offenem SCTASK bzw. vor den Tasks (Konto vermutlich mit Administratorrechten). | bmsp | 08.–09.10.2026 | RITM0049368 (SCTASK offen), RITM0049380 (vor den Tasks) | 2 |
| B20 | Die Gruppe aus dem Space greift nicht: Alle Behebungs-SCTASKs entstehen in „Mosca IT - M365 General“. | bmsptest | 01.–09.10.2026 | `sctasks.csv` (54) und Screenshots vom 09.10. (2) | 56 von 56 |
| B21 | Die Gruppe aus dem Space greift: Behebungs-SCTASKs in drei Fachgruppen, Prüf-SCTASKs in „Mosca IT - Security“. | bmsp | 08.10.2026 | `sctasks.csv` | 7 (+ 2 Prüf) |
| B22 | Die Middleware setzt am RITM Impact „1 - High“; SCTASK und REQ bleiben auf Impact 3 / Priorität 4. | bmsptest | 09.10.2026 | RITM0043106 (Screenshots) | 1 |
| B23 | `sys_audit` ist für `mosca.rest` nicht lesbar (HTTP 403). | bmsptest, bmsp | 09.10.2026 | `servicenow_time_report.py` | 2 Instanzen |

## Deutungen (nicht als Befund verwenden)

- Zu B4/B5: Der Geltungsbereich der Ausnahme entscheidet über den Abschluss,
  nicht ihr Typ. Grundlage ist je ein Fall; Datum, CVE und Asset unterscheiden
  sich.
- Zu B10/B11: Entweder summiert ServiceNow die Einträge nicht in das Feld,
  oder `mosca.rest` darf es nicht lesen. Prüfbar im Formular eines SCTASK mit
  Buchung.
- Zu B20/B21: `bmsptest` ist bei der Gruppenzuordnung kein exakter Klon von
  `bmsp`.

## Nicht belegt oder offen

- Automatischer Wechsel des RITM auf „Work in Progress“ bei Übernahme des
  SCTASK (Kap. 4.3.1): nicht beobachtet; der Behebungs-SCTASK ging bei
  RITM0043106 direkt von Open auf Closed Complete. Test ausstehend.
- T1: Schließen nach dem Wiederöffnen ohne neue Buchung.
- T2: Prüf-SCTASK schließen, während der Behebungs-SCTASK wieder offen ist
  (klärt den Auslöser in B17).
- T3: Prüf-SCTASK auf Closed Incomplete setzen.
- Regel „Administratoren können das RITM nicht schließen“ (Kap. 4.3.2): mit
  einem Administratorkonto nicht prüfbar; mit einem Standardkonto testen oder
  als „Konzept, nicht getestet“ führen.
- Abschlussverhalten von Mondoo bei mehreren Assets, teils behoben, teils
  ausgenommen: nicht beobachtet.
- Wirkung einer Ausnahme „1 CVE“ auf künftige Assets: Annahme aus der
  Bedeutung des Bereichs, nicht beobachtet.
- Variante B (Hinweis statt Abschluss) und der Fix zu B3 sind auf keiner
  Instanz getestet.
