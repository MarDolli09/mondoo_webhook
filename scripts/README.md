# Hilfsskripte

Einmalige Prüf- und Auswertungsskripte gegen die Mondoo GraphQL-API und die
ServiceNow Table API (nur lesend). Sie gehören nicht zur Anwendung und werden
von ihr nicht importiert; sie brauchen nur die Standardbibliothek und die
Zugangsdaten der App in der Umgebung.

| Skript | Zweck |
|---|---|
| `verify_scores.py` | Führt die Abfrage aus `app/services/mondoo/queries.py` gegen die echte API aus und zeigt, welche Werte im Ticket landen würden. |
| `introspect_next.py` | Introspektion: welche weiteren Daten die API liefern kann (Space-Name, Benutzer zur `createdBy`-MRN, `mrns`-Sammelfilter, EPSS, Risk-Faktoren). |
| `servicenow_time_report.py` | Liest (nur lesend, Table API) die RITMs des Katalog-Items, ihre SCTASKs, die Zeiteinträge aus `task_time_worked` und die Statuswechsel aus `sys_audit` und schreibt `ritms.csv`, `sctasks.csv`, `zeitbuchungen.csv`, `statuswechsel.csv`: Durchlaufzeiten, „Geschlossen von“, Feld `time_worked` und Summe der Einträge je SCTASK und RITM, je SCTASK Rolle, Wiedereröffnungen, letzter Abschluss und offene Zeit (`closed_at` hält nach einem Reopen den ersten Abschluss). Personen pseudonymisiert, Middleware und „system“ erkennbar, `--namen` für Klarnamen. Andere Instanz über `SNOW_INSTANCE_URL=… SNOW_CATALOG_ITEM_SYS_ID=… python3 …`. Braucht die ServiceNow-Einstellungen der App; in Kudu z. B. `python3 servicenow_time_report.py --ziel /home/data/zeiten --seit 2026-10-01`, Download über `<Kudu-Adresse>/api/vfs/data/zeiten/ritms.csv` (siehe unten), danach `rm -r /home/data/zeiten`. |
| `verify_open_findings.py` | Zählt je Asset-Scope die Knoten eines Findings für die Zustände OPEN, CLOSED, EXCEPTION und ALL. Grundlage der geplanten Prüfung bei `TYPE_CLOSED`, ob noch offene, nicht ausgenommene Findings bestehen. |

## Ausführen

Lokal, mit dem Key aus dem Key Vault:

```
MONDOO_API_KEY='<key>' python3 scripts/verify_scores.py
```

Kudu SSH öffnet man im Portal über App Service → Entwicklungstools →
Erweiterte Tools bzw. SSH. Die Kudu-Adresse hat bei dieser App einen
eindeutigen Hostnamen mit Zufallsteil und Region (`…scm.<region>-01.azurewebsites.net`);
`https://<app-name>.scm.azurewebsites.net` gibt es nicht. Die Adresse
deshalb aus der Adresszeile des geöffneten Kudu-Tabs übernehmen; Dateien
unter `/home` lädt man über `<Kudu-Adresse>/api/vfs/<Pfad unter /home>`
herunter. Dort sind die App-Einstellungen als Umgebungsvariablen gesetzt,
die Skripte liegen aber nicht, weil Oryx nur `output.tar.zst` ablegt.
Kurze Skripte per Heredoc anlegen und starten:

```
cd /tmp && cat > verify_scores.py <<'PY'
<Inhalt einfügen>
PY
python3 verify_scores.py
```

Lange Skripte schneidet die Webkonsole beim Einfügen ab. Dann lokal gzip- und
Base64-kodieren, in Teilen von rund zwölf Zeilen mit `cat >> t.b64 <<'X'`
einfügen, mit `base64 -d t.b64 | gunzip > skript.py` entpacken und mit
`md5sum` gegen den lokalen Stand prüfen.

Die MRNs am Kopf der Skripte zeigen auf den Space `eu-elastic-hodgkin-413342`
und sind bei Bedarf anzupassen.
