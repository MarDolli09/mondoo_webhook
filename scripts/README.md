# Hilfsskripte

Einmalige Prüfskripte gegen die Mondoo GraphQL-API. Sie gehören nicht zur
Anwendung und werden von ihr nicht importiert; sie brauchen nur die
Standardbibliothek und den API-Key in der Umgebung.

| Skript | Zweck |
|---|---|
| `verify_scores.py` | Führt die Abfrage aus `app/services/mondoo/queries.py` gegen die echte API aus und zeigt, welche Werte im Ticket landen würden. |
| `introspect_next.py` | Introspektion: welche weiteren Daten die API liefern kann (Space-Name, Benutzer zur `createdBy`-MRN, `mrns`-Sammelfilter, EPSS, Risk-Faktoren). |
| `verify_open_findings.py` | Zählt je Asset-Scope die Knoten eines Findings für die Zustände OPEN, CLOSED, EXCEPTION und ALL. Grundlage der geplanten Prüfung bei `TYPE_CLOSED`, ob noch offene, nicht ausgenommene Findings bestehen. |

## Ausführen

Lokal, mit dem Key aus dem Key Vault:

```
MONDOO_API_KEY='<key>' python3 scripts/verify_scores.py
```

In Kudu SSH (`https://<app>.scm.azurewebsites.net/webssh/host`) ist der Key
bereits als Umgebungsvariable gesetzt, die Skripte liegen dort aber nicht,
weil Oryx nur `output.tar.zst` ablegt. Inhalt per Heredoc anlegen und starten:

```
cd /tmp && cat > verify_scores.py <<'PY'
<Inhalt einfügen>
PY
python3 verify_scores.py
```

Die MRNs am Kopf der Skripte zeigen auf den Space `eu-elastic-hodgkin-413342`
und sind bei Bedarf anzupassen.
