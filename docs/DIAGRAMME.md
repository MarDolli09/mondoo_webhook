# Diagramme

Alle Diagramme liegen unter `docs/` als bearbeitbare draw.io-Datei (`.drawio`)
und als PNG. Stand 02.10.2026, Code-Stand `dbf30e3`. Nach Änderungen am Code
die betroffenen Diagramme prüfen und das PNG aus draw.io neu exportieren.
Quellenangabe in der Arbeit: eigene Darstellung.

| Nr. | Abbildung | Datei | Zeigt | Passt zu |
|---|---|---|---|---|
| 1 | Systemkontext der Mondoo-ServiceNow-Middleware | `system-context` | System, Personen und Nachbarsysteme mit Protokollen | Einleitung, Anforderungen |
| 2 | Schichtenmodell | `layer-model` | Erfassung, Vermittlung und Ziel; die Middleware nach Code-Paketen | Architektur |
| 3 | Verteilungsdiagramm | `deployment` | Knoten, Laufzeitumgebungen, Artefakte und Kommunikationspfade in Azure | Architektur, Betrieb |
| 4 | Domänenmodell | `domain-model` | Fachbegriffe aus Mondoo, Middleware und ServiceNow | Analyse, Datenmodell |
| 5 | Klassendiagramm | `class-diagram` | 51 Klassen nach Paketen, Ports und ihre Implementierungen | Entwurf |
| 6 | Sequenzdiagramm | `sequence-diagram` | Ablauf einer Zustellung samt Azure-Ressourcen | Entwurf, Ablauf |
| 7 | Aktivitätsdiagramm mit Fehlerbehandlung | `activity-errors` | Entscheidungen, Antworten 401, 422 und 502, Alarmierung | Entwurf, Robustheit |
| 8 | Zustandsdiagramm eines Tickets | `ticket-states` | RITM-Status und die auslösenden Mondoo-Ereignisse | Synchronisation |
| 9 | Prioritätskaskade | `priority-cascade` | Stufen von Mondoo Risk über CVSS und Titel-Tag bis Default | Fachlogik |
| 10 | Datenabbildung | `data-mapping` | Felder von Mondoo über den normalisierten Case nach ServiceNow | Datenmodell, Integration |
| 11 | Sicherheitsarchitektur | `security` | Vertrauensgrenzen und Schutzmaßnahmen je Datenfluss | Sicherheit |

Notation:

- **UML:** Verteilungs-, Klassen-, Sequenz-, Aktivitäts- und
  Zustandsdiagramm sowie das Domänenmodell.
- **Systemkontext:** angelehnt an C4, Ebene 1.
- **Weitere:** Schichtenmodell und Prioritätskaskade folgen den eigenen
  Entwürfen.
- **Farben einheitlich:** Mondoo violett, Azure hellblau, ServiceNow grün,
  Notizen gelb.
