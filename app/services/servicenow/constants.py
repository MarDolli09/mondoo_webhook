"""Feste Werte der ServiceNow-Anbindung: Organisationsdaten, Zustaende, Feldgrenzen,
Tabellen und Pfade.
"""

__all__ = [
    "AUTOMATED_CREATOR_LABEL",
    "CATALOG_TASK_LOOKUP_DELAYS",
    "CATALOG_TASK_WORKFLOW_TITLE_PREFIX",
    "CORRELATION_ID_MAX",
    "DEFAULT_MAX_RETRIES",
    "FIXED_WATCHERS",
    "PATH_OAUTH_TOKEN",
    "PATH_ORDER_NOW",
    "PATH_SUBMIT_ORDER",
    "PATH_TABLE",
    "PATH_TABLE_RECORD",
    "RETRYABLE_STATUS",
    "RITM_RESOLVE_DELAYS",
    "SHORT_DESCRIPTION_MAX",
    "SNOW_INTEGRATION_USER",
    "STATE_CLOSED_COMPLETE",
    "STATE_CLOSED_INCOMPLETE",
    "STATE_CLOSED_SKIPPED",
    "STATE_OPEN",
    "TABLE_CATALOG_TASK",
    "TABLE_REQUEST_ITEM",
    "TABLE_USER",
    "TERMINAL_STATES",
    "TOKEN_EXPIRY_MARGIN_SECONDS",
]

# ---------------------------------------------------------------------- #
# Organisationsdaten
# ---------------------------------------------------------------------- #
# Technischer ServiceNow-Benutzer: "Geoeffnet von" jedes neuen RITM.
SNOW_INTEGRATION_USER = "mosca.rest"

# Beobachter jedes neuen RITM; aufgeloest ueber die konfigurierten Suchfelder.
FIXED_WATCHERS: tuple[str, ...] = ("lars.siefert@mosca.com",)

# Anzeigename des Erstellers bei automatisch erzeugten Mondoo-Tickets.
AUTOMATED_CREATOR_LABEL = "Mondoo-Drift"

# ---------------------------------------------------------------------- #
# RITM-Zustaende
# ---------------------------------------------------------------------- #
STATE_OPEN = "1"
STATE_CLOSED_COMPLETE = "3"
STATE_CLOSED_INCOMPLETE = "4"
STATE_CLOSED_SKIPPED = "7"

TERMINAL_STATES = (
    STATE_CLOSED_COMPLETE,
    STATE_CLOSED_INCOMPLETE,
    STATE_CLOSED_SKIPPED,
)

# ---------------------------------------------------------------------- #
# Feldgrenzen der task-Tabelle
# ---------------------------------------------------------------------- #
SHORT_DESCRIPTION_MAX = 160
CORRELATION_ID_MAX = 100

# ---------------------------------------------------------------------- #
# HTTP
# ---------------------------------------------------------------------- #
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_RETRIES = 3

# Die Workflow-Engine erzeugt das RITM teils verzoegert. Wartezeiten in
# Sekunden zwischen den Aufloesungsversuchen.
RITM_RESOLVE_DELAYS = (0.0, 0.5, 1.0, 2.0)

# Ein Workflow legt den SCTASK mit "Mondoo Vulnerability - <Space>" an und
# bestimmt daraus die Assignment Group. Erst danach darf der Tickettitel den
# Text ersetzen. Wartezeiten in Sekunden zwischen den Suchen (maximal 10 s).
CATALOG_TASK_LOOKUP_DELAYS = (0.0, 1.0, 2.0, 3.0, 4.0)
# Nur Tasks mit dem Text des Workflows werden ueberschrieben; von Hand
# geaenderte Short Descriptions bleiben erhalten.
CATALOG_TASK_WORKFLOW_TITLE_PREFIX = "Mondoo Vulnerability"

# Sicherheitsmarge in Sekunden, damit kein OAuth-Token mitten im Vorgang ablaeuft
TOKEN_EXPIRY_MARGIN_SECONDS = 60.0

# ---------------------------------------------------------------------- #
# Tabellen und Endpunkt-Pfade
# ---------------------------------------------------------------------- #
TABLE_REQUEST_ITEM = "sc_req_item"
TABLE_CATALOG_TASK = "sc_task"
TABLE_USER = "sys_user"

PATH_TABLE = "/api/now/table/{table}"
PATH_TABLE_RECORD = "/api/now/table/{table}/{sys_id}"
PATH_OAUTH_TOKEN = "/oauth_token.do"
PATH_ORDER_NOW = "/api/sn_sc/servicecatalog/items/{item_sys_id}/order_now"
PATH_SUBMIT_ORDER = "/api/sn_sc/servicecatalog/cart/submit_order"
