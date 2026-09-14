# ---------------------------------------------------------------------- #
# RITM-Zustaende
# ---------------------------------------------------------------------- #
STATE_OPEN = "1"  # Standard-Status 'Offen'
STATE_CLOSED_COMPLETE = "3"
STATE_CLOSED_INCOMPLETE = "4"
STATE_CLOSED_SKIPPED = "7"

TERMINAL_STATES = (
    STATE_CLOSED_COMPLETE,
    STATE_CLOSED_INCOMPLETE,
    STATE_CLOSED_SKIPPED,
)

# ---------------------------------------------------------------------- #
# Benutzer & Beobachter
# ---------------------------------------------------------------------- #
OPENED_BY_USER = "User_Mondoo_API"
OPENED_BY_SYSTEM = "System_Mondoo_API"
FIXED_WATCHERS = ("Lars Siefert", "Alexander Haller")

# ---------------------------------------------------------------------- #
# Feldgrenzen der task-Tabelle
# ---------------------------------------------------------------------- #
SHORT_DESCRIPTION_MAX = 160
DESCRIPTION_MAX = 3900          # defensiv unter dem 4000-Zeichen-Limit
CORRELATION_ID_MAX = 100

# ---------------------------------------------------------------------- #
# HTTP
# ---------------------------------------------------------------------- #
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_RETRIES = 3

# Die Workflow-Engine erzeugt das RITM teils verzoegert. Wartezeiten in
# Sekunden zwischen den Aufloesungsversuchen.
RITM_RESOLVE_DELAYS = (0.0, 0.5, 1.0, 2.0)

# Sicherheitsmarge in Sekunden, damit kein OAuth-Token mitten im Vorgang ablaeuft
TOKEN_EXPIRY_MARGIN_SECONDS = 60.0

# ---------------------------------------------------------------------- #
# Tabellen und Endpunkt-Pfade
# ---------------------------------------------------------------------- #
TABLE_REQUEST_ITEM = "sc_req_item"
TABLE_USER_GROUP = "sys_user_group"
TABLE_USER = "sys_user"

PATH_TABLE = "/api/now/table/{table}"
PATH_TABLE_RECORD = "/api/now/table/{table}/{sys_id}"
PATH_ATTACHMENT = "/api/now/attachment/file"
PATH_OAUTH_TOKEN = "/oauth_token.do"
PATH_ORDER_NOW = "/api/sn_sc/servicecatalog/items/{item_sys_id}/order_now"
PATH_SUBMIT_ORDER = "/api/sn_sc/servicecatalog/cart/submit_order"