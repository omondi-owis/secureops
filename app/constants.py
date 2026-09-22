"""Domain constants: roles, severities, statuses, categories, security headers.

Enumerated values are kept as plain strings (not SQL enums) so the
Alembic migrations stay portable across PostgreSQL versions.
"""
from __future__ import annotations

# --- Roles / RBAC -----------------------------------------------------
ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"
ROLE_VIEWER = "VIEWER"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)

# --- Severities -------------------------------------------------------
SEV_INFO = "INFO"
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"
SEV_CRITICAL = "CRITICAL"
SEVERITIES = (SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL)
SEVERITY_ORDER = {
    SEV_INFO: 0,
    SEV_LOW: 1,
    SEV_MEDIUM: 2,
    SEV_HIGH: 3,
    SEV_CRITICAL: 4,
}

# --- Host statuses ----------------------------------------------------
HOST_ONLINE = "ONLINE"
HOST_OFFLINE = "OFFLINE"
HOST_UNKNOWN = "UNKNOWN"
HOST_STATUSES = (HOST_ONLINE, HOST_OFFLINE, HOST_UNKNOWN)

# --- Host environments ------------------------------------------------
HOST_ENVS = ("production", "staging", "lab", "development", "dmz", "other")

# --- Event categories --------------------------------------------------
CAT_AUTH = "authentication"
CAT_NETWORK = "network"
CAT_SYSTEM = "system"
CAT_SERVICE = "service"
CAT_DETECTION = "detection"
CAT_SCAN = "scan"
CAT_SECURITY = "security"
CATEGORIES = (CAT_AUTH, CAT_NETWORK, CAT_SYSTEM, CAT_SERVICE, CAT_DETECTION, CAT_SCAN, CAT_SECURITY)

# --- Event statuses ----------------------------------------------------
EVENT_NEW = "NEW"
EVENT_ACK = "ACKNOWLEDGED"
EVENT_CLOSED = "CLOSED"
EVENT_FALSE_POSITIVE = "FALSE_POSITIVE"
EVENT_STATUSES = (EVENT_NEW, EVENT_ACK, EVENT_CLOSED, EVENT_FALSE_POSITIVE)

# --- Incident statuses -------------------------------------------------
INC_OPEN = "OPEN"
INC_INVESTIGATING = "INVESTIGATING"
INC_CONTAINED = "CONTAINED"
INC_RESOLVED = "RESOLVED"
INC_CLOSED = "CLOSED"
INC_FALSE_POSITIVE = "FALSE_POSITIVE"
INCIDENT_STATUSES = (
    INC_OPEN,
    INC_INVESTIGATING,
    INC_CONTAINED,
    INC_RESOLVED,
    INC_CLOSED,
    INC_FALSE_POSITIVE,
)

# --- Vulnerability statuses -------------------------------------------
VULN_OPEN = "OPEN"
VULN_INVESTIGATING = "INVESTIGATING"
VULN_REMEDIATED = "REMEDIATED"
VULN_ACCEPTED = "ACCEPTED_RISK"
VULN_FALSE_POSITIVE = "FALSE_POSITIVE"
VULN_STATUSES = (
    VULN_OPEN,
    VULN_INVESTIGATING,
    VULN_REMEDIATED,
    VULN_ACCEPTED,
    VULN_FALSE_POSITIVE,
)

# --- Scan states -------------------------------------------------------
SCAN_PENDING = "PENDING"
SCAN_RUNNING = "RUNNING"
SCAN_COMPLETED = "COMPLETED"
SCAN_FAILED = "FAILED"
SCAN_REJECTED = "REJECTED"
SCAN_STATUSES = (SCAN_PENDING, SCAN_RUNNING, SCAN_COMPLETED, SCAN_FAILED, SCAN_REJECTED)

# --- Scan types --------------------------------------------------------
SCAN_QUICK = "quick"
SCAN_SERVICE = "service"
SCAN_CUSTOM = "custom"
SCAN_TYPES = (SCAN_QUICK, SCAN_SERVICE, SCAN_CUSTOM)

# --- Check results -----------------------------------------------------
CHECK_PASS = "PASS"
CHECK_WARNING = "WARNING"
CHECK_FAIL = "FAIL"
CHECK_INFO = "INFO"
CHECK_RESULTS = (CHECK_PASS, CHECK_WARNING, CHECK_FAIL, CHECK_INFO)

# --- Audit resource types ----------------------------------------------
AUDIT_RESOURCES = (
    "auth", "user", "host", "scan", "log", "event", "wazuh", "incident",
    "vulnerability", "report", "settings", "system", "scanner",
)

# --- Data retention / pagination ---------------------------------------
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100

# HTTP security headers applied to every response (see main.py middleware).
SECURITY_HEADERS = {    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com "
    "https://fonts.googleapis.com; "
    "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
)


# --- Autonomy modes (spec §9) ------------------------------------------
MODE_OBSERVE = "OBSERVE"
MODE_ASSIST = "ASSIST"
MODE_CONTROLLED_AUTONOMY = "CONTROLLED_AUTONOMY"
MODE_EMERGENCY_LOCKDOWN = "EMERGENCY_LOCKDOWN"
AUTONOMY_MODES = (
    MODE_OBSERVE,
    MODE_ASSIST,
    MODE_CONTROLLED_AUTONOMY,
    MODE_EMERGENCY_LOCKDOWN,
)

# --- Tool risk levels (spec §7) ----------------------------------------
RISK_READ_ONLY = "READ_ONLY"
RISK_LOW = "LOW_RISK"
RISK_MEDIUM = "MEDIUM_RISK"
RISK_HIGH = "HIGH_RISK"
RISK_CRITICAL = "CRITICAL"
RISK_FORBIDDEN = "FORBIDDEN"
RISK_LEVELS = (RISK_READ_ONLY, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL, RISK_FORBIDDEN)

# --- AI decision action types (spec §47) --------------------------------
AI_ACTION_NONE = "NONE"
AI_ACTION_INVESTIGATE = "INVESTIGATE"
AI_ACTION_RECOMMEND = "RECOMMEND"
AI_ACTION_REQUEST_APPROVAL = "REQUEST_APPROVAL"
AI_ACTION_EXECUTE_PLAYBOOK = "EXECUTE_PLAYBOOK"
AI_ACTION_TYPES = (
    AI_ACTION_NONE,
    AI_ACTION_INVESTIGATE,
    AI_ACTION_RECOMMEND,
    AI_ACTION_REQUEST_APPROVAL,
    AI_ACTION_EXECUTE_PLAYBOOK,
)

# --- Approval statuses (spec §10/§35) -----------------------------------
APPROVAL_PENDING = "PENDING"
APPROVAL_APPROVED = "APPROVED"
APPROVAL_REJECTED = "REJECTED"
APPROVAL_EXPIRED = "EXPIRED"
APPROVAL_STATUSES = (APPROVAL_PENDING, APPROVAL_APPROVED, APPROVAL_REJECTED, APPROVAL_EXPIRED)

# --- Action execution statuses -------------------------------------------
ACTION_STATUS_PENDING = "PENDING"
ACTION_STATUS_RUNNING = "RUNNING"
ACTION_STATUS_SUCCEEDED = "SUCCEEDED"
ACTION_STATUS_FAILED = "FAILED"
ACTION_STATUS_ROLLED_BACK = "ROLLED_BACK"
ACTION_STATUS_DENIED = "DENIED"
ACTION_STATUSES = (
    ACTION_STATUS_PENDING,
    ACTION_STATUS_RUNNING,
    ACTION_STATUS_SUCCEEDED,
    ACTION_STATUS_FAILED,
    ACTION_STATUS_ROLLED_BACK,
    ACTION_STATUS_DENIED,
)

# --- AI availability states ---------------------------------------------
AI_ONLINE = "ONLINE"
AI_OFFLINE = "OFFLINE"
AI_DISABLED = "DISABLED"
AI_STATES = (AI_ONLINE, AI_OFFLINE, AI_DISABLED)

# --- Evidence classifications (spec §12) ---------------------------------
EVIDENCE_OBSERVED = "OBSERVED"
EVIDENCE_INFERRED = "INFERRED"
EVIDENCE_UNKNOWN = "UNKNOWN"
EVIDENCE_CLASSES = (EVIDENCE_OBSERVED, EVIDENCE_INFERRED, EVIDENCE_UNKNOWN)

# --- Baseline states -----------------------------------------------------
BASELINE_ACTIVE = "ACTIVE"
BASELINE_SUPERSEDED = "SUPERSEDED"
BASELINE_STATES = (BASELINE_ACTIVE, BASELINE_SUPERSEDED)

# Roles allowed to install/trigger autonomous actions (spec §10/§35).
# APPROVALS originate from the AI decision engine; human approval is the gate.
