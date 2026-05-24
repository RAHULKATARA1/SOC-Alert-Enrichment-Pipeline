"""
SOC Alert Enrichment Pipeline — Central Configuration

Loads settings from environment variables with sensible defaults
for offline mode operation.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

# ─── Project Paths ───────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"

# Create directories if they don't exist
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ─── API Keys ────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ALIENVAULT_OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# ─── API Endpoints ───────────────────────────────────────────────
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ALIENVAULT_OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# ─── Rate Limiting ───────────────────────────────────────────────
VT_RATE_LIMIT = int(os.getenv("VT_RATE_LIMIT", "4"))        # requests per minute (free tier)
ABUSEIPDB_RATE_LIMIT = int(os.getenv("ABUSEIPDB_RATE_LIMIT", "60"))  # per minute
OTX_RATE_LIMIT = int(os.getenv("OTX_RATE_LIMIT", "100"))    # per minute

# ─── Severity Thresholds ─────────────────────────────────────────
SEVERITY_THRESHOLDS = {
    "CRITICAL": 80,   # score >= 80
    "HIGH": 60,       # score >= 60
    "MEDIUM": 40,     # score >= 40
    "LOW": 20,        # score >= 20
    "INFO": 0,        # score >= 0
}

# Severity scoring weights (must sum to 1.0)
SCORING_WEIGHTS = {
    "vt_detection_ratio": 0.40,
    "abuse_confidence": 0.20,
    "mitre_severity": 0.20,
    "ioc_type_risk": 0.10,
    "alert_source_priority": 0.10,
}

# ─── MITRE Tactic Severity Scores ────────────────────────────────
MITRE_TACTIC_SCORES = {
    "Impact": 95,
    "Exfiltration": 90,
    "Command and Control": 85,
    "Lateral Movement": 80,
    "Collection": 70,
    "Credential Access": 75,
    "Execution": 70,
    "Persistence": 65,
    "Privilege Escalation": 65,
    "Defense Evasion": 60,
    "Discovery": 40,
    "Initial Access": 50,
    "Reconnaissance": 30,
    "Resource Development": 20,
}

# ─── IOC Type Risk Scores ────────────────────────────────────────
IOC_TYPE_RISK = {
    "hash_sha256": 90,
    "hash_sha1": 85,
    "hash_md5": 80,
    "url": 70,
    "domain": 60,
    "ip": 50,
    "email": 30,
}

# ─── Alert Source Priority ────────────────────────────────────────
ALERT_SOURCE_PRIORITY = {
    "edr": 90,
    "firewall": 80,
    "ids": 75,
    "email_gateway": 70,
    "proxy": 60,
    "dns": 55,
    "siem_correlation": 85,
    "user_report": 40,
    "default": 50,
}

# ─── Offline Mode ──────────────────────────────────────────────────
OFFLINE_MODE = not any([VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, ALIENVAULT_OTX_API_KEY])

# ─── Logging ──────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
