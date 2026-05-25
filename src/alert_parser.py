"""
SOC Alert Parser — Module 3

Parses raw alert payloads from Splunk-style JSON format,
normalizes fields, validates data, and deduplicates alerts.
Returns structured Alert dataclass objects for downstream processing.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Normalized alert structure for SOC pipeline processing."""

    alert_id: str
    timestamp: datetime
    alert_name: str
    alert_type: str
    source: str
    severity_hint: str
    raw_log: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    mitre_tactic: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert Alert to dictionary for serialization."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "alert_name": self.alert_name,
            "alert_type": self.alert_type,
            "source": self.source,
            "severity_hint": self.severity_hint,
            "raw_log": self.raw_log,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user": self.user,
            "mitre_tactic": self.mitre_tactic,
            "metadata": self.metadata,
        }


class AlertParser:
    """
    Parses and normalizes raw alert data from various SIEM sources.

    Supports:
    - Splunk-style JSON alert payloads
    - Batch processing from JSON files
    - Field normalization and validation
    - Alert deduplication by alert_id
    """

    # Required fields for a valid alert
    REQUIRED_FIELDS = {"alert_id", "timestamp", "alert_name", "raw_log"}

    # Supported alert types for classification
    VALID_ALERT_TYPES = {
        "phishing_email",
        "malware_detected",
        "c2_communication",
        "brute_force",
        "data_exfiltration",
        "ransomware",
        "suspicious_powershell",
        "credential_theft",
        "lateral_movement",
        "persistence_mechanism",
        "unknown",
    }

    def __init__(self):
        self._seen_ids: set = set()
        self._parse_errors: list = []
        logger.info("AlertParser initialized")

    def parse_file(self, filepath: str | Path) -> list[Alert]:
        """
        Parse alerts from a JSON file.

        Args:
            filepath: Path to JSON file containing alert array.

        Returns:
            List of validated, deduplicated Alert objects.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            logger.error(f"Alert file not found: {filepath}")
            raise FileNotFoundError(f"Alert file not found: {filepath}")

        logger.info(f"Loading alerts from {filepath}")
        with open(filepath, "r") as f:
            raw_alerts = json.load(f)

        if not isinstance(raw_alerts, list):
            raw_alerts = [raw_alerts]

        alerts = []
        for raw in raw_alerts:
            alert = self.parse_alert(raw)
            if alert:
                alerts.append(alert)

        logger.info(
            f"Parsed {len(alerts)} valid alerts from {len(raw_alerts)} raw entries "
            f"({len(self._parse_errors)} errors, "
            f"{len(raw_alerts) - len(alerts) - len(self._parse_errors)} duplicates)"
        )
        return alerts

    def parse_alert(self, raw: dict) -> Optional[Alert]:
        """
        Parse a single raw alert dictionary into an Alert object.

        Args:
            raw: Dictionary containing raw alert data.

        Returns:
            Alert object if valid and not duplicate, None otherwise.
        """
        # ── Validate required fields ──
        missing = self.REQUIRED_FIELDS - set(raw.keys())
        if missing:
            error_msg = f"Alert missing required fields: {missing}"
            logger.warning(error_msg)
            self._parse_errors.append({"raw": raw, "error": error_msg})
            return None

        # ── Deduplicate ──
        alert_id = str(raw["alert_id"]).strip()
        if alert_id in self._seen_ids:
            logger.debug(f"Duplicate alert skipped: {alert_id}")
            return None
        self._seen_ids.add(alert_id)

        # ── Normalize timestamp ──
        timestamp = self._parse_timestamp(raw["timestamp"])
        if not timestamp:
            error_msg = (
                f"Invalid timestamp format in alert {alert_id}: {raw['timestamp']}"
            )
            logger.warning(error_msg)
            self._parse_errors.append({"raw": raw, "error": error_msg})
            return None

        # ── Normalize alert type ──
        alert_type = raw.get("alert_type", "unknown").lower().strip()
        if alert_type not in self.VALID_ALERT_TYPES:
            logger.debug(
                f"Unknown alert type '{alert_type}' for {alert_id}, setting to 'unknown'"
            )
            alert_type = "unknown"

        # ── Build Alert object ──
        alert = Alert(
            alert_id=alert_id,
            timestamp=timestamp,
            alert_name=str(raw.get("alert_name", "")).strip(),
            alert_type=alert_type,
            source=str(raw.get("source", "unknown")).lower().strip(),
            severity_hint=str(raw.get("severity_hint", "medium")).lower().strip(),
            raw_log=str(raw.get("raw_log", "")),
            src_ip=self._normalize_ip(raw.get("src_ip")),
            dst_ip=self._normalize_ip(raw.get("dst_ip")),
            user=str(raw.get("user", "")).strip() or None,
            mitre_tactic=raw.get("mitre_tactic"),
        )

        logger.debug(f"Parsed alert: {alert.alert_id} — {alert.alert_name}")
        return alert

    def _parse_timestamp(self, ts_value) -> Optional[datetime]:
        """Attempt to parse timestamp from multiple formats."""
        if isinstance(ts_value, datetime):
            return ts_value

        ts_str = str(ts_value).strip()
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%b %d %Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        return None

    def _normalize_ip(self, ip_value) -> Optional[str]:
        """Normalize and validate IP address."""
        if not ip_value:
            return None
        ip_str = str(ip_value).strip()
        # Basic validation — non-empty string with dots
        if ip_str and "." in ip_str:
            return ip_str
        return None

    def get_parse_errors(self) -> list[dict]:
        """Return list of parse errors encountered."""
        return self._parse_errors.copy()

    def reset(self):
        """Reset parser state for reprocessing."""
        self._seen_ids.clear()
        self._parse_errors.clear()
        logger.info("AlertParser state reset")
