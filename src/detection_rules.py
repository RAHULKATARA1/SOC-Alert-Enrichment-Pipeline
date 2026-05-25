"""
Detection Rules Engine — Module 2

Executes SIEM (Splunk) correlation rules by analyzing raw logs (e.g. from firewall/proxy)
and generating Alerts based on rule matches.
"""

import csv
import logging
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from dateutil.parser import parse as parse_date
from src.alert_parser import Alert

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Evaluates raw logs against predefined detection rules to generate alerts.
    Executes SPL (Splunk Processing Language) scheduled searches.
    """

    def __init__(self):
        self.rules = [
            self._rule_brute_force,
            self._rule_malicious_attachment,
            self._rule_c2_beaconing,
            self._rule_data_exfiltration,
            self._rule_lateral_movement_rdp,
        ]
        self.alert_counter = 100
        logger.info(f"DetectionEngine initialized with {len(self.rules)} rules")

    def analyze_logs(self, log_file: Path | str) -> list[Alert]:
        """Read logs from CSV and run all detection rules against them."""
        log_file = Path(log_file)
        if not log_file.exists():
            logger.error(f"Log file not found: {log_file}")
            return []

        logs = []
        try:
            with open(log_file, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    logs.append(row)
        except Exception as e:
            logger.error(f"Error reading logs: {e}")
            return []

        logger.info(f"Loaded {len(logs)} log events for analysis")

        generated_alerts = []
        for rule in self.rules:
            alerts = rule(logs)
            generated_alerts.extend(alerts)

        logger.info(f"Detection engine generated {len(generated_alerts)} alerts")
        return generated_alerts

    def _generate_alert_id(self) -> str:
        """Generate a unique sequential alert ID."""
        self.alert_counter += 1
        return f"DETECT-{datetime.now().strftime('%Y%m')}-{self.alert_counter:04d}"

    # ── Detection Rules (SPL Equivalents) ─────────────────────────────────

    def _rule_brute_force(self, logs: list[dict]) -> list[Alert]:
        """
        SPL Equivalent:
        index=firewall action=deny dest_port=22
        | stats count by src_ip, dst_ip
        | where count > 20
        """
        alerts = []
        # Count denied SSH connections per source IP
        ssh_denies = defaultdict(list)

        for log in logs:
            if log.get("action") == "deny" and log.get("dst_port") == "22":
                src = log.get("src_ip")
                if src:
                    ssh_denies[src].append(log)

        for src_ip, events in ssh_denies.items():
            if len(events) >= 20:
                target_ip = events[0].get("dst_ip")
                timestamp = events[-1].get("timestamp")

                alert = Alert(
                    alert_id=self._generate_alert_id(),
                    timestamp=parse_date(timestamp),
                    alert_name="High Volume SSH Brute Force Detected",
                    alert_type="brute_force",
                    source="firewall",
                    severity_hint="high",
                    raw_log=f"Detected {len(events)} failed SSH login attempts from {src_ip} targeting {target_ip} within monitored timeframe.",
                    src_ip=src_ip,
                    dst_ip=target_ip,
                    mitre_tactic="Credential Access",
                )
                alerts.append(alert)
        return alerts

    def _rule_malicious_attachment(self, logs: list[dict]) -> list[Alert]:
        """
        SPL Equivalent:
        index=email attachment="*.exe" OR attachment="*.vbs" OR attachment="*.docm"
        """
        alerts = []
        suspicious_exts = [".exe", ".vbs", ".docm", ".bat", ".ps1"]

        for log in logs:
            if log.get("event_type") == "email":
                attachment = log.get("attachment", "").lower()
                if any(attachment.endswith(ext) for ext in suspicious_exts):
                    alert = Alert(
                        alert_id=self._generate_alert_id(),
                        timestamp=parse_date(log["timestamp"]),
                        alert_name="Suspicious Email Attachment Detected",
                        alert_type="phishing_email",
                        source="email_gateway",
                        severity_hint="high",
                        raw_log=f"Email delivered containing potentially malicious executable attachment '{attachment}'. Source IP: {log.get('src_ip')}",
                        src_ip=log.get("src_ip"),
                        dst_ip=log.get("dst_ip"),
                        mitre_tactic="Initial Access",
                    )
                    alerts.append(alert)
        return alerts

    def _rule_c2_beaconing(self, logs: list[dict]) -> list[Alert]:
        """
        SPL Equivalent:
        index=proxy url="*beacon*" OR dest_port=443
        | stats count by src_ip, dst_ip, url
        | where count >= 3
        """
        alerts = []
        beacons = defaultdict(list)

        for log in logs:
            if log.get("event_type") == "web" and log.get("dst_port") == "443":
                url = log.get("url", "")
                if "beacon" in url.lower() or "callback" in url.lower():
                    src_dst = (log.get("src_ip"), log.get("dst_ip"))
                    beacons[src_dst].append(log)

        for (src_ip, dst_ip), events in beacons.items():
            if len(events) >= 3:
                url = events[0].get("url")
                timestamp = events[-1].get("timestamp")

                alert = Alert(
                    alert_id=self._generate_alert_id(),
                    timestamp=parse_date(timestamp),
                    alert_name="Suspected C2 Beaconing Activity",
                    alert_type="c2_communication",
                    source="proxy",
                    severity_hint="critical",
                    raw_log=f"Host {src_ip} exhibits repetitive HTTPS beaconing behavior to {dst_ip}. URL pattern: {url}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    mitre_tactic="Command and Control",
                )
                alerts.append(alert)
        return alerts

    def _rule_data_exfiltration(self, logs: list[dict]) -> list[Alert]:
        """
        SPL Equivalent:
        index=proxy OR index=firewall action=allow
        | where bytes > 1000000000  (> 1GB)
        """
        alerts = []
        for log in logs:
            bytes_transferred = int(log.get("bytes", 0))
            if log.get("action") == "allow" and bytes_transferred > 1000000000:  # 1 GB
                alert = Alert(
                    alert_id=self._generate_alert_id(),
                    timestamp=parse_date(log["timestamp"]),
                    alert_name="Large Data Transfer - Potential Exfiltration",
                    alert_type="data_exfiltration",
                    source="proxy",
                    severity_hint="high",
                    raw_log=f"Massive outbound data transfer detected. Host {log.get('src_ip')} transferred {bytes_transferred / 1000000000:.2f} GB to {log.get('dst_ip')}. Destination URL: {log.get('url', 'N/A')}",
                    src_ip=log.get("src_ip"),
                    dst_ip=log.get("dst_ip"),
                    mitre_tactic="Exfiltration",
                )
                alerts.append(alert)
        return alerts

    def _rule_lateral_movement_rdp(self, logs: list[dict]) -> list[Alert]:
        """
        SPL Equivalent:
        index=firewall dest_port=3389 action=allow
        | stats dc(dst_ip) as target_count by src_ip
        | where target_count >= 3
        """
        alerts = []
        rdp_connections = defaultdict(set)
        timestamps = defaultdict(list)

        for log in logs:
            if log.get("dst_port") == "3389" and log.get("action") == "allow":
                src = log.get("src_ip")
                dst = log.get("dst_ip")
                ts = log.get("timestamp")
                if src and dst:
                    rdp_connections[src].add(dst)
                    if ts:
                        timestamps[src].append(ts)

        for src_ip, targets in rdp_connections.items():
            if len(targets) >= 3:
                ts_list = timestamps.get(src_ip, [])
                if ts_list:
                    latest_ts = parse_date(max(ts_list))
                else:
                    latest_ts = datetime.now()

                alert = Alert(
                    alert_id=self._generate_alert_id(),
                    timestamp=latest_ts,
                    alert_name="Lateral Movement via RDP Scanning",
                    alert_type="lateral_movement",
                    source="siem_correlation",
                    severity_hint="high",
                    raw_log=f"Host {src_ip} made successful RDP connections to {len(targets)} different internal hosts: {', '.join(list(targets)[:5])}",
                    src_ip=src_ip,
                    mitre_tactic="Lateral Movement",
                )
                alerts.append(alert)
        return alerts
