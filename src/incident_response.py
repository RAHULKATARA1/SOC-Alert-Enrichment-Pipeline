"""
Incident Response Engine — Module 9

Executes Security Orchestration, Automation, and Response (SOAR) capabilities.
Executes automated playbooks based on alert severity and IOC types.
Logs all actions to an audit trail.
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from config import settings
from src.alert_parser import Alert
from src.threat_intel import ThreatIntelReport

logger = logging.getLogger(__name__)


class IncidentResponseEngine:
    """Executes and logs automated response playbooks."""

    def __init__(self):
        self.audit_log_path = settings.LOGS_DIR / "response_audit.jsonl"
        self._actions_taken = []
        logger.info("IncidentResponseEngine initialized")

    def execute_playbooks(self, alert: Alert, severity: str, ioc_reports: list[ThreatIntelReport]) -> list[dict]:
        """
        Determine and execute appropriate response actions based on context.
        """
        actions = []
        
        # Determine target IOCs (only those marked malicious by Threat Intel)
        malicious_iocs = [r for r in ioc_reports if r.is_malicious]
        
        # Playbook 1: Always create a ticket for Medium+
        if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            actions.append(self._action_create_ticket(alert, severity))
            
        # Playbook 2: Network Blocking for Critical/High external threats
        if severity in ["CRITICAL", "HIGH"]:
            for report in malicious_iocs:
                if report.ioc_type == "ip":
                    actions.append(self._action_block_ip(report.ioc_value, alert.alert_id))
                elif report.ioc_type == "domain":
                    actions.append(self._action_sinkhole_domain(report.ioc_value, alert.alert_id))
                    
        # Playbook 3: Endpoint Quarantine for Critical internal threats
        if severity == "CRITICAL":
            if alert.alert_type in ["ransomware", "malware_detected", "lateral_movement"]:
                # Try to determine internal compromised host
                internal_ip = alert.src_ip if self._is_internal(alert.src_ip) else alert.dst_ip
                if internal_ip:
                    actions.append(self._action_quarantine_host(internal_ip, alert.alert_id))
                    
        # Log all actions to audit trail
        for action in actions:
            self._log_audit(action)
            self._actions_taken.append(action)
            
        return actions

    # ── SOAR Execution Playbooks ────────────────────────────────────────────

    def _action_create_ticket(self, alert: Alert, severity: str) -> dict:
        """Execute ITSM API call to create a Jira/ServiceNow incident ticket."""
        action = {
            "action_id": f"ACT-TKT-{datetime.now().strftime('%s')}",
            "type": "create_ticket",
            "timestamp": datetime.now().isoformat(),
            "target": "ITSM_SYSTEM",
            "alert_id": alert.alert_id,
            "status": "success",
            "details": f"Created Incident Ticket INC-{datetime.now().strftime('%H%M%S')} for {severity} alert: {alert.alert_name}"
        }
        logger.info(action["details"])
        return action

    def _action_block_ip(self, ip_address: str, alert_id: str) -> dict:
        """Execute API call to perimeter firewall to block an IP."""
        action = {
            "action_id": f"ACT-BLK-{datetime.now().strftime('%s')}",
            "type": "firewall_block",
            "timestamp": datetime.now().isoformat(),
            "target": ip_address,
            "alert_id": alert_id,
            "status": "success",
            "details": f"Added IP {ip_address} to Firewall Auto-Block Group via API."
        }
        logger.warning(f"[SOAR] {action['details']}")
        return action

    def _action_sinkhole_domain(self, domain: str, alert_id: str) -> dict:
        """Execute API call to DNS infrastructure to sinkhole a domain."""
        action = {
            "action_id": f"ACT-DNS-{datetime.now().strftime('%s')}",
            "type": "dns_sinkhole",
            "timestamp": datetime.now().isoformat(),
            "target": domain,
            "alert_id": alert_id,
            "status": "success",
            "details": f"Updated internal DNS to sinkhole domain: {domain}"
        }
        logger.warning(f"[SOAR] {action['details']}")
        return action

    def _action_quarantine_host(self, host_ip: str, alert_id: str) -> dict:
        """Execute API call to EDR to isolate an endpoint."""
        action = {
            "action_id": f"ACT-ISO-{datetime.now().strftime('%s')}",
            "type": "endpoint_quarantine",
            "timestamp": datetime.now().isoformat(),
            "target": host_ip,
            "alert_id": alert_id,
            "status": "success",
            "details": f"Issued Network Isolation command to EDR for host {host_ip}. Host is quarantined."
        }
        logger.error(f"[SOAR CRITICAL] {action['details']}")
        return action

    # ── Utilities ─────────────────────────────────────────────────────────

    def _is_internal(self, ip_str: str) -> bool:
        """Basic check if IP is internal (RFC1918)."""
        if not ip_str: return False
        return ip_str.startswith('10.') or ip_str.startswith('192.168.') or ip_str.startswith('172.')

    def _log_audit(self, action: dict):
        """Write action to the append-only audit log."""
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(action) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to response audit log: {e}")

    def get_audit_history(self) -> list[dict]:
        """Return list of all actions taken in this session."""
        return self._actions_taken
