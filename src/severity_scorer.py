"""
Severity Scoring & Classification — Module 6

Calculates an overall severity score for an alert based on multiple factors:
- Threat Intelligence (VT Detection Ratio, AbuseIPDB Confidence)
- MITRE ATT&CK Tactic Severity (e.g. Impact > Recon)
- Alert Source Priority (e.g. EDR > Proxy)
- Highest Risk IOC Type found in the alert

Maps the final score to standard SOC severities: CRITICAL, HIGH, MEDIUM, LOW, INFO.
"""

import logging
from config import settings
from src.alert_parser import Alert
from src.threat_intel import ThreatIntelReport

logger = logging.getLogger(__name__)


class SeverityScorer:
    """Calculates risk scores and classifies alert severity."""

    def __init__(self):
        self.weights = settings.SCORING_WEIGHTS
        self.thresholds = settings.SEVERITY_THRESHOLDS
        self.mitre_scores = settings.MITRE_TACTIC_SCORES
        self.ioc_risk = settings.IOC_TYPE_RISK
        self.source_priority = settings.ALERT_SOURCE_PRIORITY
        logger.info("SeverityScorer initialized")

    def calculate_severity(
        self, alert: Alert, ioc_reports: list[ThreatIntelReport]
    ) -> tuple[str, float, dict]:
        """
        Calculate overall severity score for an alert and classify it.

        Args:
            alert: The original Alert object
            ioc_reports: List of ThreatIntelReports associated with this alert

        Returns:
            Tuple of (Severity Label, Numeric Score, Score Breakdown Dictionary)
        """
        score_breakdown = {}

        # 1. Threat Intel Score: Max VT Detection Ratio (0-100)
        max_vt_ratio = 0.0
        max_abuse_score = 0.0

        for report in ioc_reports:
            if report.vt_detection_ratio > max_vt_ratio:
                max_vt_ratio = report.vt_detection_ratio
            if report.abuse_confidence_score > max_abuse_score:
                max_abuse_score = report.abuse_confidence_score

        vt_score_component = (max_vt_ratio * 100) * self.weights["vt_detection_ratio"]
        abuse_score_component = max_abuse_score * self.weights["abuse_confidence"]

        score_breakdown["vt_score"] = round(vt_score_component, 2)
        score_breakdown["abuse_score"] = round(abuse_score_component, 2)

        # 2. MITRE Tactic Severity
        tactic = alert.mitre_tactic or "Unknown"
        base_mitre_score = self.mitre_scores.get(tactic, 50)  # Default to 50 if unknown
        mitre_component = base_mitre_score * self.weights["mitre_severity"]
        score_breakdown["mitre_score"] = round(mitre_component, 2)

        # 3. IOC Type Risk
        highest_ioc_risk = 0
        for report in ioc_reports:
            risk = self.ioc_risk.get(report.ioc_type, 10)
            if risk > highest_ioc_risk:
                highest_ioc_risk = risk

        # If no IOCs found, give base risk of 10
        if highest_ioc_risk == 0:
            highest_ioc_risk = 10

        ioc_risk_component = highest_ioc_risk * self.weights["ioc_type_risk"]
        score_breakdown["ioc_type_score"] = round(ioc_risk_component, 2)

        # 4. Alert Source Priority
        source = alert.source.lower()
        source_score = self.source_priority.get(source, self.source_priority["default"])
        source_component = source_score * self.weights["alert_source_priority"]
        score_breakdown["source_score"] = round(source_component, 2)

        # Calculate Final Score (0 to 100)
        final_score = sum(score_breakdown.values())

        # If Splunk already flagged as critical, boost the score
        if (
            alert.severity_hint.lower() == "critical"
            and final_score < self.thresholds["CRITICAL"]
        ):
            final_score = min(100.0, final_score + 15.0)
            score_breakdown["hint_boost"] = 15.0

        # Ensure bounds
        final_score = max(0.0, min(100.0, final_score))

        # Determine Label
        severity_label = "INFO"
        for label, threshold in sorted(
            self.thresholds.items(), key=lambda x: x[1], reverse=True
        ):
            if final_score >= threshold:
                severity_label = label
                break

        logger.info(
            f"Alert {alert.alert_id} scored {final_score:.1f} -> {severity_label}"
        )
        return severity_label, round(final_score, 2), score_breakdown

    def get_recommended_action(self, severity_label: str) -> str:
        """Return SOC playbook recommendation based on severity."""
        actions = {
            "CRITICAL": "IMMEDIATE ESCALATION (P1). Contain affected endpoint. Trigger IR Playbook.",
            "HIGH": "Escalate to Tier 2. Investigate immediately. Block malicious IOCs.",
            "MEDIUM": "Add to triage queue. Review within 4 hours.",
            "LOW": "Log and monitor. Close if no further activity.",
            "INFO": "Informational only. No action required.",
        }
        return actions.get(severity_label.upper(), "Review alert.")
