"""
Slack Notification Engine — Module 7

Formats and sends rich security alerts to a Slack channel via Webhooks
using Slack Block Kit formatting. Falls back to console output if no
webhook is configured (Offline Mode).
"""

import requests
import json
import logging
from config import settings
from src.alert_parser import Alert
from src.threat_intel import ThreatIntelReport

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Sends formatted alerts to Slack using Block Kit."""

    # Severity Colors (Hex)
    COLORS = {
        "CRITICAL": "#FF0000",  # Red
        "HIGH": "#FF8C00",  # Dark Orange
        "MEDIUM": "#FFD700",  # Gold
        "LOW": "#1E90FF",  # Dodger Blue
        "INFO": "#808080",  # Gray
    }

    # Emojis
    EMOJIS = {"CRITICAL": "🚨", "HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "👀", "INFO": "ℹ️"}

    def __init__(self):
        self.webhook_url = settings.SLACK_WEBHOOK_URL
        self.offline_mode = not bool(self.webhook_url)
        if self.offline_mode:
            logger.info(
                "SlackNotifier running in Console Output Mode (no webhook configured)"
            )
        else:
            logger.info("SlackNotifier initialized with Webhook")

    def notify(
        self,
        alert: Alert,
        severity_label: str,
        score: float,
        recommended_action: str,
        ioc_reports: list[ThreatIntelReport],
    ):
        """
        Send notification for a single alert.
        """
        blocks = self._build_block_kit(
            alert, severity_label, score, recommended_action, ioc_reports
        )

        payload = {
            "text": f"{self.EMOJIS.get(severity_label, '')} {severity_label} Alert: {alert.alert_name}",
            "blocks": blocks,
            "attachments": [
                {
                    "color": self.COLORS.get(severity_label, self.COLORS["INFO"]),
                    "blocks": [
                        {"type": "section", "text": {"type": "mrkdwn", "text": " "}}
                    ],  # Just for the colored bar
                }
            ],
        }

        if self.offline_mode:
            self._console_fallback(payload, severity_label)
            return True

        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if response.status_code != 200:
                logger.error(
                    f"Slack webhook failed: {response.status_code} - {response.text}"
                )
                return False
            logger.info(f"Slack notification sent for {alert.alert_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    def _build_block_kit(
        self,
        alert: Alert,
        severity: str,
        score: float,
        action: str,
        ioc_reports: list[ThreatIntelReport],
    ) -> list[dict]:
        """Build the rich Slack Block Kit message structure."""

        emoji = self.EMOJIS.get(severity, "")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {severity} SEVERITY ALERT: {alert.alert_name}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert.alert_id}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    },
                    {"type": "mrkdwn", "text": f"*Source:*\n{alert.source.upper()}"},
                    {"type": "mrkdwn", "text": f"*Score:*\n{score}/100"},
                ],
            },
            {"type": "divider"},
        ]

        # Threat Intel Summary
        malicious_iocs = [r for r in ioc_reports if r.is_malicious]
        if malicious_iocs:
            intel_text = "*Threat Intelligence Match:*\n"
            for r in malicious_iocs:
                vt_score = f"{r.vt_malicious}/{r.vt_total}" if r.vt_total > 0 else "N/A"
                malware = (
                    f" ({', '.join(r.malware_families[:2])})"
                    if r.malware_families
                    else ""
                )
                intel_text += f"• `{r.ioc_value}` - VT: {vt_score}{malware}\n"

            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": intel_text}}
            )

        # MITRE ATT&CK
        if alert.mitre_tactic:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*MITRE Tactic:*\n{alert.mitre_tactic}",
                    },
                }
            )

        # Raw Log Snippet (Truncated)
        raw_snip = (
            alert.raw_log[:200] + "..." if len(alert.raw_log) > 200 else alert.raw_log
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Raw Log Evidence:*\n```{raw_snip}```",
                },
            }
        )

        # Recommended Action
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action:*\n🚨 {action}",
                },
            }
        )

        return blocks

    def _console_fallback(self, payload: dict, severity: str):
        """Print the notification to console when webhook is not configured."""
        print(f"\n{'='*60}")
        print(f" [SLACK NOTIFICATION OUTPUT - {severity}] ")
        print(f"{'='*60}")

        for block in payload.get("blocks", []):
            if block["type"] == "header":
                print(block["text"]["text"])
            elif block["type"] == "section":
                if "fields" in block:
                    for f in block["fields"]:
                        print(f["text"].replace("*", "").replace("\n", ": "))
                elif "text" in block:
                    print(block["text"]["text"].replace("*", "").replace("```", ""))
            elif block["type"] == "divider":
                print("-" * 60)

        print(f"{'='*60}\n")
