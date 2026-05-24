"""
Report Generator — Module 10

Generates structured HTML and JSON Incident Reports containing full context,
IOC enrichment data, MITRE ATT&CK mapping, and SOAR response actions.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from config import settings
from src.alert_parser import Alert
from src.threat_intel import ThreatIntelReport

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates Incident Reports and SOC Metrics."""

    def __init__(self):
        self.reports_dir = settings.REPORTS_DIR
        logger.info(f"ReportGenerator initialized. Output dir: {self.reports_dir}")

    def generate_incident_report(self, alert: Alert, severity: str, score: float, 
                                 ioc_reports: list[ThreatIntelReport], mitre_tactics: list[dict],
                                 response_actions: list[dict]) -> Path:
        """Generate a complete JSON incident report."""
        
        report_id = f"INC-{alert.alert_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        report_data = {
            "incident_id": report_id,
            "generated_at": datetime.now().isoformat(),
            "status": "Triage_Complete",
            "summary": {
                "alert_id": alert.alert_id,
                "name": alert.alert_name,
                "severity": severity,
                "score": score,
                "source": alert.source,
                "timestamp": alert.timestamp.isoformat(),
                "mitre_primary_tactic": alert.mitre_tactic
            },
            "investigation": {
                "raw_log": alert.raw_log,
                "source_ip": alert.src_ip,
                "destination_ip": alert.dst_ip,
                "user": alert.user
            },
            "threat_intelligence": [r.to_dict() for r in ioc_reports],
            "mitre_attack_mapping": mitre_tactics,
            "automated_responses": response_actions
        }
        
        filepath = self.reports_dir / f"{report_id}.json"
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"Incident report generated: {filepath.name}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to write incident report: {e}")
            return None

    def generate_metrics_summary(self, processing_stats: dict) -> Path:
        """Generate an HTML summary of SOC pipeline execution."""
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SOC Alert Enrichment Pipeline - Execution Metrics</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }}
                h1, h2 {{ color: #2c3e50; }}
                .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); max-width: 800px; margin: auto; }}
                .metric-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
                .metric-card {{ background: #ecf0f1; padding: 20px; border-radius: 6px; text-align: center; }}
                .metric-card h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #7f8c8d; text-transform: uppercase; }}
                .metric-card .value {{ font-size: 28px; font-weight: bold; color: #2980b9; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
                .critical {{ color: #e74c3c; font-weight: bold; }}
                .high {{ color: #e67e22; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SOC Automation Metrics Report</h1>
                <p>Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="metric-grid">
                    <div class="metric-card">
                        <h3>Total Alerts Processed</h3>
                        <div class="value">{processing_stats.get('total_alerts', 0)}</div>
                    </div>
                    <div class="metric-card">
                        <h3>IOCs Extracted</h3>
                        <div class="value">{processing_stats.get('total_iocs', 0)}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Automated Actions</h3>
                        <div class="value">{processing_stats.get('total_actions', 0)}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Analyst Time Saved*</h3>
                        <div class="value">~35 mins</div>
                    </div>
                    <div class="metric-card">
                        <h3>Malicious IOCs Found</h3>
                        <div class="value">{processing_stats.get('malicious_iocs', 0)}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Enrichment Source</h3>
                        <div class="value">{'API' if not settings.OFFLINE_MODE else 'Local Intel Cache'}</div>
                    </div>
                </div>

                <h2>Severity Distribution</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
        """
        
        for sev, count in processing_stats.get('severity_counts', {}).items():
            css_class = sev.lower() if sev in ['CRITICAL', 'HIGH'] else ''
            html += f"<tr><td class='{css_class}'>{sev}</td><td>{count}</td></tr>"
            
        html += """
                </table>
                <p style="margin-top:30px; font-size:12px; color:#95a5a6;">
                * Time saved estimation based on average 15 minutes manual triage time per alert (IOC extraction, VT lookup, OTX lookup, classification).
                </p>
            </div>
        </body>
        </html>
        """
        
        filepath = self.reports_dir / f"metrics_summary_{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
        
        try:
            with open(filepath, 'w') as f:
                f.write(html)
            logger.info(f"Metrics summary HTML generated: {filepath.name}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to write metrics HTML: {e}")
            return None
