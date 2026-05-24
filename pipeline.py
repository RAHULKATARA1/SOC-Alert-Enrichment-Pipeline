#!/usr/bin/env python3
"""
SOC Alert Enrichment Pipeline — Main Orchestrator

Ties together all 10 modules:
1. Log Collection & 2. SIEM Detection (if starting from raw logs)
3. Alert Parsing
4. IOC Extraction
5. Threat Intelligence Enrichment
6. Severity Scoring
7. Slack Notification
9. Incident Response
10. Reporting

Usage:
    python pipeline.py --offline
    python pipeline.py --input data/sample_alerts.json
    python pipeline.py --logs data/sample_logs.csv
"""

import argparse
import logging
import sys
from pathlib import Path

from config import settings
from src.alert_parser import AlertParser
from src.ioc_extractor import IOCExtractor
from src.threat_intel import ThreatIntelEnricher
from src.severity_scorer import SeverityScorer
from src.slack_notifier import SlackNotifier
from src.incident_response import IncidentResponseEngine
from src.report_generator import ReportGenerator
from src.mitre_mapper import MitreMapper
from src.detection_rules import DetectionEngine

# Setup Logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT,
    datefmt=settings.LOG_DATE_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(settings.LOGS_DIR / "pipeline.log")
    ]
)
logger = logging.getLogger("SOC-Pipeline")


class SOCPipeline:
    def __init__(self):
        logger.info("Initializing SOC Alert Enrichment Pipeline...")
        self.alert_parser = AlertParser()
        self.ioc_extractor = IOCExtractor(extract_private_ips=False)
        self.threat_intel = ThreatIntelEnricher()
        self.severity_scorer = SeverityScorer()
        self.slack_notifier = SlackNotifier()
        self.incident_response = IncidentResponseEngine()
        self.report_generator = ReportGenerator()
        self.mitre_mapper = MitreMapper()
        self.detection_engine = DetectionEngine()
        
        # Metrics state
        self.stats = {
            "total_alerts": 0,
            "total_iocs": 0,
            "malicious_iocs": 0,
            "total_actions": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        }

    def process_raw_logs(self, logs_path: str):
        """Phase 1 & 2: Process raw logs through Detection Engine to generate alerts."""
        logger.info(f"Processing raw logs from {logs_path}")
        alerts = self.detection_engine.analyze_logs(logs_path)
        if not alerts:
            logger.warning("No alerts generated from logs.")
            return
            
        self._process_alerts(alerts)

    def process_alert_file(self, alerts_path: str):
        """Phase 3: Parse structured alerts from JSON."""
        logger.info(f"Processing structured alerts from {alerts_path}")
        alerts = self.alert_parser.parse_file(alerts_path)
        if not alerts:
            logger.warning("No valid alerts parsed.")
            return
            
        self._process_alerts(alerts)

    def _process_alerts(self, alerts: list):
        """Run the core pipeline on a list of Alerts."""
        self.stats["total_alerts"] += len(alerts)
        
        for idx, alert in enumerate(alerts, 1):
            logger.info(f"\n{'='*80}\nProcessing Alert {idx}/{len(alerts)}: {alert.alert_id} - {alert.alert_name}\n{'='*80}")
            
            # Phase 4: IOC Extraction
            iocs = self.ioc_extractor.extract_from_alert(alert)
            self.stats["total_iocs"] += len(iocs)
            
            # Phase 5: Threat Intel Enrichment
            ioc_reports_dict = self.threat_intel.enrich_batch(iocs)
            ioc_reports_list = list(ioc_reports_dict.values())
            
            malicious_count = sum(1 for r in ioc_reports_list if r.is_malicious)
            self.stats["malicious_iocs"] += malicious_count
            
            # Phase 6: Severity Scoring
            severity, score, breakdown = self.severity_scorer.calculate_severity(alert, ioc_reports_list)
            self.stats["severity_counts"][severity] += 1
            action_rec = self.severity_scorer.get_recommended_action(severity)
            
            # MITRE Mapping
            extracted_types = {ioc.ioc_type for ioc in iocs}
            mitre_tactics = self.mitre_mapper.map_alert(alert, extracted_types)
            if not alert.mitre_tactic and mitre_tactics:
                alert.mitre_tactic = mitre_tactics[0].get("tactic")
            
            # Phase 9: Automated Incident Response (SOAR)
            response_actions = self.incident_response.execute_playbooks(alert, severity, ioc_reports_list)
            self.stats["total_actions"] += len(response_actions)
            
            # Phase 7: Slack Notification
            self.slack_notifier.notify(alert, severity, score, action_rec, ioc_reports_list)
            
            # Phase 10: Generate Individual Report
            self.report_generator.generate_incident_report(
                alert, severity, score, ioc_reports_list, mitre_tactics, response_actions
            )
            
        # End of pipeline run — generate summary
        self.report_generator.generate_metrics_summary(self.stats)
        logger.info("\nPipeline execution completed successfully.")
        logger.info(f"Summary generated in: {settings.REPORTS_DIR.absolute()}")


def main():
    parser = argparse.ArgumentParser(description="SOC Alert Enrichment Pipeline")
    parser.add_argument("--offline", action="store_true", help="Run the pipeline in offline mode using the local threat intel cache.")
    parser.add_argument("--input", type=str, help="Path to JSON file containing structured alerts.")
    parser.add_argument("--logs", type=str, help="Path to CSV file containing raw firewall/proxy logs.")
    
    args = parser.parse_args()
    
    pipeline = SOCPipeline()
    
    if args.offline:
        logger.info("Starting in OFFLINE mode. Utilizing Local Threat Intel Cache...")
        # Override to offline mode regardless of .env
        settings.OFFLINE_MODE = True
        pipeline.threat_intel.offline_mode = True
        pipeline.slack_notifier.offline_mode = True
        
        sample_path = settings.DATA_DIR / "sample_alerts.json"
        pipeline.process_alert_file(sample_path)
        
    elif args.input:
        pipeline.process_alert_file(args.input)
        
    elif args.logs:
        pipeline.process_raw_logs(args.logs)
        
    else:
        parser.print_help()
        print("\nExample usage:")
        print("  python pipeline.py --offline")

if __name__ == "__main__":
    main()
