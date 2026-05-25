"""
MITRE ATT&CK Mapper — Core Module

Maps alerts and IOCs to MITRE ATT&CK tactics, techniques, and procedures (TTPs).
Loads technique definitions from config/mitre_mappings.json.
"""

import json
import logging
from config import settings
from src.alert_parser import Alert

logger = logging.getLogger(__name__)


class MitreMapper:
    """Maps alerts to MITRE ATT&CK techniques."""

    def __init__(self):
        self.mappings_file = settings.PROJECT_ROOT / "config" / "mitre_mappings.json"
        self.techniques = {}
        self.alert_type_mapping = {}
        self.ioc_type_mapping = {}
        self._load_mappings()
        logger.info("MitreMapper initialized")

    def _load_mappings(self):
        """Load MITRE mappings from JSON config file."""
        if not self.mappings_file.exists():
            logger.error(f"MITRE mappings file not found at {self.mappings_file}")
            return

        try:
            with open(self.mappings_file, "r") as f:
                data = json.load(f)
                self.techniques = data.get("techniques", {})
                self.alert_type_mapping = data.get("alert_type_mapping", {})
                self.ioc_type_mapping = data.get("ioc_type_mapping", {})
            logger.debug(f"Loaded {len(self.techniques)} MITRE techniques")
        except Exception as e:
            logger.error(f"Failed to load MITRE mappings: {e}")

    def map_alert(self, alert: Alert, extracted_ioc_types: set = None) -> list[dict]:
        """
        Map an alert to relevant MITRE techniques based on its type and IOCs.

        Args:
            alert: The Alert object
            extracted_ioc_types: Optional set of IOC types extracted from the alert

        Returns:
            List of dictionaries containing technique details.
        """
        matched_technique_ids = set()

        # 1. Map by Alert Type
        if alert.alert_type in self.alert_type_mapping:
            matched_technique_ids.update(self.alert_type_mapping[alert.alert_type])

        # 2. Map by extracted IOC types
        if extracted_ioc_types:
            for ioc_type in extracted_ioc_types:
                if ioc_type in self.ioc_type_mapping:
                    matched_technique_ids.update(self.ioc_type_mapping[ioc_type])

        # 3. Compile full technique details
        results = []
        for tid in matched_technique_ids:
            if tid in self.techniques:
                tech = self.techniques[tid].copy()
                results.append(tech)

        # Sort by severity descending
        results.sort(key=lambda x: x.get("severity", 0), reverse=True)
        return results

    def get_tactic_for_technique(self, technique_id: str) -> str:
        """Get the primary tactic for a given technique ID."""
        tech = self.techniques.get(technique_id)
        if tech:
            return tech.get("tactic", "Unknown")
        return "Unknown"
