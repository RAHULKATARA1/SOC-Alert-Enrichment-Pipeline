from datetime import datetime
from src.severity_scorer import SeverityScorer
from src.alert_parser import Alert
from src.threat_intel import ThreatIntelReport


def test_severity_calculation():
    scorer = SeverityScorer()
    alert = Alert(
        alert_id="TEST-1",
        timestamp=datetime.now(),
        alert_name="Test",
        severity_hint="high",
        raw_log="Log",
        src_ip="",
        dst_ip="",
        alert_type="malware_detected",
        source="edr",
    )

    sev, score, _ = scorer.calculate_severity(alert, [])
    assert 0 <= score <= 100
    assert sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_malicious_ioc_increases_severity():
    scorer = SeverityScorer()
    alert = Alert(
        alert_id="TEST-1",
        timestamp=datetime.now(),
        alert_name="Test",
        severity_hint="low",
        raw_log="Log",
        src_ip="",
        dst_ip="",
        alert_type="general",
        source="default",
    )

    # Baseline
    sev_base, score_base, _ = scorer.calculate_severity(alert, [])

    # With highly malicious IOC
    report = ThreatIntelReport(
        ioc_value="1.1.1.1",
        ioc_type="ip",
        vt_malicious=50,
        vt_total=90,
        is_malicious=True,
    )
    sev_high, score_high, _ = scorer.calculate_severity(alert, [report])

    assert score_high > score_base
