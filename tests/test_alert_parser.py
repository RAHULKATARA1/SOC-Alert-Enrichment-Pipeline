import pytest
import json
from src.alert_parser import AlertParser


def test_parse_valid_alert(tmp_path):
    parser = AlertParser()
    data = [
        {
            "alert_id": "TEST-1",
            "timestamp": "2023-10-27T10:00:00Z",
            "alert_name": "Test Alert",
            "severity_hint": "high",
            "raw_log": "Test log",
            "src_ip": "1.1.1.1",
            "dst_ip": "8.8.8.8",
        }
    ]
    file_path = tmp_path / "alerts.json"
    file_path.write_text(json.dumps(data))

    alerts = parser.parse_file(str(file_path))
    assert len(alerts) == 1
    assert alerts[0].alert_id == "TEST-1"
    assert alerts[0].src_ip == "1.1.1.1"


def test_parse_invalid_file():
    parser = AlertParser()
    with pytest.raises(FileNotFoundError):
        parser.parse_file("nonexistent.json")
