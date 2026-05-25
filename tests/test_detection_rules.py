from src.detection_rules import DetectionEngine


def test_rule_brute_force():
    engine = DetectionEngine()
    logs = [
        {
            "action": "deny",
            "dst_port": "22",
            "src_ip": "1.1.1.1",
            "dst_ip": "10.0.0.1",
            "timestamp": "2023-10-27T10:00:00Z",
        }
        for _ in range(25)
    ]
    alerts = engine._rule_brute_force(logs)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "brute_force"
    assert alerts[0].src_ip == "1.1.1.1"


def test_rule_lateral_movement_rdp():
    engine = DetectionEngine()
    logs = []
    # 1 source, 3 different targets
    for i in range(3):
        logs.append(
            {
                "action": "allow",
                "dst_port": "3389",
                "src_ip": "10.0.0.5",
                "dst_ip": f"10.0.0.{10+i}",
                "timestamp": f"2023-10-27T10:0{i}:00Z",
            }
        )

    alerts = engine._rule_lateral_movement_rdp(logs)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "lateral_movement"
    assert alerts[0].src_ip == "10.0.0.5"
