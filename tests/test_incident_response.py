from src.incident_response import IncidentResponseEngine


def test_is_internal():
    engine = IncidentResponseEngine()

    # Valid private IPs
    assert engine._is_internal("10.0.0.1") is True
    assert engine._is_internal("192.168.1.5") is True
    assert engine._is_internal("172.16.0.5") is True
    assert engine._is_internal("172.31.255.255") is True

    # Valid public IPs
    assert engine._is_internal("8.8.8.8") is False
    # This was previously a bug: 172.8.0.1 is public but starts with 172.
    assert engine._is_internal("172.8.0.1") is False

    # Invalid strings
    assert engine._is_internal("invalid_ip") is False
    assert engine._is_internal("") is False
