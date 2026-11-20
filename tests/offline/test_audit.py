from backend.audit import log_event


def test_audit_log():
    log_event(
        "test",
        {"value": "demo"}
    )

    assert True