from backend.audit import log_event, get_audit_events


def test_audit_log():
    unique_action = "test_audit_verification_event"
    log_event(
        "security_audit_test",
        {"action": unique_action}
    )

    events = get_audit_events()
    matching = [
        e for e in events
        if e.get("event_type") == "security_audit_test"
        and e.get("details", {}).get("action") == unique_action
    ]

    assert len(matching) > 0
    latest = matching[-1]
    assert "timestamp" in latest
    assert latest["event_type"] == "security_audit_test"
    assert latest["details"]["action"] == unique_action
