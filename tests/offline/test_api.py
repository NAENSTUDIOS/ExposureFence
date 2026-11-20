import json
import pytest
from backend.audit import log_event, verify_audit_hash_chain, verify_zero_mutations
from backend.auth import verify_password
from backend.session_store import create_session, valid_session, get_session, destroy_session
from backend.proposals import create_proposal
from backend.approvals import approve_by_id, reject_by_id


def test_auth_and_session_lifecycle():
    assert verify_password("ExposureFenceAdmin2026!") is True
    assert verify_password("WrongPassword123") is False

    session_id = create_session("admin")
    assert valid_session(session_id) is True

    session_data = get_session(session_id)
    assert session_data["username"] == "admin"
    assert "csrf_token" in session_data

    assert destroy_session(session_id) is True
    assert valid_session(session_id) is False


def test_audit_hash_chain_integrity():
    event1 = log_event("chain_test_event_1", {"key": "val1"})
    assert "prev_hash" in event1
    assert "event_hash" in event1

    event2 = log_event("chain_test_event_2", {"key": "val2"})
    assert event2["prev_hash"] == event1["event_hash"]

    assert verify_audit_hash_chain() is True
    assert verify_zero_mutations() is True


def test_approval_by_id_lifecycle():
    proposal = create_proposal("F-S3-001", "bucket-test-001", "Block Public Access")
    pid = proposal["proposal_id"]

    # Reject unauthenticated approval
    with pytest.raises(PermissionError):
        approve_by_id(pid, "unauthenticated_session")

    # Approve with valid session
    session_id = create_session("sec_officer")
    res = approve_by_id(pid, session_id)
    assert res["status"] == "APPROVED"
    assert res["approver"] == "sec_officer"

    # Reject invalid transition
    with pytest.raises(ValueError, match="Invalid transition"):
        approve_by_id(pid, session_id)


def test_agentcore_client_status():
    from agent.agentcore_client import AgentCoreClient
    client = AgentCoreClient()
    status = client.get_status()
    assert "configured_region" in status
    assert "harness_arn" in status
    assert "aws_credentials_present" in status
