from backend.approvals import (
    approve,
    reject
)
from backend.session_store import create_session
from backend.proposals import create_proposal
from backend.database import get_connection, initialize_db

import pytest


def test_approve():
    session_id = create_session("admin")

    proposal = {
        "status": "PENDING"
    }

    result = approve(
        proposal,
        session_id
    )

    assert result["status"] == "APPROVED"


def test_reject():
    session_id = create_session("admin")

    proposal = {
        "status": "PENDING"
    }

    result = reject(
        proposal,
        session_id
    )

    assert result["status"] == "REJECTED"


def test_invalid_transition():
    session_id = create_session("admin")

    proposal = {
        "status": "APPROVED"
    }

    with pytest.raises(ValueError):
        approve(
            proposal,
            session_id
        )


def test_invalid_session_rejected():
    proposal = {
        "status": "PENDING"
    }

    with pytest.raises(PermissionError):
        approve(
            proposal,
            "fake-unauthenticated-session"
        )


def test_sqlite_approval_integration():
    initialize_db()
    session_id = create_session("admin")

    # 1. Create proposal in sqlite
    proposal = create_proposal(
        "F-SQLITE-001",
        "sg-001",
        "Restrict SSH to trusted CIDR"
    )
    proposal_id = proposal["proposal_id"]
    assert proposal["status"] == "PENDING"

    # 2. Approve proposal with valid session
    approved = approve(proposal, session_id)
    assert approved["status"] == "APPROVED"

    # 3. Verify proposal state updated in sqlite
    conn = get_connection()
    row = conn.execute("SELECT status FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "APPROVED"
