from backend.approvals import (
    approve,
    reject
)
from backend.session_store import create_session

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



def test_invalid_session_rejected():
    proposal = {
        "status": "PENDING"
    }

    with pytest.raises(PermissionError):
        approve(
            proposal,
            "fake-unauthenticated-session"
        )