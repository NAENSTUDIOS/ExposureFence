from backend.approvals import (
    approve,
    reject
)

import pytest


def test_approve():

    proposal = {
        "status": "PENDING"
    }

    result = approve(proposal)

    assert result["status"] == "APPROVED"


def test_reject():

    proposal = {
        "status": "PENDING"
    }

    result = reject(proposal)

    assert result["status"] == "REJECTED"


def test_invalid_transition():

    proposal = {
        "status": "APPROVED"
    }

    with pytest.raises(ValueError):
        approve(proposal)