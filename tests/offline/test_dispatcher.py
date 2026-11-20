from backend.dispatcher import execute, ALLOWED_TOOLS
import pytest


def test_three_tool_limit():
    assert len(ALLOWED_TOOLS) == 3
    assert "read_mock_s3" in ALLOWED_TOOLS
    assert "read_mock_security_groups" in ALLOWED_TOOLS
    assert "propose_fix" in ALLOWED_TOOLS


def test_allowed_tool_s3():
    result = execute("read_mock_s3")
    assert result is not None
    assert len(result) > 0


def test_allowed_tool_sg():
    result = execute("read_mock_security_groups")
    assert result is not None
    assert len(result) > 0


def test_allowed_tool_propose_fix():
    result = execute("propose_fix", finding_id="F-S3-001")
    assert result is not None
    assert result["finding_id"] == "F-S3-001"
    assert result["status"] == "PENDING"
    assert "proposal_id" in result


def test_propose_fix_invalid_finding():
    with pytest.raises(ValueError, match="Invalid finding ID"):
        execute("propose_fix", finding_id="INVALID-FINDING-999")


def test_reject_unknown_tool():
    with pytest.raises(ValueError, match="Unauthorized tool"):
        execute("shell")
