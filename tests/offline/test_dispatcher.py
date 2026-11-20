from backend.dispatcher import execute
import pytest


def test_allowed_tool():
    result = execute("read_mock_s3")
    assert result is not None


def test_reject_unknown_tool():
    with pytest.raises(ValueError):
        execute("shell")
