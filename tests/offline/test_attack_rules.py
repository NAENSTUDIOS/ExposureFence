from backend.dispatcher import execute
import pytest


def test_unknown_tool_blocked():

    with pytest.raises(ValueError):
        execute("shell")


def test_fake_admin_tool():

    with pytest.raises(ValueError):
        execute("approve_everything")


def test_os_command_blocked():

    with pytest.raises(ValueError):
        execute("cmd")


def test_powershell_blocked():

    with pytest.raises(ValueError):
        execute("powershell")