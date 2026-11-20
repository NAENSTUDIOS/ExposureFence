from backend.tools import (
    read_mock_s3,
    read_mock_security_groups
)

from backend.audit import log_event


ALLOWED_TOOLS = {
    "read_mock_s3": read_mock_s3,
    "read_mock_security_groups": read_mock_security_groups,
}


def execute(tool_name):
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError("Unauthorized tool")

    log_event(
        "tool_execution",
        {"tool": tool_name}
    )

    return ALLOWED_TOOLS[tool_name]()