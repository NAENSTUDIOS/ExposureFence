"""
ExposureFence Security Boundary Enforcement.
Provides runtime checks that enforce Zero-Trust containment on tool dispatching and mutations.
"""

from backend.audit import verify_zero_mutations, get_audit_events
from backend.integrity import verify_fixture_integrity


def assert_zero_mutations():
    """Asserts that no cloud resource mutation events have occurred in the audit trail."""
    if not verify_zero_mutations():
        raise AssertionError("Security Invariant Violated: Cloud mutations detected in audit trail.")
    return True


def assert_fixture_integrity(path: str):
    """Asserts that mock fixtures match expected SHA-256 digests."""
    if not verify_fixture_integrity(path):
        raise AssertionError(f"Security Invariant Violated: Fixture integrity mismatch on {path}.")
    return True


def assert_tool_allowlist(tool_name: str, allowed_tools: set):
    """Enforces that only whitelisted tools can be called."""
    if tool_name not in allowed_tools:
        raise ValueError(f"Unauthorized tool requested: {tool_name}")
    return True
