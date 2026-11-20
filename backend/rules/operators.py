"""
ExposureFence — Deterministic Rule Operators
Implements purely deterministic condition evaluation for security rules.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.rules.exceptions import UnknownOperatorError
from backend.rules.models import OperatorType


def resolve_field_path(data: Any, path: str) -> Tuple[bool, Any]:
    """
    Resolves a dot-delimited path on a nested dictionary or object.
    Supports array indexing: e.g., 'payload.items[0].name'.
    Returns (exists: bool, value: Any).
    """
    if data is None:
        return False, None

    tokens = []
    # Tokenize path on dots and bracketed indices
    for segment in path.split("."):
        parts = re.split(r"\[(\d+)\]", segment)
        for part in parts:
            if part:
                tokens.append(int(part) if part.isdigit() else part)

    curr = data
    for token in tokens:
        if isinstance(curr, dict):
            if token in curr:
                curr = curr[token]
            else:
                return False, None
        elif isinstance(curr, (list, tuple)):
            if isinstance(token, int) and 0 <= token < len(curr):
                curr = curr[token]
            else:
                return False, None
        elif hasattr(curr, str(token)):
            curr = getattr(curr, str(token))
        else:
            return False, None

    return True, curr


def _check_cidr_in(actual: Any, expected: Any) -> bool:
    """Checks if actual IP/CIDR is contained within expected CIDR network."""
    try:
        expected_net = ipaddress.ip_network(str(expected).strip(), strict=False)
        actual_str = str(actual).strip()
        if "/" in actual_str:
            actual_net = ipaddress.ip_network(actual_str, strict=False)
            return actual_net.subnet_of(expected_net)
        else:
            actual_ip = ipaddress.ip_address(actual_str)
            return actual_ip in expected_net
    except Exception:
        return False


def _check_port_in(actual: Any, expected: Any) -> bool:
    """
    Checks if a port is in a port range or matches expected port.
    expected can be int (e.g. 22) or tuple/list/str (e.g. "20-25" or [20, 25]).
    """
    try:
        actual_port = int(actual)
        if isinstance(expected, (list, tuple)) and len(expected) == 2:
            return expected[0] <= actual_port <= expected[1]
        elif isinstance(expected, str) and "-" in expected:
            low, high = map(int, expected.split("-"))
            return low <= actual_port <= high
        else:
            return actual_port == int(expected)
    except Exception:
        return False


def _check_not_contains_open_port(ip_permissions: Any, port: Any) -> bool:
    """
    Validates that a collection of Security Group IP permissions does NOT expose
    the specified port to 0.0.0.0/0 or ::/0.
    Returns True if the port is NOT openly exposed (compliant).
    Returns False if open to the internet (violation).
    """
    if not isinstance(ip_permissions, list):
        return True

    target_port = int(port)
    open_cidrs = {"0.0.0.0/0", "::/0"}

    for perm in ip_permissions:
        if not isinstance(perm, dict):
            continue

        from_port = perm.get("FromPort") or perm.get("from_port")
        to_port = perm.get("ToPort") or perm.get("to_port")
        ip_protocol = str(perm.get("IpProtocol") or perm.get("ip_protocol") or "-1")

        # Check if port is covered
        port_covered = False
        if ip_protocol == "-1":
            port_covered = True
        elif from_port is not None and to_port is not None:
            if int(from_port) <= target_port <= int(to_port):
                port_covered = True

        if not port_covered:
            continue

        # Check if any IP ranges are 0.0.0.0/0
        ip_ranges = perm.get("IpRanges") or perm.get("ip_ranges") or []
        for r in ip_ranges:
            cidr = r.get("CidrIp") if isinstance(r, dict) else r
            if str(cidr).strip() in open_cidrs:
                return False  # Violation: open to world

        # Check IPv6 ranges
        ipv6_ranges = perm.get("Ipv6Ranges") or perm.get("ipv6_ranges") or []
        for r in ipv6_ranges:
            cidr = r.get("CidrIpv6") if isinstance(r, dict) else r
            if str(cidr).strip() in open_cidrs:
                return False  # Violation: open to world

    return True


def evaluate_operator(
    operator: OperatorType,
    actual_value: Any,
    expected_value: Any,
    exists: bool = True,
) -> bool:
    """
    Evaluates a single operator comparison against actual and expected values.
    Returns True if the condition holds, False otherwise.
    """
    if operator == OperatorType.FIELD_EXISTS:
        return exists

    if operator == OperatorType.FIELD_MISSING:
        return not exists

    if not exists:
        # If the field doesn't exist, comparison operations fail unless testing NOT_EQUALS
        return operator == OperatorType.NOT_EQUALS

    if operator == OperatorType.EQUALS:
        return actual_value == expected_value

    elif operator == OperatorType.NOT_EQUALS:
        return actual_value != expected_value

    elif operator == OperatorType.CONTAINS:
        if actual_value is None:
            return False
        if isinstance(actual_value, (list, tuple, set, dict, str)):
            return expected_value in actual_value
        return False

    elif operator == OperatorType.NOT_CONTAINS:
        if actual_value is None:
            return True
        if isinstance(actual_value, (list, tuple, set, dict, str)):
            return expected_value not in actual_value
        return True

    elif operator == OperatorType.STARTS_WITH:
        return str(actual_value).startswith(str(expected_value))

    elif operator == OperatorType.ENDS_WITH:
        return str(actual_value).endswith(str(expected_value))

    elif operator == OperatorType.CIDR_IN:
        return _check_cidr_in(actual_value, expected_value)

    elif operator == OperatorType.PORT_IN:
        return _check_port_in(actual_value, expected_value)

    elif operator == OperatorType.NOT_CONTAINS_OPEN_PORT:
        return _check_not_contains_open_port(actual_value, expected_value)

    elif operator == OperatorType.IN_LIST:
        if isinstance(expected_value, (list, tuple, set)):
            return actual_value in expected_value
        return False

    elif operator == OperatorType.NOT_IN_LIST:
        if isinstance(expected_value, (list, tuple, set)):
            return actual_value not in expected_value
        return True

    elif operator == OperatorType.COUNT_EQUALS:
        try:
            return len(actual_value) == int(expected_value)
        except Exception:
            return False

    elif operator == OperatorType.COUNT_GREATER_THAN:
        try:
            return len(actual_value) > int(expected_value)
        except Exception:
            return False

    elif operator == OperatorType.COUNT_LESS_THAN:
        try:
            return len(actual_value) < int(expected_value)
        except Exception:
            return False

    elif operator == OperatorType.REGEX_MATCH:
        try:
            return bool(re.search(str(expected_value), str(actual_value)))
        except Exception:
            return False

    elif operator == OperatorType.EVIDENCE_VERIFIED:
        # Cross-verifies evidence integrity via verifier
        try:
            from backend.evidence.verifier import verify_single_record
            res = verify_single_record(actual_value)
            return res.get("valid", False)
        except Exception:
            return False

    else:
        raise UnknownOperatorError(f"Unsupported operator: {operator}")
