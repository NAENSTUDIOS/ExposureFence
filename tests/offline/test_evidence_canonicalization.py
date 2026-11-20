"""
Tests for RFC 8785 (JSON Canonicalization Scheme) Implementation
Verifies key sorting, whitespace elimination, numeric precision,
Unicode compliance, and strict domain rejection (NaN, Infinity, non-string keys).
"""

from datetime import datetime, timezone
from decimal import Decimal
import json
import pytest

from backend.evidence.canonicalization import (
    canonicalize_json,
    canonicalize_json_str,
    normalize_for_canonicalization,
)
from backend.evidence.exceptions import CanonicalizationError


def test_key_ordering_determinism():
    """Different key insertion orders produce identical canonical bytes."""
    dict1 = {"z": 100, "a": 1, "m": 50}
    dict2 = {"a": 1, "m": 50, "z": 100}
    dict3 = {"m": 50, "z": 100, "a": 1}

    bytes1 = canonicalize_json(dict1)
    bytes2 = canonicalize_json(dict2)
    bytes3 = canonicalize_json(dict3)

    assert bytes1 == bytes2 == bytes3
    assert bytes1 == b'{"a":1,"m":50,"z":100}'


def test_nested_key_ordering():
    """Nested dictionaries are recursively ordered lexicographically."""
    data1 = {"parent": {"b": 2, "a": 1}, "list": [{"y": 2, "x": 1}]}
    data2 = {"list": [{"x": 1, "y": 2}], "parent": {"a": 1, "b": 2}}

    assert canonicalize_json(data1) == canonicalize_json(data2)
    assert canonicalize_json(data1) == b'{"list":[{"x":1,"y":2}],"parent":{"a":1,"b":2}}'


def test_whitespace_elimination():
    """Whitespace variations in input do not affect canonicalization."""
    obj = {"key": "value", "count": 42}
    raw_json_pretty = json.dumps(obj, indent=4)
    raw_json_spaced = json.dumps(obj, separators=(", ", ": "))

    parsed_pretty = json.loads(raw_json_pretty)
    parsed_spaced = json.loads(raw_json_spaced)

    assert canonicalize_json(parsed_pretty) == canonicalize_json(parsed_spaced)
    assert canonicalize_json(parsed_pretty) == b'{"count":42,"key":"value"}'


def test_unicode_preservation():
    """Unicode characters are encoded natively as UTF-8 without unnecessary escapes."""
    data = {"message": "Security \u2705 Verified", "tag": "\u00e9l\u00e9ment"}
    canonical = canonicalize_json_str(data)
    assert "Security \u2705 Verified" in canonical
    assert "\u00e9l\u00e9ment" in canonical
    assert "\\u" not in canonical


def test_nan_rejection():
    """NaN float or Decimal is strictly rejected."""
    with pytest.raises(CanonicalizationError, match="NaN or Infinity"):
        canonicalize_json({"value": float("nan")})

    with pytest.raises(CanonicalizationError, match="Decimal value"):
        canonicalize_json({"value": Decimal("NaN")})


def test_infinity_rejection():
    """Infinity float or Decimal is strictly rejected."""
    with pytest.raises(CanonicalizationError, match="NaN or Infinity"):
        canonicalize_json({"value": float("inf")})

    with pytest.raises(CanonicalizationError, match="NaN or Infinity"):
        canonicalize_json({"value": float("-inf")})


def test_non_string_dictionary_keys():
    """Non-string dictionary keys are strictly rejected."""
    with pytest.raises(CanonicalizationError, match="Non-string dictionary key"):
        canonicalize_json({123: "numeric_key"})

    with pytest.raises(CanonicalizationError, match="Non-string dictionary key"):
        canonicalize_json({(1, 2): "tuple_key"})


def test_datetime_normalization():
    """Timezone-aware datetime objects are converted to standard UTC ISO-8601 strings."""
    dt = datetime(2026, 11, 21, 12, 30, 45, tzinfo=timezone.utc)
    res = canonicalize_json_str({"timestamp": dt})
    assert res == '{"timestamp":"2026-11-21T12:30:45Z"}'


def test_decimal_normalization():
    """Decimals are converted to exact integers or floats."""
    data = {"integer": Decimal("42"), "fraction": Decimal("3.14")}
    canonical = canonicalize_json_str(data)
    assert canonical == '{"fraction":3.14,"integer":42}'


def test_unsupported_object_types():
    """Arbitrary unsupported Python objects raise CanonicalizationError."""
    class CustomArbitraryClass:
        pass

    with pytest.raises(CanonicalizationError, match="Unsupported object type"):
        canonicalize_json({"bad": CustomArbitraryClass()})
