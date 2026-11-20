"""
ExposureFence Evidence Engine RFC 8785 Canonicalization Module
Implements RFC 8785 (JSON Canonicalization Scheme - JCS) for deterministic,
cryptographically reproducible payload hashing.
"""

from datetime import date, datetime, timezone
from decimal import Decimal
import math
from typing import Any, Dict, List, Union
import uuid

import rfc8785

from backend.evidence.exceptions import CanonicalizationError

CANONICALIZATION_ALGORITHM = "RFC-8785"
CANONICALIZATION_VERSION = "1.0"


def normalize_for_canonicalization(obj: Any) -> Any:
    """
    Normalizes complex Python types (datetime, date, Decimal, UUID) into standard
    JSON-representable primitives according to RFC 8785 rules.
    Rejects NaN, Infinity, and non-string dictionary keys.
    """
    if obj is None:
        return None

    if isinstance(obj, bool):
        return obj

    if isinstance(obj, (int,)):
        return obj

    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalizationError(f"Float value {obj} (NaN or Infinity) is not representable in JCS")
        return obj

    if isinstance(obj, Decimal):
        if obj.is_nan() or obj.is_infinite():
            raise CanonicalizationError(f"Decimal value {obj} is not representable in JCS")
        # If integer equivalent, return int
        if obj % 1 == 0:
            return int(obj)
        return float(obj)

    if isinstance(obj, (datetime,)):
        # Normalize datetime to UTC ISO-8601 with trailing 'Z'
        if obj.tzinfo is None:
            # Assume UTC if naive
            utc_dt = obj.replace(tzinfo=timezone.utc)
        else:
            utc_dt = obj.astimezone(timezone.utc)
        # Format as YYYY-MM-DDTHH:MM:SSZ (or with microseconds if non-zero)
        if utc_dt.microsecond > 0:
            return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(obj, (date,)):
        return obj.isoformat()

    if isinstance(obj, (str,)):
        return obj

    if isinstance(obj, (uuid.UUID,)):
        return str(obj)

    if isinstance(obj, (list, tuple, set)):
        return [normalize_for_canonicalization(item) for item in obj]

    if isinstance(obj, dict):
        normalized_dict = {}
        for key, val in obj.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"Non-string dictionary key encountered: {key!r} ({type(key).__name__})")
            normalized_dict[key] = normalize_for_canonicalization(val)
        return normalized_dict

    # Check if object has asdict or to_dict
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return normalize_for_canonicalization(obj.to_dict())

    raise CanonicalizationError(f"Unsupported object type for canonicalization: {type(obj).__name__}")


def canonicalize_json(data: Any) -> bytes:
    """
    Serializes a normalized Python object into canonical RFC 8785 JSON bytes.
    Guarantees deterministic lexicographic key ordering, minimal spacing,
    and strict IEEE 754 number formatting.
    """
    try:
        normalized = normalize_for_canonicalization(data)
        return rfc8785.dumps(normalized)
    except rfc8785.CanonicalizationError as e:
        raise CanonicalizationError(f"RFC 8785 canonicalization failed: {e}") from e
    except Exception as e:
        if isinstance(e, CanonicalizationError):
            raise
        raise CanonicalizationError(f"Unexpected error during canonicalization: {e}") from e


def canonicalize_json_str(data: Any) -> str:
    """Returns canonical RFC 8785 JSON decoded as a UTF-8 string."""
    return canonicalize_json(data).decode("utf-8")
