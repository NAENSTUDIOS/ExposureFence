"""
ExposureFence — Intelligence Normalization Service
Standardizes severities, resource ARNs, timestamps, and input sanitization
across heterogeneous cloud security finding sources.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, Optional

from backend.intelligence.models import FindingSeverity


def normalize_severity(raw_severity: Any) -> FindingSeverity:
    """
    Normalizes severity across ASFF labels, numeric scores, and Prowler strings.
    """
    if raw_severity is None:
        return FindingSeverity.INFORMATIONAL

    if isinstance(raw_severity, (int, float)):
        if raw_severity >= 90:
            return FindingSeverity.CRITICAL
        elif raw_severity >= 70:
            return FindingSeverity.HIGH
        elif raw_severity >= 40:
            return FindingSeverity.MEDIUM
        elif raw_severity > 0:
            return FindingSeverity.LOW
        return FindingSeverity.INFORMATIONAL

    s = str(raw_severity).strip().upper()
    if "CRIT" in s or s == "FATAL":
        return FindingSeverity.CRITICAL
    elif "HIGH" in s or s == "ERROR":
        return FindingSeverity.HIGH
    elif "MED" in s or s == "WARN" or s == "WARNING":
        return FindingSeverity.MEDIUM
    elif "LOW" in s or s == "NOTICE":
        return FindingSeverity.LOW
    elif "INFO" in s or "PASS" in s or "INFORMATIONAL" in s:
        return FindingSeverity.INFORMATIONAL

    return FindingSeverity.MEDIUM


def normalize_arn(
    resource_id: str,
    service: str,
    account_id: str = "123456789012",
    region: str = "us-east-1"
) -> str:
    """
    Ensures a standardized AWS ARN format for any resource identifier.
    """
    cleaned_id = resource_id.strip()
    if cleaned_id.startswith("arn:aws:"):
        return cleaned_id

    srv = service.lower().strip()
    if srv == "s3":
        # S3 ARN: arn:aws:s3:::bucket-name
        return f"arn:aws:s3:::{cleaned_id}"
    elif srv == "ec2":
        if cleaned_id.startswith("sg-"):
            return f"arn:aws:ec2:{region}:{account_id}:security-group/{cleaned_id}"
        elif cleaned_id.startswith("i-"):
            return f"arn:aws:ec2:{region}:{account_id}:instance/{cleaned_id}"
        elif cleaned_id.startswith("vpc-"):
            return f"arn:aws:ec2:{region}:{account_id}:vpc/{cleaned_id}"
        return f"arn:aws:ec2:{region}:{account_id}:resource/{cleaned_id}"
    elif srv == "iam":
        if "/" in cleaned_id:
            return f"arn:aws:iam::{account_id}:{cleaned_id}"
        return f"arn:aws:iam::{account_id}:role/{cleaned_id}"

    return f"arn:aws:{srv}:{region}:{account_id}:resource/{cleaned_id}"


def normalize_timestamp(raw_timestamp: Optional[str]) -> str:
    """
    Parses arbitrary ISO 8601 strings and returns canonical ISO 8601 UTC.
    """
    if not raw_timestamp:
        return datetime.now(timezone.utc).isoformat()

    try:
        clean = raw_timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def sanitize_untrusted_text(text: Optional[str], max_len: int = 2000) -> str:
    """
    Sanitizes untrusted text from third-party finding descriptions or tags
    to prevent indirect prompt injection and control character abuse.
    """
    if not text:
        return ""

    # Remove null bytes and non-printable control characters (except newline/tab)
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
    # Truncate to maximum permissible length
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "... [TRUNCATED]"
    return cleaned.strip()


def compute_raw_hash(raw_data: Any) -> str:
    """
    Computes a deterministic SHA-256 hash of raw JSON or dictionary payload.
    """
    if isinstance(raw_data, (dict, list)):
        canonical_str = json.dumps(raw_data, sort_keys=True, separators=(",", ":"))
    else:
        canonical_str = str(raw_data)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
