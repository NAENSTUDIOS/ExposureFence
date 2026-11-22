"""
ExposureFence — Assessment Evidence Status & Safety Invariant Engine
Defines standardized assessment states and guarantees that cloud inspection errors
can NEVER evaluate to VERIFIED or VERIFIED_SECURE.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, Optional


class AssessmentStatus(str, Enum):
    """
    Standardized operational and verification states for AWS evidence collection.
    """
    VERIFIED = "VERIFIED"
    ASSESSMENT_INCOMPLETE = "ASSESSMENT_INCOMPLETE"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
    REGION_NOT_ALLOWED = "REGION_NOT_ALLOWED"
    CREDENTIALS_UNAVAILABLE = "CREDENTIALS_UNAVAILABLE"
    API_TIMEOUT = "API_TIMEOUT"
    THROTTLED = "THROTTLED"


def map_error_to_assessment_status(exc: Exception) -> AssessmentStatus:
    """
    Maps an exception or client error to the appropriate AssessmentStatus.
    INVARIANT: An error condition MUST NEVER map to VERIFIED or VERIFIED_SECURE.
    """
    exc_type_name = type(exc).__name__
    exc_str = str(exc).lower()

    if "credentialsunavailable" in exc_str or exc_type_name == "CredentialsUnavailableError":
        return AssessmentStatus.CREDENTIALS_UNAVAILABLE
    if "accountmismatch" in exc_str or exc_type_name == "AccountMismatchError":
        return AssessmentStatus.ACCOUNT_MISMATCH
    if "accountverification" in exc_str or exc_type_name == "AccountVerificationError":
        return AssessmentStatus.ACCOUNT_MISMATCH
    if "unauthorizedregion" in exc_str or exc_type_name == "UnauthorizedRegionError":
        return AssessmentStatus.REGION_NOT_ALLOWED
    if "accessdenied" in exc_str or "unauthorizedoperation" in exc_str or "forbidden" in exc_str:
        return AssessmentStatus.ACCESS_DENIED
    if "timeout" in exc_str or exc_type_name == "APITimeoutError":
        return AssessmentStatus.API_TIMEOUT
    if "throttl" in exc_str or "requestlimitexceeded" in exc_str or exc_type_name in ("APIThrottledError", "APIBudgetExceededError"):
        return AssessmentStatus.THROTTLED

    return AssessmentStatus.ASSESSMENT_INCOMPLETE


def build_failure_evidence(
    resource_id: str,
    source_type: str,
    status: AssessmentStatus,
    error_message: str,
    account_id: Optional[str] = None,
    region: Optional[str] = None
) -> Dict[str, Any]:
    """
    Constructs an explicit, normalized failure evidence record adhering to invariant rules.
    Guarantees verification_result is never clean/secure.
    """
    if status == AssessmentStatus.VERIFIED:
        raise ValueError("Cannot build failure evidence with a VERIFIED status.")

    timestamp = datetime.now(timezone.utc).isoformat()
    raw_evidence = {
        "resource_id": resource_id,
        "error": error_message,
        "failure_status": status.value,
        "is_verified_secure": False,
        "assessment_complete": False
    }

    canonical_raw = json.dumps(raw_evidence, sort_keys=True)
    digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
    prefix = source_type.split("::")[-1] if "::" in source_type else "AWS"
    evidence_id = f"EV-FAIL-{prefix}-{resource_id}-{digest[:8]}"

    return {
        "evidence_id": evidence_id,
        "resource_id": resource_id,
        "source_type": source_type,
        "account_id": account_id or "UNKNOWN",
        "region": region or "UNKNOWN",
        "collection_timestamp": timestamp,
        "raw_evidence": raw_evidence,
        "sha256": digest,
        "verification_result": "ASSESSMENT_INCOMPLETE",
        "assessment_status": status.value
    }
