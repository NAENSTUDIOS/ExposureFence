"""
ExposureFence — Account Identity Verification Component
Enforces caller identity validation via sts:GetCallerIdentity against the configured
12-digit account allowlist (EXPOSUREFENCE_ALLOWED_ACCOUNT_ID).
"""

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Optional

from backend.connectors.exceptions import (
    AccountMismatchError,
    AccountVerificationError
)
from backend.connectors.redaction import redact_credentials

ACCOUNT_ID_REGEX = re.compile(r"^\d{12}$")


def validate_account_id_format(account_id: str) -> bool:
    """Validates that an account ID is a non-empty string consisting of exactly 12 numeric digits."""
    if not account_id or not isinstance(account_id, str):
        return False
    return bool(ACCOUNT_ID_REGEX.match(account_id.strip()))


def verify_caller_account(
    client_or_session: Any,
    allowed_account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validates caller AWS account against EXPOSUREFENCE_ALLOWED_ACCOUNT_ID using sts:GetCallerIdentity.
    Aborts immediately with AccountMismatchError or AccountVerificationError on discrepancy.
    Returns sanitized identity metadata for assessment records.
    """
    target_allowed = (allowed_account_id or os.getenv("EXPOSUREFENCE_ALLOWED_ACCOUNT_ID", "")).strip()

    if not target_allowed:
        raise AccountVerificationError(
            "EXPOSUREFENCE_ALLOWED_ACCOUNT_ID is not configured. Account allowlist is strictly required in AWS mode."
        )

    if not validate_account_id_format(target_allowed):
        raise AccountVerificationError(
            f"Configured allowed account ID '{target_allowed}' is invalid. Must be exactly 12 numeric digits."
        )

    # Resolve STS client
    if hasattr(client_or_session, "get_caller_identity"):
        sts_client = client_or_session
    elif hasattr(client_or_session, "client"):
        sts_client = client_or_session.client("sts")
    elif hasattr(client_or_session, "get_client"):
        sts_client = client_or_session.get_client("sts")
    else:
        raise AccountVerificationError("Invalid client or session supplied to verify_caller_account.")

    try:
        identity = sts_client.get_caller_identity()
    except Exception as e:
        raise AccountVerificationError(f"Failed to query caller identity via sts:GetCallerIdentity: {type(e).__name__}: {e}")

    actual_account = str(identity.get("Account", "")).strip()
    caller_arn = str(identity.get("Arn", ""))
    user_id = str(identity.get("UserId", ""))

    if not actual_account:
        raise AccountVerificationError("STS response did not contain an Account identifier.")

    if actual_account != target_allowed:
        raise AccountMismatchError(
            f"Target account mismatch: Caller AWS account '{actual_account}' does not match "
            f"configured allowlist '{target_allowed}'. Aborting discovery."
        )

    verification_metadata = {
        "status": "VERIFIED",
        "account_id": actual_account,
        "caller_arn": caller_arn,
        "user_id": user_id,
        "verification_timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Guarantee zero credentials or session tokens in output
    return redact_credentials(verification_metadata)
