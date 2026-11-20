"""
ExposureFence Authentication Service
Enforces strict Bcrypt verification for out-of-band admin approvers.
Requires APPROVER_PASSWORD_HASH to be explicitly configured.
No hardcoded default passwords permitted.
"""

import os
import bcrypt


def verify_password(password: str, username: str = None) -> bool:
    """
    Verifies admin credentials against APPROVER_PASSWORD_HASH.
    Authentication is strictly prohibited if APPROVER_PASSWORD_HASH is unset.
    Never prints or logs password or hash strings.
    """
    password_hash = os.getenv("APPROVER_PASSWORD_HASH")
    if not password_hash:
        return False

    expected_user = os.getenv("APPROVER_USERNAME", "admin")
    if username is not None and username != expected_user:
        return False

    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False
