import os
import bcrypt
from backend.auth import verify_password


def test_verify_password():
    # Verify missing hash denies authentication
    if "APPROVER_PASSWORD_HASH" in os.environ:
        del os.environ["APPROVER_PASSWORD_HASH"]
    assert verify_password("AnyPassword") is False

    password = "SuperSecretPassword123!"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    os.environ["APPROVER_PASSWORD_HASH"] = hashed

    try:
        assert verify_password(password) is True
        assert verify_password("WrongPassword") is False
    finally:
        del os.environ["APPROVER_PASSWORD_HASH"]
