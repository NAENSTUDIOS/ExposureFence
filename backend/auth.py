import os
import bcrypt

# Default password for local single-admin development: "ExposureFenceAdmin2026!"
DEFAULT_DEV_HASH = "$2b$12$KIXbV7tY49v1x5d806aPceKzL985yJ58r2j2s9K3W0a7n2v7c4hKe"


def verify_password(password: str) -> bool:
    password_hash = os.getenv("APPROVER_PASSWORD_HASH")

    if not password_hash:
        # Allow default dev password if APPROVER_PASSWORD_HASH not explicitly set
        if password == "ExposureFenceAdmin2026!":
            return True
        return False

    try:
        return bcrypt.checkpw(
            password.encode(),
            password_hash.encode()
        )
    except Exception:
        return False
