import os
import bcrypt

def verify_password(password: str) -> bool:
    password_hash = os.getenv("APPROVER_PASSWORD_HASH")

    if not password_hash:
        return False

    return bcrypt.checkpw(
        password.encode(),
        password_hash.encode()
    )