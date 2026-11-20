"""
ExposureFence In-Memory Session Store
Manages authenticated out-of-band operator sessions with CSRF tokens and TTL expiry.
"""

import secrets
import time

SESSIONS = {}
SESSION_TTL_SECONDS = 3600  # 1 hour expiry


def create_session(username: str) -> str:
    session_id = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    SESSIONS[session_id] = {
        "username": username,
        "csrf_token": csrf_token,
        "created_at": time.time()
    }
    return session_id


def get_session(session_id: str):
    if not valid_session(session_id):
        return None
    return SESSIONS.get(session_id)


def valid_session(session_id: str) -> bool:
    if not session_id or session_id not in SESSIONS:
        return False

    session = SESSIONS[session_id]
    # Check session expiration
    if time.time() - session.get("created_at", 0) > SESSION_TTL_SECONDS:
        del SESSIONS[session_id]
        return False

    return True


def destroy_session(session_id: str) -> bool:
    if session_id in SESSIONS:
        del SESSIONS[session_id]
        return True
    return False
