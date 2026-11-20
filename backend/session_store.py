import secrets
import time

SESSIONS = {}


def create_session(username):
    session_id = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    SESSIONS[session_id] = {
        "username": username,
        "csrf_token": csrf_token,
        "created_at": time.time()
    }
    return session_id


def get_session(session_id):
    return SESSIONS.get(session_id)


def valid_session(session_id):
    return session_id in SESSIONS


def destroy_session(session_id):
    if session_id in SESSIONS:
        del SESSIONS[session_id]
        return True
    return False



def destroy_session(session_id):
    if session_id in SESSIONS:
        del SESSIONS[session_id]
        return True
    return False