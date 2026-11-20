import uuid

SESSIONS = {}

def create_session(username):
    session_id = str(uuid.uuid4())

    SESSIONS[session_id] = {
        "username": username
    }

    return session_id

def valid_session(session_id):
    return session_id in SESSIONS