from backend.session_store import (
    create_session,
    valid_session
)

def test_session_creation():

    session = create_session("admin")

    assert valid_session(session)