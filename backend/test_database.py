from backend.database import initialize_db


def test_database_creation():
    initialize_db()

    assert True