from backend.database import initialize_db, get_connection


def test_database_creation():
    initialize_db()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='proposals'")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "proposals"
