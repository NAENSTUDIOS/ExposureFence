import sqlite3


DB_PATH = "exposurefence.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_db():
    conn = get_connection()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS proposals (
        proposal_id TEXT PRIMARY KEY,
        finding_id TEXT,
        resource_id TEXT,
        remediation TEXT,
        status TEXT
    )
    """)

    conn.commit()
    conn.close()