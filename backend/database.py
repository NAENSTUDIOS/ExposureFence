import sqlite3

DB_PATH = "exposurefence.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def initialize_db():
    conn = get_connection()
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS proposals (
            proposal_id TEXT PRIMARY KEY,
            finding_id TEXT,
            resource_id TEXT,
            remediation TEXT,
            status TEXT
        )
        """)
    conn.close()

    # Additive Phase 4 evidence tables and triggers
    from backend.evidence.repository import initialize_evidence_tables
    initialize_evidence_tables(DB_PATH)
