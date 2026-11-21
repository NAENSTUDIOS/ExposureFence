import sqlite3

DB_PATH = "exposurefence.db"

PROPOSAL_ADDITIONAL_COLUMNS = [
    ("evidence_id", "TEXT"),
    ("evidence_payload_digest", "TEXT"),
    ("rule_id", "TEXT"),
    ("rule_version", "TEXT"),
    ("rule_set_digest", "TEXT"),
    ("remediation_template_id", "TEXT"),
    ("remediation_digest", "TEXT"),
    ("created_at", "TEXT"),
    ("expires_at", "TEXT"),
    ("auto_approval_score", "REAL"),
    ("auto_approval_decision", "TEXT"),
    ("auto_approval_policy", "TEXT"),
    ("auto_approval_digest", "TEXT"),
    ("auto_approval_timestamp", "TEXT"),
]

_INITIALIZED_DBS = set()


def initialize_db(db_path=None):
    target = db_path or DB_PATH
    conn = sqlite3.connect(target, timeout=20.0)
    conn.execute("PRAGMA journal_mode=WAL")
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
        # Safe idempotent column additions for advanced proposal binding
        for col_name, col_type in PROPOSAL_ADDITIONAL_COLUMNS:
            try:
                conn.execute(f"ALTER TABLE proposals ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                # Column already exists
                pass

    conn.close()

    # Additive Phase 4 evidence tables and triggers
    from backend.evidence.repository import initialize_evidence_tables
    initialize_evidence_tables(target)
    _INITIALIZED_DBS.add(target)


def get_connection(db_path=None):
    target = db_path or DB_PATH
    if target not in _INITIALIZED_DBS:
        initialize_db(target)
    conn = sqlite3.connect(target, timeout=20.0)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn
