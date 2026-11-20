"""
ExposureFence — Phase 9 Red-Team Workstream 5: Reliability & Operational Security
Adversarial test cases targeting:
- API authorization bypass rejection
- Database concurrency and SQLite WAL mode resilience
- Automated database backup and SHA-256 integrity verification
- Audit hash-chain tamper detection (cryptographic non-repudiation)
- Subsystem health and metrics observability probes
"""

import concurrent.futures
import json
import os
import sqlite3
import pytest

from backend.audit import log_event, verify_audit_hash_chain, get_audit_events
from backend.database import get_connection
from backend.observability.backup import create_backup, verify_backup
from backend.observability.health import check_system_health
from backend.observability.metrics import collect_system_metrics


def test_operational_database_concurrency_wal_mode(tmp_path):
    """
    STRESS TEST: High concurrent writes across multiple worker threads to SQLite database.
    DEFENSE: SQLite WAL (Write-Ahead Logging) mode and busy_timeout prevent 'database is locked' errors.
    """
    db_file = str(tmp_path / "concurrent_stress.db")

    # Initialize table
    conn = get_connection(db_file)
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS stress_log (id INTEGER PRIMARY KEY, worker_id TEXT, ts TEXT)")
    conn.close()

    def worker_task(worker_idx: int):
        for i in range(25):
            c = get_connection(db_file)
            with c:
                c.execute("INSERT INTO stress_log (worker_id, ts) VALUES (?, ?)", (f"worker_{worker_idx}", f"iter_{i}"))
            c.close()
        return True

    # Run 8 concurrent worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_task, idx) for idx in range(8)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 8
    assert all(r is True for r in results)

    # Verify total rows written: 8 workers * 25 inserts = 200 rows
    check_conn = get_connection(db_file)
    count = check_conn.execute("SELECT count(*) FROM stress_log").fetchone()[0]
    check_conn.close()
    assert count == 200


def test_operational_backup_creation_and_integrity_verification(tmp_path):
    """
    OPERATIONAL ASSURANCE: Automated SQLite snapshot backup with SHA-256 checksum verification.
    """
    db_file = str(tmp_path / "primary_app.db")
    backup_dir = str(tmp_path / "backups")

    conn = get_connection(db_file)
    with conn:
        conn.execute("CREATE TABLE records (id TEXT PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO records VALUES ('r1', 'critical_state')")
    conn.close()

    # Create backup snapshot
    backup_result = create_backup(backup_dir=backup_dir, db_path=db_file)
    manifest_path = backup_result["manifest_path"]
    assert os.path.exists(manifest_path)
    assert "manifest" in backup_result

    # Verify backup integrity
    assert verify_backup(manifest_path) is True

    # Tamper with backup database file
    db_backup_file = os.path.join(backup_dir, backup_result["manifest"]["database_file"])
    with open(db_backup_file, "ab") as f:
        f.write(b"CORRUPTION")

    # Verify corruption is detected
    assert verify_backup(manifest_path) is False


def test_operational_audit_chain_tamper_detection(tmp_path):
    """
    ATTACK: An adversary attempts to delete or alter a past event in the audit trail.
    DEFENSE: SHA-256 prev_hash -> event_hash hash chain detects broken sequence.
    """
    audit_file = str(tmp_path / "tamper_audit.jsonl")

    # Log 3 sequential events to temporary audit file
    import backend.audit
    orig_audit_path = backend.audit.AUDIT_FILE
    backend.audit.AUDIT_FILE = audit_file

    try:
        e1 = log_event("SYS_STARTUP", {"version": "1.0"})
        e2 = log_event("PROPOSAL_CREATED", {"proposal_id": "P-01"})
        e3 = log_event("PROPOSAL_APPROVED", {"proposal_id": "P-01", "approver": "admin"})

        assert verify_audit_hash_chain() is True

        # Read all events and tamper with event 2
        with open(audit_file, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        # Adversary alters details in event 2 (claiming approval was rejected)
        lines[1]["details"]["proposal_id"] = "P-TAMPERED-99"

        with open(audit_file, "w") as f:
            for l in lines:
                f.write(json.dumps(l) + "\n")

        # Hash chain verification MUST FAIL
        assert verify_audit_hash_chain() is False

    finally:
        backend.audit.AUDIT_FILE = orig_audit_path


def test_operational_health_probes(tmp_path):
    """
    OBSERVABILITY ASSURANCE: /api/health probe checks all core subsystems.
    """
    db_file = str(tmp_path / "health_test.db")
    conn = get_connection(db_file)
    conn.close()

    health = check_system_health(db_path=db_file)
    assert health["status"] in ("healthy", "degraded")
    assert "probes" in health
    assert "database_connected" in health["probes"]
    assert "audit_hash_chain_valid" in health["probes"]


def test_operational_metrics_collection(tmp_path):
    """
    OBSERVABILITY ASSURANCE: /api/metrics produces Prometheus/JSON metrics with uptime and counters.
    """
    db_file = str(tmp_path / "metrics_test.db")
    metrics = collect_system_metrics(db_path=db_file)

    assert "security_metrics" in metrics
    assert "system_metrics" in metrics
    assert "proposals_pending_review" in metrics["security_metrics"]
    assert metrics["security_metrics"]["zero_mutation_invariant"] is True
