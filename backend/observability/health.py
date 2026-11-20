"""
ExposureFence — Health Check & Readiness Probes
Provides operational readiness and health telemetry for /api/health endpoint.
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict, Optional

from backend.audit import verify_audit_hash_chain, verify_zero_mutations
from backend.connectors.aws_session import get_data_mode
from backend.database import get_connection


def check_system_health(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs comprehensive system readiness and health probes:
    - Database connectivity (WAL mode SQLite)
    - Audit log hash chain cryptographic integrity
    - Zero cloud mutations verification
    - Data mode status
    """
    now = datetime.now(timezone.utc).isoformat()
    db_ok = False
    db_error = None

    try:
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        row = cursor.fetchone()
        db_ok = row is not None and row[0] == 1
        conn.close()
    except Exception as e:
        db_error = str(e)

    audit_chain_ok = verify_audit_hash_chain()
    zero_mutations_ok = verify_zero_mutations()
    data_mode = get_data_mode()

    is_healthy = db_ok and audit_chain_ok and zero_mutations_ok

    return {
        "status": "healthy" if is_healthy else "degraded",
        "timestamp": now,
        "probes": {
            "database_connected": db_ok,
            "database_error": db_error,
            "audit_hash_chain_valid": audit_chain_ok,
            "zero_cloud_mutations_verified": zero_mutations_ok,
            "data_mode": data_mode
        },
        "version": "3.0.0"
    }
