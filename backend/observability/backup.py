"""
ExposureFence — Database & Audit Ledger Backup and Restore Utility
Creates timestamped, SHA-256 verified snapshot archives of the SQLite database and audit log.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
from typing import Any, Dict, Optional


def create_backup(backup_dir: str = "backups", db_path: str = "exposurefence.db", audit_path: str = "audit.jsonl") -> Dict[str, Any]:
    """
    Creates a verified snapshot of the active database and audit ledger.
    """
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    target_db = os.path.join(backup_dir, f"exposurefence_{timestamp}.db")
    target_audit = os.path.join(backup_dir, f"audit_{timestamp}.jsonl")
    manifest_path = os.path.join(backup_dir, f"backup_manifest_{timestamp}.json")

    db_hash = "FILE_NOT_FOUND"
    if os.path.exists(db_path):
        shutil.copy2(db_path, target_db)
        with open(target_db, "rb") as f:
            db_hash = hashlib.sha256(f.read()).hexdigest()

    audit_hash = "FILE_NOT_FOUND"
    if os.path.exists(audit_path):
        shutil.copy2(audit_path, target_audit)
        with open(target_audit, "rb") as f:
            audit_hash = hashlib.sha256(f.read()).hexdigest()

    manifest = {
        "backup_timestamp": datetime.now(timezone.utc).isoformat(),
        "database_file": os.path.basename(target_db),
        "database_sha256": db_hash,
        "audit_file": os.path.basename(target_audit),
        "audit_sha256": audit_hash
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return {
        "manifest_path": manifest_path,
        "manifest": manifest
    }


def verify_backup(manifest_path: str) -> bool:
    """Verifies that a backup archive has not been tampered with."""
    if not os.path.exists(manifest_path):
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    b_dir = os.path.dirname(manifest_path)
    db_file = os.path.join(b_dir, manifest.get("database_file", ""))
    audit_file = os.path.join(b_dir, manifest.get("audit_file", ""))

    if not os.path.exists(db_file) or not os.path.exists(audit_file):
        return False

    with open(db_file, "rb") as f:
        db_hash = hashlib.sha256(f.read()).hexdigest()

    with open(audit_file, "rb") as f:
        audit_hash = hashlib.sha256(f.read()).hexdigest()

    return db_hash == manifest.get("database_sha256") and audit_hash == manifest.get("audit_sha256")
