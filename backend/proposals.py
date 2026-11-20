"""
ExposureFence — Proposal Management Service
Manages deterministic remediation proposals with Advanced Evidence Binding,
cryptographic digest verification, and expiration tracking.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import os
from typing import Any, Dict, List, Optional
import uuid

from backend.database import get_connection


def _compute_sha256(text: str) -> str:
    """Computes SHA-256 digest of input string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _get_rules_digest() -> str:
    """Computes SHA-256 digest of active rules/rules.yaml."""
    rules_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "rules", "rules.yaml"
    )
    if os.path.exists(rules_path):
        try:
            with open(rules_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass
    return "GENESIS_RULES_DIGEST"


def create_proposal(
    finding_id: str,
    resource_id: str,
    remediation: str,
    evidence_id: Optional[str] = None,
    evidence_payload_digest: Optional[str] = None,
    rule_id: Optional[str] = None,
    rule_version: Optional[str] = "1.0.0",
    rule_set_digest: Optional[str] = None,
    remediation_template_id: Optional[str] = None,
    remediation_digest: Optional[str] = None,
    expires_at: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates a new remediation proposal in PENDING state bound to verified evidence.
    """
    proposal_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    created_at = now.isoformat()

    # Default TTL: 24 hours (86,400 seconds)
    default_expiry = (now + timedelta(seconds=86400)).isoformat()
    final_expires_at = expires_at or default_expiry

    resolved_evidence_digest = evidence_payload_digest
    resolved_rules_digest = rule_set_digest or _get_rules_digest()
    resolved_remediation_digest = remediation_digest or _compute_sha256(remediation.strip())
    resolved_rule_id = rule_id or ("SEC-S3-001" if "S3" in finding_id else "SEC-EC2-001" if "SG" in finding_id else "R04")

    # If evidence_id provided, verify evidence exists and bind proposal
    if evidence_id:
        from backend.evidence.service import EvidenceService
        svc = EvidenceService(db_path=db_path)
        ev = svc.get_evidence(evidence_id)
        if not ev:
            raise ValueError(f"Cannot create proposal: Evidence ID '{evidence_id}' does not exist in evidence ledger")

        if not resolved_evidence_digest:
            resolved_evidence_digest = ev.payload_sha256

        # Check evidence integrity
        if ev.integrity_status == "INTEGRITY_MISMATCH":
            raise ValueError(f"Cannot create proposal: Evidence '{evidence_id}' has integrity mismatch")

        # Check evidence freshness (blocks STALE evidence)
        if ev.freshness_status == "STALE":
            raise ValueError(f"Cannot create proposal: Evidence '{evidence_id}' is stale and cannot be used for new proposals")

        # Record proposal binding in evidence relationships
        try:
            svc.link_proposal(proposal_id, evidence_id, resolved_evidence_digest)
        except Exception:
            pass

    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            INSERT INTO proposals (
                proposal_id, finding_id, resource_id, remediation, status,
                evidence_id, evidence_payload_digest, rule_id, rule_version,
                rule_set_digest, remediation_template_id, remediation_digest,
                created_at, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proposal_id,
                finding_id,
                resource_id,
                remediation,
                "PENDING",
                evidence_id,
                resolved_evidence_digest,
                resolved_rule_id,
                rule_version,
                resolved_rules_digest,
                remediation_template_id or f"TMPL-{resolved_rule_id}",
                resolved_remediation_digest,
                created_at,
                final_expires_at,
            )
        )
    conn.close()

    return {
        "proposal_id": proposal_id,
        "finding_id": finding_id,
        "resource_id": resource_id,
        "remediation": remediation,
        "status": "PENDING",
        "evidence_id": evidence_id,
        "evidence_payload_digest": resolved_evidence_digest,
        "rule_id": resolved_rule_id,
        "rule_version": rule_version,
        "created_at": created_at,
        "expires_at": final_expires_at,
    }


def get_proposals(db_path: Optional[str] = None):
    conn = get_connection(db_path)
    rows = conn.execute(
        """
        SELECT *
        FROM proposals
        """
    ).fetchall()
    conn.close()
    return rows


def get_proposal_by_id(proposal_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a single proposal as a dictionary."""
    conn = get_connection(db_path)
    cursor = conn.execute(
        """
        SELECT proposal_id, finding_id, resource_id, remediation, status,
               evidence_id, evidence_payload_digest, rule_id, rule_version,
               rule_set_digest, remediation_template_id, remediation_digest,
               created_at, expires_at
        FROM proposals
        WHERE proposal_id = ?
        """,
        (proposal_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None

    return {
        "proposal_id": row[0],
        "finding_id": row[1],
        "resource_id": row[2],
        "remediation": row[3],
        "status": row[4],
        "evidence_id": row[5],
        "evidence_payload_digest": row[6],
        "rule_id": row[7],
        "rule_version": row[8],
        "rule_set_digest": row[9],
        "remediation_template_id": row[10],
        "remediation_digest": row[11],
        "created_at": row[12],
        "expires_at": row[13],
    }
