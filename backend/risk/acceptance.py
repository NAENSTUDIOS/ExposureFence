"""
ExposureFence — Risk Acceptance Registry & Governance
Maintains formal risk acceptance records, validates expiration timestamps,
and enforces automatic expiration and revocation with full audit logging.
"""

from datetime import datetime, timezone
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

from backend.database import get_connection
from backend.risk.models import RiskAcceptance


def initialize_risk_acceptance_tables(db_path: Optional[str] = None) -> None:
    """Creates risk acceptance table."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS risk_acceptances (
            acceptance_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            resource_arn TEXT NOT NULL,
            justification TEXT NOT NULL,
            approver TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ra_finding ON risk_acceptances(finding_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ra_resource ON risk_acceptances(resource_arn)")
    conn.close()


class RiskAcceptanceService:
    """Service managing risk acceptances, expirations, and revocations."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        initialize_risk_acceptance_tables(db_path)

    def create_acceptance(
        self,
        finding_id: str,
        resource_arn: str,
        justification: str,
        approver: str,
        expires_at: str
    ) -> RiskAcceptance:
        """Creates and registers a new formal risk acceptance."""
        if not justification or len(justification.strip()) < 10:
            raise ValueError("Risk acceptance requires a comprehensive justification of at least 10 characters.")

        # Expiration must be valid future date
        try:
            clean = expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp_dt <= now:
                raise ValueError("Risk acceptance expiration must be in the future.")
        except Exception as e:
            if isinstance(e, ValueError) and "future" in str(e):
                raise
            raise ValueError(f"Invalid expiration timestamp: {expires_at}")

        acceptance_id = f"RA-{uuid.uuid4().hex[:8]}"
        accepted_at = datetime.now(timezone.utc).isoformat()

        record = RiskAcceptance(
            acceptance_id=acceptance_id,
            finding_id=finding_id,
            resource_arn=resource_arn,
            justification=justification.strip(),
            approver=approver.strip(),
            accepted_at=accepted_at,
            expires_at=expires_at,
            status="ACTIVE"
        )

        conn = get_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO risk_acceptances (
                        acceptance_id, finding_id, resource_arn, justification,
                        approver, accepted_at, expires_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.acceptance_id,
                        record.finding_id,
                        record.resource_arn,
                        record.justification,
                        record.approver,
                        record.accepted_at,
                        record.expires_at,
                        record.status
                    )
                )
        finally:
            conn.close()

        try:
            from backend.audit import log_event
            log_event(
                "RISK_ACCEPTED",
                {
                    "acceptance_id": acceptance_id,
                    "finding_id": finding_id,
                    "resource_arn": resource_arn,
                    "approver": approver,
                    "expires_at": expires_at
                }
            )
        except Exception:
            pass

        return record

    def get_active_acceptance(self, finding_id: str = None, resource_arn: str = None) -> Optional[RiskAcceptance]:
        """
        Retrieves active risk acceptance, automatically transitioning to EXPIRED if past due.
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM risk_acceptances WHERE status = 'ACTIVE' AND ("
            params = []
            conditions = []
            if finding_id:
                conditions.append("finding_id = ?")
                params.append(finding_id)
            if resource_arn:
                conditions.append("resource_arn = ?")
                params.append(resource_arn)
            if not conditions:
                return None

            query += " OR ".join(conditions) + ")"
            cursor.execute(query, params)
            row = cursor.fetchone()
            if not row:
                return None

            acceptance = RiskAcceptance(*row)

            # Check expiration
            clean = acceptance.expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            if now > exp_dt:
                with conn:
                    conn.execute(
                        "UPDATE risk_acceptances SET status = 'EXPIRED' WHERE acceptance_id = ?",
                        (acceptance.acceptance_id,)
                    )
                acceptance.status = "EXPIRED"
                return None

            return acceptance
        finally:
            conn.close()

    def revoke_acceptance(self, acceptance_id: str, revoker: str = "security-admin") -> bool:
        """Revokes an active risk acceptance."""
        conn = get_connection(self.db_path)
        try:
            with conn:
                res = conn.execute(
                    "UPDATE risk_acceptances SET status = 'REVOKED' WHERE acceptance_id = ? AND status = 'ACTIVE'",
                    (acceptance_id,)
                )
                if res.rowcount > 0:
                    try:
                        from backend.audit import log_event
                        log_event("RISK_ACCEPTANCE_REVOKED", {"acceptance_id": acceptance_id, "revoker": revoker})
                    except Exception:
                        pass
                    return True
                return False
        finally:
            conn.close()
