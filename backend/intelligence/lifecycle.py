"""
ExposureFence — Finding Lifecycle & Suppression Manager
Enforces deterministic finding state transitions (NEW, ACTIVE, SUPPRESSED, RESOLVED, REOPENED)
with mandatory suppression justifications, expiration validation, and audit integration.
"""

from datetime import datetime, timezone
from typing import Optional

from backend.intelligence.models import CanonicalFinding, FindingStatus


class FindingLifecycleManager:
    """Manages state transitions and suppression governance for CanonicalFindings."""

    @staticmethod
    def activate(finding: CanonicalFinding) -> CanonicalFinding:
        """Transitions finding from NEW to ACTIVE."""
        if finding.status == FindingStatus.NEW:
            finding.status = FindingStatus.ACTIVE
            finding.last_seen = datetime.now(timezone.utc).isoformat()
        return finding

    @staticmethod
    def suppress(
        finding: CanonicalFinding,
        justification: str,
        suppressed_until: str,
        approver: str = "security-admin"
    ) -> CanonicalFinding:
        """
        Suppresses an active finding with mandatory justification and expiration timestamp.
        """
        if not justification or len(justification.strip()) < 5:
            raise ValueError("Suppression requires a documented justification of at least 5 characters.")

        if not suppressed_until:
            raise ValueError("Suppression requires an explicit expiration timestamp (ISO 8601).")

        # Validate timestamp is in future
        try:
            clean = suppressed_until.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp_dt <= now:
                raise ValueError("Suppression expiration must be in the future.")
        except Exception as e:
            if isinstance(e, ValueError) and "future" in str(e):
                raise
            raise ValueError(f"Invalid suppression expiration timestamp: {suppressed_until}")

        finding.status = FindingStatus.SUPPRESSED
        finding.suppression_reason = f"[{approver}] {justification.strip()}"
        finding.suppressed_until = suppressed_until

        # Audit event
        try:
            from backend.audit import log_event
            log_event(
                "FINDING_SUPPRESSED",
                {
                    "finding_id": finding.finding_id,
                    "resource_arn": finding.resource_arn,
                    "justification": justification,
                    "suppressed_until": suppressed_until,
                    "approver": approver
                }
            )
        except Exception:
            pass

        return finding

    @staticmethod
    def evaluate_suppression_expiry(finding: CanonicalFinding) -> CanonicalFinding:
        """
        Checks if a suppressed finding has expired; if so, automatically re-activates it.
        """
        if finding.status != FindingStatus.SUPPRESSED or not finding.suppressed_until:
            return finding

        try:
            clean = finding.suppressed_until.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > exp_dt:
                finding.status = FindingStatus.ACTIVE
                finding.suppression_reason = f"[EXPIRED] Previously suppressed until {finding.suppressed_until}"
                finding.suppressed_until = None
        except Exception:
            pass

        return finding

    @staticmethod
    def resolve(finding: CanonicalFinding) -> CanonicalFinding:
        """Marks finding as resolved when verification proves mitigation."""
        finding.status = FindingStatus.RESOLVED
        finding.last_seen = datetime.now(timezone.utc).isoformat()
        return finding

    @staticmethod
    def reopen(finding: CanonicalFinding) -> CanonicalFinding:
        """Re-opens a previously resolved finding when recurrence is detected."""
        finding.status = FindingStatus.REOPENED
        finding.last_seen = datetime.now(timezone.utc).isoformat()
        return finding
