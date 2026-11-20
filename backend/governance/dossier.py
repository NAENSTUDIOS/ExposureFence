"""
ExposureFence — Cryptographic Evidence Dossier Generator
Packages all investigation artifacts into a sealed, exportable, tamper-evident dossier
with root SHA-256 integrity verification.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict


class EvidenceDossierGenerator:
    """Generates and verifies sealed cryptographic evidence dossiers."""

    @staticmethod
    def generate_dossier(
        proof_chain_record: Dict[str, Any],
        finding_details: Dict[str, Any],
        evidence_record: Dict[str, Any],
        rule_evaluation: Dict[str, Any],
        risk_score_details: Dict[str, Any],
        remediation_plan: Dict[str, Any],
        verification_report: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Assembles a comprehensive, verifiable investigation dossier.
        """
        generated_at = datetime.now(timezone.utc).isoformat()

        dossier_body = {
            "dossier_version": "1.0.0",
            "generated_at": generated_at,
            "chain_id": proof_chain_record.get("chain_id"),
            "target": {
                "finding_id": finding_details.get("finding_id"),
                "resource_arn": finding_details.get("resource_arn"),
                "severity": finding_details.get("severity")
            },
            "evidence": {
                "evidence_id": evidence_record.get("evidence_id"),
                "payload_sha256": evidence_record.get("payload_sha256"),
                "integrity_status": evidence_record.get("integrity_status"),
                "provenance": evidence_record.get("provenance")
            },
            "rule_evaluation": {
                "rule_id": rule_evaluation.get("rule_id"),
                "status": rule_evaluation.get("status"),
                "violations_count": len(rule_evaluation.get("violations", []))
            },
            "risk_assessment": {
                "overall_score": risk_score_details.get("overall_score"),
                "severity": risk_score_details.get("severity"),
                "breakdown": risk_score_details.get("component_breakdown")
            },
            "governance": {
                "remediation_action": remediation_plan.get("action_type"),
                "remediation_plan_digest": remediation_plan.get("plan_digest"),
                "rollback_plan_digest": remediation_plan.get("rollback_plan", {}).get("rollback_digest"),
                "approver": proof_chain_record.get("approver_identity"),
                "approval_timestamp": proof_chain_record.get("approval_timestamp"),
                "lifecycle_state": proof_chain_record.get("lifecycle_state")
            },
            "verification": verification_report or {"status": "PENDING"}
        }

        canonical_bytes = json.dumps(dossier_body, sort_keys=True).encode("utf-8")
        dossier_root_hash = hashlib.sha256(canonical_bytes).hexdigest()

        return {
            "dossier_root_hash": dossier_root_hash,
            "dossier": dossier_body
        }

    @staticmethod
    def verify_dossier(dossier_package: Dict[str, Any]) -> bool:
        """Verifies that the dossier root hash matches the canonical dossier contents."""
        expected_hash = dossier_package.get("dossier_root_hash")
        body = dossier_package.get("dossier")
        if not expected_hash or not body:
            return False

        canonical_bytes = json.dumps(body, sort_keys=True).encode("utf-8")
        computed = hashlib.sha256(canonical_bytes).hexdigest()
        return computed == expected_hash
