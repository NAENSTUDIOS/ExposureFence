"""
ExposureFence — Security Operations Inline Tools
Implements the 3 approved tools under strict governance:
- read_mock_s3: Accesses S3 configurations, generates/verifies EvidenceRecords, evaluates YAML rules.
- read_mock_security_groups: Accesses SG configurations, generates/verifies EvidenceRecords, evaluates YAML rules.
- propose_fix: Validates finding, checks evidence integrity/freshness, verifies rule violation, and creates evidence-bound PENDING proposal.
"""

import json
import os
from typing import Any, Dict, List, Optional

from backend.integrity import verify_fixture_integrity
from backend.proposals import create_proposal

APPROVED_REMEDIATIONS = {
    "F-S3-001": {
        "resource_id": "bucket-public-001",
        "evidence_id": "EV-S3-001",
        "rule_id": "SEC-S3-001",
        "remediation": "Enable S3 Block Public Access and remove public bucket policy"
    },
    "F-SG-001": {
        "resource_id": "sg-001",
        "evidence_id": "EV-SG-001",
        "rule_id": "SEC-EC2-001",
        "remediation": "Restrict port 22 ingress to authorized bastion CIDR and revoke 0.0.0.0/0"
    }
}


def read_mock_s3(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Reads approved synthetic AWS S3 bucket configurations.
    Verifies fixture SHA-256, synchronizes with the Evidence Ledger, and evaluates YAML rules.
    """
    path = "mock_data/s3_buckets.json"
    if not verify_fixture_integrity(path):
        raise ValueError("Fixture integrity violation")

    # Ingest / retrieve from Evidence Ledger
    from backend.evidence.service import EvidenceService
    from backend.rules.service import RulesEngine

    svc = EvidenceService(db_path=db_path)
    engine = RulesEngine()

    with open(path, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    enriched_items = []
    for item in raw_items:
        ev_id = item.get("evidence_id")
        rec = svc.get_evidence(ev_id) if ev_id else None
        if not rec and ev_id:
            try:
                svc.ingest_mock_data()
                rec = svc.get_evidence(ev_id)
            except Exception:
                pass

        # Build enriched record preserving exact original keys
        enriched = dict(item)
        if rec:
            enriched["payload_sha256"] = rec.payload_sha256
            enriched["integrity_status"] = rec.integrity_status
            enriched["freshness_status"] = rec.freshness_status
            enriched["assessment_status"] = rec.assessment_status

            # Evaluate applicable declarative rules
            rule_res = engine.evaluate_rule("SEC-S3-001", evidence=rec)
            enriched["rule_evaluation"] = {
                "rule_id": rule_res.rule_id,
                "status": rule_res.status,
                "severity": rule_res.severity,
                "violations": rule_res.violations
            }
        else:
            enriched["integrity_status"] = "VERIFIED"
            enriched["freshness_status"] = "STATIC_FIXTURE"

        enriched_items.append(enriched)

    return enriched_items


def read_mock_security_groups(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Reads approved synthetic AWS EC2 security-group ingress rules.
    Verifies fixture SHA-256, synchronizes with the Evidence Ledger, and evaluates YAML rules.
    """
    path = "mock_data/security_groups.json"
    if not verify_fixture_integrity(path):
        raise ValueError("Fixture integrity violation")

    from backend.evidence.service import EvidenceService
    from backend.rules.service import RulesEngine

    svc = EvidenceService(db_path=db_path)
    engine = RulesEngine()

    with open(path, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    enriched_items = []
    for item in raw_items:
        ev_id = item.get("evidence_id")
        rec = svc.get_evidence(ev_id) if ev_id else None
        if not rec and ev_id:
            try:
                svc.ingest_mock_data()
                rec = svc.get_evidence(ev_id)
            except Exception:
                pass

        enriched = dict(item)
        if rec:
            enriched["payload_sha256"] = rec.payload_sha256
            enriched["integrity_status"] = rec.integrity_status
            enriched["freshness_status"] = rec.freshness_status
            enriched["assessment_status"] = rec.assessment_status

            rule_res = engine.evaluate_rule("SEC-EC2-001", evidence=rec)
            enriched["rule_evaluation"] = {
                "rule_id": rule_res.rule_id,
                "status": rule_res.status,
                "severity": rule_res.severity,
                "violations": rule_res.violations
            }
        else:
            enriched["integrity_status"] = "VERIFIED"
            enriched["freshness_status"] = "STATIC_FIXTURE"

        enriched_items.append(enriched)

    return enriched_items


def propose_fix(finding_id: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Submits an evidence-bound remediation fix proposal for human review.
    Enforces evidence verification, freshness, and rule-violation confirmation.
    Strictly forbids direct automated execution.
    """
    if finding_id not in APPROVED_REMEDIATIONS:
        raise ValueError(f"Invalid finding ID: {finding_id}")

    mapping = APPROVED_REMEDIATIONS[finding_id]
    evidence_id = mapping.get("evidence_id") or ("EV-S3-001" if "S3" in finding_id else "EV-SG-001")
    rule_id = mapping.get("rule_id") or ("SEC-S3-001" if "S3" in finding_id else "SEC-EC2-001")

    # 1. Resolve and verify evidence record from the ledger
    from backend.evidence.service import EvidenceService
    from backend.rules.service import RulesEngine

    svc = EvidenceService(db_path=db_path)
    engine = RulesEngine()

    ev = svc.get_evidence(evidence_id)
    if not ev:
        # Fallback to check if mock data needs initial ingestion
        try:
            svc.ingest_mock_data()
            ev = svc.get_evidence(evidence_id)
        except Exception:
            pass

    if not ev:
        raise ValueError(f"Cannot propose fix: Evidence record '{evidence_id}' does not exist in evidence ledger")

    # 2. Check evidence integrity
    if ev.integrity_status == "INTEGRITY_MISMATCH":
        raise ValueError(f"Cannot propose fix: Evidence '{evidence_id}' has an integrity mismatch (tampered payload)")

    # 3. Check evidence freshness (blocks STALE evidence)
    if ev.freshness_status == "STALE":
        raise ValueError(f"Cannot propose fix: Evidence '{evidence_id}' is STALE and cannot support new proposals")

    # 4. Verify rule evaluation confirms the exposure violation
    rule_res = engine.evaluate_rule(rule_id, evidence=ev)
    if rule_res.status == "PASS":
        raise ValueError(f"Cannot propose fix: Rule '{rule_id}' passed for evidence '{evidence_id}' — no violation detected to fix")

    # 5. Create Advanced Evidence-Bound Proposal
    proposal = create_proposal(
        finding_id=finding_id,
        resource_id=mapping["resource_id"],
        remediation=mapping["remediation"],
        evidence_id=ev.evidence_id,
        evidence_payload_digest=ev.payload_sha256,
        rule_id=rule_id,
        rule_version="1.0.0",
        db_path=db_path,
    )

    return {
        "proposal_id": proposal["proposal_id"],
        "finding_id": finding_id,
        "resource_id": mapping["resource_id"],
        "suggested_remediation": mapping["remediation"],
        "status": "PENDING",
        "evidence_id": ev.evidence_id,
        "evidence_payload_digest": ev.payload_sha256,
        "rule_id": rule_id,
        "rule_evaluation_status": "VIOLATION_CONFIRMED",
        "created_at": proposal.get("created_at"),
        "expires_at": proposal.get("expires_at"),
    }
