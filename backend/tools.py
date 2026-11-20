import json
from backend.integrity import verify_fixture_integrity
from backend.proposals import create_proposal

APPROVED_REMEDIATIONS = {
    "F-S3-001": {
        "resource_id": "bucket-public-001",
        "remediation": "Enable S3 Block Public Access and remove public bucket policy"
    },
    "F-SG-001": {
        "resource_id": "sg-001",
        "remediation": "Restrict port 22 ingress to authorized bastion CIDR and revoke 0.0.0.0/0"
    }
}


def read_mock_s3():
    path = "mock_data/s3_buckets.json"
    if not verify_fixture_integrity(path):
        raise ValueError("Fixture integrity violation")

    with open(path) as f:
        return json.load(f)


def read_mock_security_groups():
    path = "mock_data/security_groups.json"
    if not verify_fixture_integrity(path):
        raise ValueError("Fixture integrity violation")

    with open(path) as f:
        return json.load(f)


def propose_fix(finding_id: str):
    if finding_id not in APPROVED_REMEDIATIONS:
        raise ValueError(f"Invalid finding ID: {finding_id}")

    mapping = APPROVED_REMEDIATIONS[finding_id]
    evidence_id = "EV-S3-001" if "S3" in finding_id else "EV-SG-001"
    proposal = create_proposal(
        finding_id=finding_id,
        resource_id=mapping["resource_id"],
        remediation=mapping["remediation"],
        evidence_id=evidence_id
    )

    return {
        "proposal_id": proposal["proposal_id"],
        "finding_id": finding_id,
        "resource_id": mapping["resource_id"],
        "suggested_remediation": mapping["remediation"],
        "status": "PENDING"
    }
