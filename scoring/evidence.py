EVIDENCE_REGISTRY = {
    "EV-S3-001": "Public S3 bucket evidence",
    "EV-S3-002": "Private S3 bucket evidence",
    "EV-SG-001": "Open SSH security group evidence",
    "EV-SG-002": "Restricted security group evidence"
}


def evidence_exists(evidence_id: str) -> bool:
    return evidence_id in EVIDENCE_REGISTRY


def get_evidence(evidence_id: str):
    return EVIDENCE_REGISTRY.get(evidence_id)