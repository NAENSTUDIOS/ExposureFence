from scoring.rubric import calculate_score
from scoring.evidence import evidence_exists


def analyze_s3(record):
    evidence_id = record.get("evidence_id")
    if not evidence_id or not evidence_exists(evidence_id):
        return None

    if record.get("public_access"):
        return {
            "resource_id": record["resource_id"],
            "evidence_id": record["evidence_id"],
            "finding": "S3_PUBLIC",
            **calculate_score("S3_PUBLIC")
        }

    return None


def analyze_security_group(record):
    evidence_id = record.get("evidence_id")
    if not evidence_id or not evidence_exists(evidence_id):
        return None

    if (
        record.get("port") == 22
        and record.get("cidr") == "0.0.0.0/0"
    ):
        return {
            "resource_id": record["sg_id"],
            "evidence_id": record["evidence_id"],
            "finding": "SSH_PUBLIC",
            **calculate_score("SSH_PUBLIC")
        }

    return None
