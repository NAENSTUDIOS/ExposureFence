from scoring.rubric import calculate_score


def analyze_s3(record):

    if record["public_access"]:

        return {
            "resource_id": record["resource_id"],
            "evidence_id": record["evidence_id"],
            "finding": "S3_PUBLIC",
            **calculate_score("S3_PUBLIC")
        }

    return None


def analyze_security_group(record):

    if (
        record["port"] == 22
        and record["cidr"] == "0.0.0.0/0"
    ):

        return {
            "resource_id": record["sg_id"],
            "evidence_id": record["evidence_id"],
            "finding": "SSH_PUBLIC",
            **calculate_score("SSH_PUBLIC")
        }

    return None