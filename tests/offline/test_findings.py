from backend.findings import (
    analyze_s3,
    analyze_security_group
)


def test_public_bucket():

    result = analyze_s3(
        {
            "resource_id": "bucket-public-001",
            "public_access": True,
            "evidence_id": "EV-S3-001"
        }
    )

    assert result["severity"] == "CRITICAL"


def test_public_ssh():

    result = analyze_security_group(
        {
            "sg_id": "sg-001",
            "port": 22,
            "cidr": "0.0.0.0/0",
            "evidence_id": "EV-SG-001"
        }
    )

    assert result["severity"] == "HIGH"