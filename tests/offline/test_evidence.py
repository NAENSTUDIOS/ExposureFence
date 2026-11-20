from scoring.evidence import evidence_exists


def test_valid_evidence():
    assert evidence_exists("EV-S3-001")


def test_invalid_evidence():
    assert not evidence_exists("INVALID-ID")
