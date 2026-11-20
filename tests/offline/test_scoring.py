from scoring.rubric import calculate_score


def test_s3_public():
    result = calculate_score("S3_PUBLIC")

    assert result["score"] == 90
    assert result["severity"] == "CRITICAL"


def test_ssh_public():
    result = calculate_score("SSH_PUBLIC")

    assert result["score"] == 80
    assert result["severity"] == "HIGH"


def test_unknown():
    result = calculate_score("UNKNOWN")

    assert result["score"] == 0