def calculate_score(finding_type):

    score = 0

    if finding_type == "S3_PUBLIC":
        score = 90

    elif finding_type == "SSH_PUBLIC":
        score = 80

    if score >= 90:
        severity = "CRITICAL"
    elif score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "NO ISSUE IDENTIFIED IN SUPPLIED EVIDENCE"

    return {
        "score": score,
        "severity": severity
    }