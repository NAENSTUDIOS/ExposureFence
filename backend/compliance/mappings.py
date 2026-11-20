"""
ExposureFence — Compliance Framework Control Mappings
Codifies traceable mappings for CIS AWS Benchmark v3.0, NIST CSF 2.0, MITRE ATT&CK Cloud,
AWS Well-Architected Framework, and OWASP Top 10 for LLM Applications (2025).
"""

from typing import Any, Dict, List


FRAMEWORK_CONTROLS = [
    # 1. CIS AWS Foundations Benchmark v3.0
    {
        "framework": "CIS-AWS-v3.0",
        "control_id": "CIS-1.16",
        "title": "Ensure IAM policies that allow full '*:*' administrative privileges are restricted",
        "description": "IAM policies must not grant wildcard administrative permissions to untrusted workload roles.",
        "related_rules": ["SEC-IAM-001", "R02"],
        "target_service": "iam"
    },
    {
        "framework": "CIS-AWS-v3.0",
        "control_id": "CIS-2.1.5",
        "title": "Ensure that S3 Buckets are configured with 'Block Public Access'",
        "description": "Amazon S3 Block Public Access must be enabled at the bucket level to prevent unauthorized exposure.",
        "related_rules": ["SEC-S3-001", "R01"],
        "target_service": "s3"
    },
    {
        "framework": "CIS-AWS-v3.0",
        "control_id": "CIS-5.2",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote management ports (22, 3389)",
        "description": "Security groups must not permit unrestricted inbound connections on SSH or RDP.",
        "related_rules": ["SEC-EC2-001", "R01"],
        "target_service": "ec2"
    },

    # 2. NIST Cybersecurity Framework 2.0
    {
        "framework": "NIST-CSF-2.0",
        "control_id": "PR.AC-3",
        "title": "Access permissions and authorizations are managed",
        "description": "Access privileges are restricted in accordance with least privilege and separation of duties.",
        "related_rules": ["SEC-S3-001", "SEC-IAM-001", "R05"],
        "target_service": "all"
    },
    {
        "framework": "NIST-CSF-2.0",
        "control_id": "PR.AC-5",
        "title": "Network integrity is protected and perimeter boundaries are enforced",
        "description": "Network boundaries separate internal resources from public internet traffic.",
        "related_rules": ["SEC-EC2-001"],
        "target_service": "ec2"
    },
    {
        "framework": "NIST-CSF-2.0",
        "control_id": "PR.DS-1",
        "title": "Data-at-rest is protected against unauthorized disclosure",
        "description": "Storage resources are safeguarded against public read and write access.",
        "related_rules": ["SEC-S3-001"],
        "target_service": "s3"
    },

    # 3. MITRE ATT&CK for Cloud Matrix
    {
        "framework": "MITRE-ATTACK",
        "control_id": "T1530",
        "title": "Data from Cloud Storage Object",
        "description": "Adversaries may access data from cloud storage buckets that are misconfigured for public read.",
        "related_rules": ["SEC-S3-001"],
        "target_service": "s3"
    },
    {
        "framework": "MITRE-ATTACK",
        "control_id": "T1078.004",
        "title": "Valid Accounts: Cloud Accounts",
        "description": "Adversaries obtain credentials to gain access via public ingress points.",
        "related_rules": ["SEC-EC2-001"],
        "target_service": "ec2"
    },
    {
        "framework": "MITRE-ATTACK",
        "control_id": "T1098",
        "title": "Account Manipulation: Additional Cloud Roles",
        "description": "Adversaries manipulate cloud role attachments to escalate privileges.",
        "related_rules": ["SEC-IAM-001"],
        "target_service": "iam"
    },

    # 4. AWS Well-Architected Framework (Security Pillar)
    {
        "framework": "AWS-WAF-Security",
        "control_id": "SEC-02",
        "title": "Secure Identities and Permissions",
        "description": "Rely on centralized identity and least-privilege permissions.",
        "related_rules": ["SEC-IAM-001", "R05"],
        "target_service": "iam"
    },
    {
        "framework": "AWS-WAF-Security",
        "control_id": "SEC-06",
        "title": "Protect Data at Rest and in Transit",
        "description": "Prevent accidental public exposure of data stores.",
        "related_rules": ["SEC-S3-001"],
        "target_service": "s3"
    },

    # 5. OWASP Top 10 for LLM Applications (2025)
    {
        "framework": "OWASP-LLM-2025",
        "control_id": "LLM01",
        "title": "Prompt Injection Defense",
        "description": "Direct and indirect prompt injections must be neutralized by passive input handling and tool dispatcher boundaries.",
        "related_rules": ["R06", "T01", "T06"],
        "target_service": "agent"
    },
    {
        "framework": "OWASP-LLM-2025",
        "control_id": "LLM06",
        "title": "Excessive Agency Prevention",
        "description": "The AI model must not possess write/delete permissions and cannot approve its own remediation proposals.",
        "related_rules": ["R02", "R03", "R04", "R05", "T02", "T05"],
        "target_service": "agent"
    }
]
