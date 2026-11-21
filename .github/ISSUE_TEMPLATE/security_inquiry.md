---
name: Security Inquiry
about: Non-vulnerability security questions, threat model clarifications, or policy inquiries
title: "[SECURITY INQUIRY] "
labels: security
assignees: ''
---

> **IMPORTANT:** If you are reporting a suspected security vulnerability or governance bypass, **DO NOT SUBMIT THIS PUBLIC ISSUE.** Please follow our private disclosure process in [SECURITY.md](https://github.com/NAENSTUDIOS/ExposureFence/blob/main/SECURITY.md) or email `security@naenstudios.com`.

## Inquiry Summary
A clear summary of your security inquiry or threat model question.

## Relevant Subsystems
- [ ] Declarative Rules Engine (`rules/rules.yaml`)
- [ ] Evidence Ledger & RFC 8785 Canonicalization (`backend/evidence/`)
- [ ] Bedrock AgentCore Tool Dispatcher (`backend/dispatcher.py`)
- [ ] 90% Automated Remediation Approval Policy (`backend/governance/auto_approval.py`)
- [ ] ASIVE Adaptive Intelligence Sandbox (`backend/adaptive/`)
- [ ] Tamper-Evident Audit Ledger (`backend/audit.py`)

## Question Details
Please describe the scenario, theoretical boundary concern, or compliance question.
