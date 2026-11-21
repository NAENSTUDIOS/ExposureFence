# Security Policy & Vulnerability Disclosure

**Project:** ExposureFence  
**Maintainer:** NAENSTUDIOS  
**Security Contact:** `security@naenstudios.com`  

ExposureFence is an evidence-driven cloud security governance platform. We take security vulnerabilities within our platform, governance state machine, and proof chain with utmost seriousness.

---

## 1. Supported Versions

Security updates and patches are actively applied to the following release branches:

| Version Branch | Supported | Description |
| :--- | :--- | :--- |
| `feature/top-tier-platform-evolution` | **Yes** | Active development & release candidate |
| `main` | **Yes** | Production release branch |
| `< 1.0.0-rc` | No | Legacy hackathon prototypes |

---

## 2. Reporting a Vulnerability

**Please DO NOT report security vulnerabilities via public GitHub issues, discussions, or pull requests.**

If you discover a potential security vulnerability, privilege escalation flaw, or governance bypass within ExposureFence, please report it privately:

1. **Email:** Send your report to `security@naenstudios.com`.
2. **Subject Line:** `[Vulnerability Report] ExposureFence - <Brief Summary>`
3. **Include Details:**
   - Affected file(s), class(es), or endpoint(s).
   - Step-by-step reproduction steps or minimal proof-of-concept script.
   - Threat impact assessment (e.g., prompt injection boundary escape, evidence digest forgery, approval role bypass).
   - Any suggested remediation or patch.

We will acknowledge receipt of your report within **48 hours** and provide periodic updates during technical investigation and remediation.

---

## 3. Scope of Security Research

### In-Scope Vulnerabilities
We particularly encourage research and responsible disclosure regarding:
- **Approval Gate Bypasses:** Any mechanism allowing an unauthenticated caller or `caller_role="ai_agent"` to approve proposals or execute remediation.
- **Evidence Tampering Flaws:** Any condition where an evidence payload can be modified without failing RFC 8785 SHA-256 integrity verification.
- **Prompt Injection Boundary Escapes:** Any prompt injection pattern that forces the agent to call unauthorized system tools, write to disk, or execute arbitrary shell commands.
- **Audit Hash Chain Invalidation:** Any silent break or undetected modification in `audit.jsonl` event records.
- **State Machine Corruption:** Any invalid lifecycle transition (e.g., executing a proposal without prior `APPROVED` status).

### Out-of-Scope Topics
- Vulnerabilities solely resulting from user modification of local Python code.
- Limitations of offline mock fixtures when operating strictly in `EXPOSUREFENCE_DATA_MODE=mock`.
- Denial-of-service on local development endpoints (`127.0.0.1:8000`) caused by local resource exhaustion.

---

## 4. Disclosure Timeline & Attribution

1. **Initial Review:** Within 48 hours of report submission.
2. **Remediation & Testing:** Patches will be developed in an isolated branch and validated against our offline test harness.
3. **Public Release:** Once a verified patch is landed, we will publish a security advisory in `CHANGELOG.md` and credit the reporting researcher (unless anonymity is requested).
