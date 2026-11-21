# ExposureFence — Developer Onboarding & Local Development Guide

Welcome to the ExposureFence engineering repository. This guide walks you through setting up, inspecting, running, testing, and extending ExposureFence in a local, zero-cost, offline development environment.

---

## 1. Zero-Cost & Offline-First Principles

ExposureFence is built on two engineering guarantees:
1. **Zero Out-of-Pocket Cost:** You do NOT need an active AWS account, paid API keys, credit cards, or external SaaS subscriptions to run, test, or contribute to ExposureFence.
2. **Zero Inbound/Outbound Cloud Mutations:** All tests, rule evaluations, and demonstration pipelines execute against deterministic, cryptographically signed local fixtures.

---

## 2. Directory Layout & Architecture Map

```text
ExposureFence/
├── agent/                         # Amazon Bedrock AgentCore client and inline tools
│   ├── agentcore_client.py        # 12-step Converse stream handoff loop & dispatcher
│   ├── deploy.py                  # Managed harness deployment configuration
│   ├── inline_tools.py            # Three inline tool definitions (schemas & parameters)
│   ├── invoke.py                  # Agent invocation entrypoint
│   └── prompts.py                 # System prompts, role definitions, and guidelines
│
├── backend/                       # Core governance and security engine
│   ├── adaptive/                  # ASIVE continuous adaptive evolution engine (12 modules)
│   ├── compliance/                # CIS, NIST, MITRE, and OWASP compliance mapping
│   ├── connectors/                # Read-only AWS connectors (S3, EC2 Security Groups, IAM)
│   ├── evidence/                  # RFC 8785 evidence engine, repository, and verification
│   ├── governance/                # Auto-approval policy, proof chains, and dossiers
│   ├── graph/                     # Asset graph, multi-hop BFS attack path traversal
│   ├── intelligence/              # Multi-source finding normalizer (Security Hub, Config, Prowler)
│   ├── rbac/                      # Role-based access control and session management
│   ├── risk/                      # Contextual risk engine and multi-factor scoring
│   ├── rules/                     # Declarative rules engine and safe in-tree YAML parser
│   ├── audit.py                   # SHA-256 tamper-evident hash-chained audit logging
│   ├── dispatcher.py              # Server-side tool execution dispatcher & allowlist
│   ├── evaluate.py                # Security scorecard evaluation runner (R01-R07 & T01-T07)
│   └── server.py                  # Local Python HTTP server (127.0.0.1:8000)
│
├── dashboard/                     # Local Security Operations Console (Vanilla JS, 13 tabs)
│   ├── index.html                 # Single-page console layout
│   ├── app.js                     # Dashboard interaction, rendering, and API binding
│   └── styles.css                 # Dark-mode security operations styling
│
├── docs/                          # Architecture specifications, threat models, and reports
├── mock_data/                     # Synthetic AWS infrastructure fixtures with SHA-256 hashes
├── rules/                         # Declarative security rules (rules.yaml)
├── scripts/                       # Demonstration pipelines (Success, Failure, End-to-End)
└── tests/                         # Comprehensive test harness
    ├── offline/                   # 244 deterministic offline unit and integration tests
    └── live/                      # Live AWS infrastructure tests (requires explicit opt-in)
```

---

## 3. Local Environment Setup

### System Requirements
- Python 3.10 through 3.15 (standard CPython).
- Supported OS: Linux (Ubuntu, Debian, Fedora), macOS, Windows 10/11 (PowerShell or WSL2).
- Git.

### Step 1: Clone the Repository
```bash
git clone https://github.com/NAENSTUDIOS/ExposureFence.git
cd ExposureFence
```

### Step 2: Create a Virtual Environment
**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Configuration & Environment Variables

Copy the template configuration file:
```bash
cp .env.example .env
```

### Core Configuration Variables
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `EXPOSUREFENCE_DATA_MODE` | `mock` | `mock` uses local synthetic fixtures; `aws` uses read-only cloud inspection. |
| `HOST` | `127.0.0.1` | Local IP binding. Bound strictly to localhost for security. |
| `PORT` | `8000` | Local HTTP port for the Security Operations Console. |
| `APPROVER_USERNAME` | `admin` | Security officer identity for dashboard authentication. |
| `APPROVER_PASSWORD_HASH` | *Empty* | Bcrypt password hash for dashboard login. |
| `AWS_DEFAULT_REGION` | `us-east-1` | AWS region for connector configuration. |

### Generating the Admin Password Hash
To access the local Security Operations Console, generate a Bcrypt hash for your desired password:
```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'YourSecurePasswordHere', bcrypt.gensalt()).decode())"
```
Paste the generated hash into `APPROVER_PASSWORD_HASH` in `.env`.

---

## 5. Running the Local Security Console

Start the backend server:
```bash
python -m backend.server
```
Open your browser and navigate to:
```text
http://127.0.0.1:8000
```
Log in using:
- **Username:** `admin` (or your configured `APPROVER_USERNAME`)
- **Password:** The password you used when generating the Bcrypt hash.

---

## 6. Running Tests & Evaluations

### 1. Execute Complete Offline Test Suite (244 Tests)
Runs in ~10 seconds locally:
```bash
python -m pytest tests/offline backend/test_database.py -q
```

### 2. Run the Security Scorecard Evaluation
```bash
python -m backend.evaluate
```
This runs the 7 declarative security rules (R01–R07) and 7 adversarial red-team attack vectors (T01–T07), verifying a 100% security score.

### 3. Run the End-to-End Portfolio Pipeline
```bash
python scripts/demo_pipeline.py
```

### 4. Run Demonstration Scenarios A & B
- **Scenario A (Successful Verification & Merkle Dossier Sealing):**
  ```bash
  python scripts/demo_success_scenario.py
  ```
- **Scenario B (Failed Remediation & Drift Catching):**
  ```bash
  python scripts/demo_failure_scenario.py
  ```

---

## 7. Troubleshooting & FAQs

### Issue: `ModuleNotFoundError: No module named 'rfc8785'`
**Solution:** Ensure your virtual environment is active and run `pip install -r requirements.txt`.

### Issue: `PermissionError` when logging into the dashboard
**Solution:** Ensure `APPROVER_PASSWORD_HASH` is populated in your `.env` file with a valid Bcrypt hash generated using the Python command above.

### Issue: `Port 8000 already in use`
**Solution:** Update `PORT=8080` in `.env` and access `http://127.0.0.1:8080`.

---

## 8. Architectural Invariants for Contributors

When authoring new modules or tests:
1. **Never make live cloud writes:** Connectors must remain read-only (`Describe*`, `Get*`, `List*`).
2. **Never allow AI self-approval:** Proposal lifecycle state transitions to `APPROVED` or `AUTO_APPROVED_CONDITIONAL` require human approvers or the deterministic policy engine.
3. **Preserve RFC 8785 hashing:** All evidence payloads must use deterministic JSON canonicalization before SHA-256 digesting.
4. **Fast, deterministic tests:** Unit tests must execute in under 15 seconds without internet dependencies.
