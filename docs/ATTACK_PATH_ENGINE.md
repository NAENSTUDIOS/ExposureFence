# ExposureFence — Cloud Asset Graph & Deterministic Attack-Path Engine

## 1. Architectural Overview

The **ExposureFence Cloud Asset Graph Engine** (`backend/graph/`) provides a deterministic, multi-hop relationship model representing cloud resources, networking pathways, IAM authorization graphs, and data assets.

Traditional vulnerability scanners analyze cloud resources in isolation (e.g., "S3 bucket is private", "Security group port 22 is open"). In contrast, real-world cloud security breaches occur through **chained multi-step attack paths**: an attacker exploits an externally exposed boundary, pivots through an intermediate workload, assumes an attached IAM role, escalates privileges, and exfiltrates data from a confidential downstream datastore.

The Graph Engine models these complex relationships to:
1. Discover end-to-end paths from public internet entrypoints to high-value assets.
2. Calculate contextual blast radius and downstream reachability.
3. Identify structural choke points where a single remediation breaks the entire attack chain.

---

## 2. Graph Schema & Relationship Topology

The graph is implemented as an in-memory directed graph (`ResourceGraph`) with forward and reverse adjacency indexing, serialization to Cytoscape.js, and export to JSON.

### 2.1 Node Types (`NodeType`)

| Node Type | Description | Key Properties |
| :--- | :--- | :--- |
| `INTERNET` | External untrusted boundary | `cidr: 0.0.0.0/0`, `untrusted: True` |
| `SECURITY_GROUP` | EC2 Security Group | `group_id`, `ingress_rules` |
| `EC2_INSTANCE` | Compute instance workload | `instance_id`, `subnet_id`, `iam_instance_profile` |
| `IAM_ROLE` | IAM Role assumed by workloads or users | `role_arn`, `trust_policy` |
| `IAM_POLICY` | Managed or inline IAM policy document | `policy_arn`, `statements` |
| `S3_BUCKET` | Object storage resource | `bucket_name`, `arn`, `classification` |
| `DATABASE` | Relational or NoSQL datastore | `db_instance_id`, `engine`, `classification` |

### 2.2 Edge Types (`EdgeType`)

| Edge Type | Direction | Semantics |
| :--- | :--- | :--- |
| `TRAFFIC_INGRESS` | `INTERNET` $\to$ `SECURITY_GROUP` | Public network ingress allowed |
| `ATTACHES_TO` | `SECURITY_GROUP` $\to$ `EC2_INSTANCE` | Network filtering applied to compute workload |
| `ASSUMES_ROLE` | `EC2_INSTANCE` $\to$ `IAM_ROLE` | Workload credential acquisition via instance profile / IMDS |
| `ATTACHES_POLICY` | `IAM_ROLE` $\to$ `IAM_POLICY` | Permissions granted to role |
| `EXFILTRATES_TO` | `IAM_POLICY` $\to$ `S3_BUCKET` | Policy authorizes data access to sensitive resource |

---

## 3. IAM Privilege Escalation Analyzer (`iam_analyzer.py`)

The IAM Analyzer evaluates policy statements to detect dangerous permissions and privilege escalation primitives:

```
[ Workload: EC2 ] ──► [ Role: SecOpsWorkerRole ]
                             │
                             ▼
                 [ Policy: AdministratorAccess ]
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
      Wildcard Rights                  Privilege Escalation
   Action: "*", Resource: "*"        iam:PassRole + ec2:RunInstances
```

### Supported Escalation Patterns

1. **`ESC-01` (Administrator Wildcard):**
   - Action matches `*` with Resource `*`.
   - Result: Full control over all cloud APIs.

2. **`ESC-02` (PassRole + EC2 RunInstances):**
   - Action contains `iam:PassRole` and `ec2:RunInstances`.
   - Result: Attacker launches compute instances attached to more privileged roles.

3. **`ESC-03` (Policy Version Creation):**
   - Action contains `iam:CreatePolicyVersion`.
   - Result: Attacker creates a new default policy version with `Allow *:*`.

4. **`ESC-04` (Role Policy Attachment):**
   - Action contains `iam:AttachRolePolicy` or `iam:PutRolePolicy`.
   - Result: Attacker directly attaches administrative policies to their role.

5. **`ESC-05` (Wildcard AssumeRole):**
   - Action contains `sts:AssumeRole` with Resource `*`.
   - Result: Attacker pivots into any role that trusts their principal.

6. **`ESC-06` (Data Exfiltration Vector):**
   - Action contains `s3:GetObject` or `s3:*` on sensitive/confidential buckets.
   - Result: Direct unauthorized exfiltration of proprietary or customer data.

---

## 4. Multi-Step Attack-Path Discovery (`attack_paths.py`)

Attack-path discovery uses **Breadth-First Search (BFS)** traversal starting from `INTERNET` entrypoints:

```
[ INTERNET ]
     │
     ▼ (TRAFFIC_INGRESS: port 22/3389 from 0.0.0.0/0)
[ sg-0123456789abcdef0 ]
     │
     ▼ (ATTACHES_TO)
[ i-0fedcba9876543210 ]
     │
     ▼ (ASSUMES_ROLE)
[ SecOpsWorkerRole ]
     │
     ▼ (ATTACHES_POLICY)
[ AdministratorAccess ]
     │
     ▼ (EXFILTRATES_TO)
[ arn:aws:s3:::confidential-prod-data ]
```

### Path Scoring & Confidence Propagation

1. **Step-Level Confidence:**
   Each edge transition has an assigned transition confidence $c_i \in (0, 1]$ based on prerequisite exploitability:
   $$\text{Confidence}_{\text{path}} = \prod_{i=1}^{k} c_i$$

2. **Total Risk Calculation:**
   Path risk integrates target criticality, step severity, and confidence:
   $$\text{Risk}_{\text{path}} = \min\left(100.0, \, \left(\text{Target Criticality} \times 0.6 + \sum \text{Step Severity} \times 0.4\right) \times \text{Confidence}_{\text{path}}\right)$$

3. **Recommended Control Extraction:**
   The engine automatically identifies the most effective mitigation to break the chain at the earliest possible hop (e.g. *"Enforce IMDSv2 and remove AdministratorAccess wildcard"*).

---

## 5. Blast-Radius & Choke-Point Analysis (`blast_radius.py`)

Given any compromised workload or identity, the **Blast Radius Engine** calculates:

1. **Downstream Reachable Nodes:** Total count and set of all graph nodes reachable via directed edges.
2. **Reachable Sensitive Targets:** Filtered subset of nodes marked with high data classification (`CRITICAL`, `CONFIDENTIAL`).
3. **Choke-Point Frequency:** Measures which intermediate nodes and edges appear most frequently across all viable attack paths:
   $$\text{Choke-Point Score}(N) = \frac{\text{Count of Paths Traversing } N}{\text{Total Active Attack Paths}}$$
   Resources with high choke-point frequency represent **optimal remediation targets**, as remediating a single choke point eliminates multiple distinct exploit vectors simultaneously.

---

## 6. End-to-End Scenario 1 Verification

Scenario 1 simulates a public EC2 instance with an administrative IAM role accessing confidential S3 data:

```python
def test_scenario_1_public_exposure_to_privileged_identity():
    # 1. Ingest multi-source intelligence findings
    # 2. Discover graph attack paths from INTERNET to S3
    # 3. Calculate multi-factor contextual risk score
    # 4. Assert Risk Score >= 85.0 (CRITICAL)
    # 5. Assert choke-point identification on SecOpsWorkerRole
```

All 6 attack-path test cases pass 100% deterministically in `tests/offline/test_graph.py` without external cloud dependencies.
