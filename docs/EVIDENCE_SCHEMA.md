# ExposureFence — Evidence Data Contract Specification (v1.0.0)

**Schema Version:** `1.0.0`  
**Standard:** RFC 8785 (JSON Canonicalization Scheme) & SHA-256 Digest Standard  
**Package:** `backend.evidence.schema`

---

## 1. Top-Level Field Specification

```json
{
  "evidence_id": "EV-AWS-S3-my-bucket-7adc573c",
  "schema_version": "1.0.0",
  "evidence_type": "CONFIGURATION_SNAPSHOT",

  "source_mode": "AWS_READ_ONLY",
  "source_provider": "AWS",
  "source_service": "s3",
  "source_type": "AWS::S3::Bucket",
  "collector_name": "ExposureFenceAWSReadOnlyCollector",
  "collector_version": "1.0.0",

  "resource_id": "my-bucket",
  "resource_type": "AWS::S3::Bucket",
  "account_id": "123456789012",
  "region": "us-east-1",
  "resource_arn": "arn:aws:s3:::my-bucket",

  "collected_at": "2026-11-21T00:15:00Z",
  "observed_at": "2026-11-21T00:15:00Z",
  "source_created_at": null,
  "source_updated_at": null,

  "provenance": {
    "source_reference": "aws://123456789012/us-east-1/s3/GetBucketPublicAccessBlock",
    "collection_activity_id": "ACT-AWS-S3-9f8e7d6c",
    "collector_identity": "ExposureFenceAWSReadOnlyCollector/1.0",
    "source_payload_digest": null,
    "parent_evidence_ids": []
  },

  "raw_evidence": { ... },
  "normalized_evidence": { ... },
  "payload_sha256": "4a7d...3b21",

  "canonicalization_algorithm": "RFC-8785",
  "canonicalization_version": "1.0",
  "hash_algorithm": "SHA-256",
  "previous_record_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "record_hash": "e3b0...b855",

  "collection_status": "COLLECTED",
  "integrity_status": "VERIFIED",
  "freshness_status": "FRESH",
  "assessment_status": "EXPOSURE_DETECTED"
}
```

---

## 2. Separate Verification State Dimensions

ExposureFence strictly decouples evidence integrity from vulnerability severity and freshness:

### 1. Collection Status (`collection_status`)
- `COLLECTED`: All requested metadata fields collected successfully.
- `PARTIAL`: Some optional metadata failed to collect due to permissions or unconfigured settings.
- `ERROR`: Collector encountered a fatal client or network error.

### 2. Integrity Status (`integrity_status`)
- `VERIFIED`: Recomputed RFC 8785 SHA-256 digest exactly matches `payload_sha256`, and record hash is intact.
- `INTEGRITY_MISMATCH`: Recomputed digest does NOT match; evidence representation was modified or corrupted.
- `UNVERIFIABLE`: Record is missing or required cryptographic metadata is absent.

### 3. Freshness Status (`freshness_status`)
- `STATIC_FIXTURE`: Synthetic local mock data fixture (permanently valid for offline development and tests).
- `FRESH`: Live AWS observation within configured policy threshold (e.g. < 1 hour).
- `STALE`: Live AWS observation older than policy threshold (cannot be used to authorize new remediations).
- `UNKNOWN`: Timestamp missing or unparseable.

### 4. Assessment Status (`assessment_status`)
- `EXPOSURE_DETECTED`: The evidence proves an active security exposure (e.g. public bucket or open SSH).
- `NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE`: The evidence proves the resource configuration is restricted.
- `NOT_ASSESSED`: Raw snapshot collected without running security rule evaluation.
- `ERROR`: Rule evaluation failed.

> **Engineering Principle:** Authentic evidence can prove an insecure state. Therefore, an insecure public S3 bucket correctly has `integrity_status = VERIFIED` and `assessment_status = EXPOSURE_DETECTED`.

---

## 3. SQLite Database Schema

```sql
CREATE TABLE evidence_records (
    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT UNIQUE NOT NULL,
    schema_version TEXT NOT NULL,
    source_mode TEXT NOT NULL,
    source_provider TEXT NOT NULL,
    source_service TEXT NOT NULL,
    source_type TEXT NOT NULL,
    collector_name TEXT NOT NULL,
    collector_version TEXT NOT NULL,
    account_id TEXT,
    region TEXT,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_arn TEXT,
    collected_at TEXT NOT NULL,
    observed_at TEXT,
    source_created_at TEXT,
    source_updated_at TEXT,
    canonicalization_algorithm TEXT NOT NULL,
    canonicalization_version TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    previous_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    collection_status TEXT NOT NULL,
    integrity_status TEXT NOT NULL,
    freshness_status TEXT NOT NULL,
    assessment_status TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE evidence_relationships (
    relationship_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    bound_payload_sha256 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence_records(evidence_id)
);
```
