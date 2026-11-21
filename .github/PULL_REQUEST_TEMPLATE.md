## Summary of Changes
Provide a clear, high-level summary of what this pull request introduces or resolves.

## Architectural Invariants Checklist
Before submitting, please confirm that your changes strictly respect our core invariants:
- [ ] **Zero Cost Invariant:** All tests run offline against local fixtures without paid cloud services.
- [ ] **Zero Mutation Invariant:** No write, update, create, or delete actions added to cloud connectors.
- [ ] **No AI Self-Approval:** AI agents (`ai_agent`, `bedrock_agent`) remain barred from approving proposals.
- [ ] **RFC 8785 Compliance:** Any new evidence types implement canonical JSON serialization.
- [ ] **Deterministic Tests:** Added or modified offline unit tests in `tests/offline/`.

## Local Verification Commands & Output
Please paste the output of your local test and security evaluation runs:
```bash
# 1. Test suite execution
python -m pytest tests/offline backend/test_database.py -q

# 2. Security scorecard verification
python -m backend.evaluate
```

## Related Issues
Fixes # (or closes #)
