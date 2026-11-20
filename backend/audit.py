import json
from datetime import datetime


AUDIT_FILE = "audit.jsonl"


def log_event(event_type, details):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "details": details
    }

    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")