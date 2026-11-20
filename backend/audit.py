import hashlib
import json
import os
import threading
from datetime import datetime, UTC

AUDIT_FILE = "audit.jsonl"
AUDIT_LOCK = threading.Lock()
GENESIS_HASH = "0" * 64


def _get_last_event_hash():
    if not os.path.exists(AUDIT_FILE):
        return GENESIS_HASH
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
            if not lines:
                return GENESIS_HASH
            last_event = json.loads(lines[-1])
            return last_event.get("event_hash", GENESIS_HASH)
    except Exception:
        return GENESIS_HASH


def log_event(event_type, details):
    with AUDIT_LOCK:
        timestamp = datetime.now(UTC).isoformat()
        prev_hash = _get_last_event_hash()
        canonical_payload = f"{prev_hash}|{timestamp}|{event_type}|{json.dumps(details, sort_keys=True)}"
        event_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

        event = {
            "timestamp": timestamp,
            "event_type": event_type,
            "details": details,
            "prev_hash": prev_hash,
            "event_hash": event_hash
        }

        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        return event


def get_audit_events():
    if not os.path.exists(AUDIT_FILE):
        return []

    events = []
    with AUDIT_LOCK:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return events


def verify_audit_hash_chain():
    events = get_audit_events()
    if not events:
        return True

    prev_expected = None
    for event in events:
        # If legacy entry without event_hash, skip legacy records
        if "event_hash" not in event:
            continue

        prev_hash = event.get("prev_hash")
        if prev_expected is not None and prev_hash != prev_expected:
            return False

        canonical = f"{prev_hash}|{event['timestamp']}|{event['event_type']}|{json.dumps(event['details'], sort_keys=True)}"
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if computed != event["event_hash"]:
            return False

        prev_expected = event["event_hash"]

    return True


def verify_zero_mutations():
    events = get_audit_events()
    mutation_markers = {"mutation", "mutate", "modify", "delete", "create_resource", "update_resource", "apply_fix"}
    for event in events:
        event_type = str(event.get("event_type", "")).lower()
        if any(marker in event_type for marker in mutation_markers):
            return False

        details = event.get("details", {})
        if isinstance(details, dict):
            tool = str(details.get("tool", "")).lower()
            action = str(details.get("action", "")).lower()
            if any(marker in tool or marker in action for marker in mutation_markers):
                return False

    return True
