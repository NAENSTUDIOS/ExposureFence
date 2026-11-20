import json
import os
from datetime import datetime, UTC

AUDIT_FILE = "audit.jsonl"


def log_event(event_type, details):

    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "details": details
    }

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def get_audit_events():
    if not os.path.exists(AUDIT_FILE):
        return []

    events = []
    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


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



def get_audit_events():
    if not os.path.exists(AUDIT_FILE):
        return []

    events = []
    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


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