"""Incident store: one DynamoDB item per incident, KMS-encrypted at rest.

This table is the post-breach memory of the pipeline: what fired, when,
what the robot did about it. Records carry a 90-day TTL so the store
self-prunes, and every response action appends to the same item's
`timeline` list - giving you the full story in one place afterwards.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

log = logging.getLogger(__name__)

_SIMULATE = os.environ.get("IR_SIMULATE") == "1"


def _table():
    import boto3
    return boto3.resource("dynamodb").Table(os.environ["INCIDENTS_TABLE"])


def save(incident) -> str:
    item = incident.to_store_item()
    if _SIMULATE:
        print(f"STORE -> incident saved (simulated): {item['incident_id']} "
              f"[{item['severity']}] {item['title']}")
        return "simulated"
    _table().put_item(Item=item)
    return "saved"


def append_action(incident_id: str, action: str, result: str,
                  detail: dict | None = None) -> str:
    """Attach the remediation outcome to the incident record.

    Kept separate from save() because remediation runs asynchronously in
    its own lambda - whoever finishes last appends to the shared record.
    """
    entry = {
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "action": action,
        "result": result,
    }
    if detail:
        entry["detail"] = detail

    if _SIMULATE:
        print(f"STORE -> timeline updated (simulated): {incident_id} "
              f"+ {action} = {result}")
        return "simulated"

    _table().update_item(
        Key={"incident_id": incident_id},
        UpdateExpression=(
            "SET #tl = list_append(if_not_exists(#tl, :empty), :entry)"
        ),
        ExpressionAttributeNames={"#tl": "timeline"},
        ExpressionAttributeValues={
            ":entry": [entry],
            ":empty": [],
        },
    )
    return "updated"


def dump_json(item: dict) -> str:
    """Pretty JSON for logs and the simulator output."""
    return json.dumps(item, indent=2, sort_keys=True, default=str)
