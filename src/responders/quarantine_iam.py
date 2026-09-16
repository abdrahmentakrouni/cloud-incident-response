"""IAM quarantine responder: freeze leaked credentials in one move.

Fires on GuardDuty credential findings (key exfiltration, malicious API
use from strange infrastructure). The response is deliberately minimal
and reversible: set every access key of the affected user to Inactive.

Disabled keys break the attack path in one API call per key. Restoring
service means creating a fresh key - rotating, not un-quarantining -
which is exactly what the runbook tells the on-call engineer to do.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_SIMULATE = os.environ.get("IR_SIMULATE") == "1"
_DRY_RUN = os.environ.get("DRY_RUN") == "1"


def plan_quarantine(user_name: str) -> dict:
    """Describe what WOULD be frozen - pure function, trivially testable."""
    return {
        "user": user_name,
        "action": "disable_all_access_keys",
        "reversible": True,
        "note": "rotation required before re-enabling service",
    }


def execute(user_name: str) -> dict:
    """Disable every active access key belonging to user_name."""
    if not user_name or user_name == "unknown":
        return {"status": "skipped", "reason": "no user identified in finding"}

    summary = f"quarantining IAM user {user_name}: disable all access keys"
    if _SIMULATE or _DRY_RUN:
        mode = "DRY-RUN" if _DRY_RUN else "SIMULATED"
        print(f"REMEDIATOR [{mode}] -> {summary}")
        return {"status": mode.lower(), "plan": plan_quarantine(user_name)}

    import boto3
    iam = boto3.client("iam")

    try:
        keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    except iam.exceptions.NoSuchEntityException:
        return {"status": "skipped", "reason": f"user {user_name} not found"}

    disabled = 0
    failures = []
    for key in keys:
        if key.get("Status") != "Active":
            continue
        try:
            iam.update_access_key(UserName=user_name,
                                  AccessKeyId=key["AccessKeyId"],
                                  Status="Inactive")
            disabled += 1
        except Exception as exc:  # noqa: BLE001
            log.error("could not disable key %s: %s", key["AccessKeyId"], exc)
            failures.append(str(key["AccessKeyId"]))

    result = {"status": "quarantined" if disabled and not failures else
              ("partial" if disabled else ("failed" if failures else
                                           "no-active-keys")),
              "user": user_name, "disabled": disabled}
    if failures:
        result["failures"] = failures
    return result


def respond(incident) -> dict:
    """Entry point used by the simulator."""
    user = (incident.payload_ref or {}).get("finding_user") or incident.actor
    result = execute(user)
    result["action"] = "quarantine_iam"
    return result


def lambda_handler(event: dict, context=None) -> dict:  # pragma: no cover
    """AWS Lambda entrypoint. Payload: {"incident_id": ..., "user": ...}"""
    incident_id = event.get("incident_id", "unknown")
    user = event.get("user", "")
    result = execute(user)
    result["action"] = "quarantine_iam"
    result["incident_id"] = incident_id

    from ..lib import incident_store
    incident_store.append_action(incident_id, "quarantine_iam",
                                 result.get("status", "unknown"),
                                 {"user": user})
    return result
