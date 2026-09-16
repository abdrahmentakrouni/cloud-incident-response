"""Triage: the brain of the pipeline.

Every security event lands here first. Triage does five things, in order:

  1. UNDERSTAND  - normalize the raw EventBridge payload into an Incident
  2. RECORD      - write it to the KMS-encrypted incident store
  3. DECIDE      - does policy say "act"? (remediable + auto-remediation on)
  4. ACT         - hand off to the remediator lambda (async, least privilege)
  5. TELL        - fan the report out to Slack/Discord/email

Design rule: the detection plane (this lambda) and the response plane
(the remediator) are separate functions with separate IAM roles. A
compromised or buggy responder can never read secrets or browse logs,
and a bug in triage can never mutate infrastructure directly.
"""

from __future__ import annotations

import json
import logging
import os

from lib import incident_store, notify
from lib.events import normalize

log = logging.getLogger(__name__)

_SIMULATE = os.environ.get("IR_SIMULATE") == "1"


def _auto_remediation_enabled() -> bool:
    return os.environ.get("AUTO_REMEDIATION", "1") == "1"


def _invoke_remediator(incident) -> str:
    """Hand the action to the remediator lambda (async, fire and log)."""
    if incident.remediation == "close_public_ports":
        payload = {
            "incident_id": incident.id,
            "action": "close_public_ports",
            "payload": incident.payload_ref,
        }
        target_env = "REMEDIATOR_SG_ARN"
    elif incident.remediation == "quarantine_iam":
        payload = {
            "incident_id": incident.id,
            "action": "quarantine_iam",
            "user": incident.payload_ref.get("finding_user") or incident.actor,
        }
        target_env = "REMEDIATOR_IAM_ARN"
    else:
        return "no remediator for action"

    if _SIMULATE:
        # The simulator runs the responder in-process so the offline demo
        # shows the exact same decision tree AWS would execute.
        from responders import quarantine_iam, remediate_sg
        if incident.remediation == "close_public_ports":
            result = remediate_sg.respond(incident)
        else:
            result = quarantine_iam.respond(incident)
        print(f"REMEDIATOR -> {result.get('action')} = {result.get('status')}")
        return f"executed in simulation: {result.get('status')}"

    try:
        import boto3
        target_arn = os.environ.get(target_env)
        if not target_arn:
            return "remediator not configured"
        boto3.client("lambda").invoke(
            FunctionName=target_arn,
            InvocationType="Event",  # async - triage returns in milliseconds
            Payload=json.dumps(payload).encode(),
        )
        return f"remediation dispatched ({incident.remediation})"
    except Exception as exc:  # noqa: BLE001 - never block alerting
        log.error("remediation dispatch failed: %s", exc)
        return f"remediation dispatch failed: {exc}"


def handle(raw_event: dict) -> dict:
    """Process one EventBridge event end to end. Returns a summary dict."""
    incident = normalize(raw_event)

    if incident is None:
        log.info("event ignored (not a tracked security event): %s",
                 raw_event.get("detail-type"))
        return {"status": "ignored"}

    # 1. Always record first - even if every channel is down, the audit
    #    trail must survive.
    store_status = incident_store.save(incident)

    # 2. Decide + act.
    action_taken = "none (alert and record only)"
    if incident.remediation:
        if _auto_remediation_enabled():
            action_taken = _invoke_remediator(incident)
        else:
            action_taken = "AUTO_REMEDIATION=0 - runbook action required"
    elif incident.remediable is False and incident.severity.level in ("P0", "P1"):
        action_taken = "no safe automated action - human runbook step"

    # 3. Tell the humans (P2+ goes to the channel; P3 is record-only).
    if incident.severity.level in ("P0", "P1", "P2"):
        deliveries = notify.dispatch(incident, action_taken)
    else:
        deliveries = {"channels": "skipped (P3 record-only)"}

    return {
        "status": "triaged",
        "incident_id": incident.id,
        "severity": incident.severity.level,
        "title": incident.title,
        "recorded": store_status,
        "action_taken": action_taken,
        "deliveries": deliveries,
    }


def lambda_handler(event: dict, context=None) -> dict:  # pragma: no cover
    """AWS Lambda entrypoint (EventBridge target, one event per invoke)."""
    return handle(event)
