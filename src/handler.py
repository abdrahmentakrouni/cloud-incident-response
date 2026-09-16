"""Lambda entrypoints (the only AWS-facing surface of the codebase).

Two functions get deployed:

  triage_handler       - target of every EventBridge rule
  remediation_handler  - invoked async by triage; dispatches by action

The handler module stays thin on purpose: all logic lives in lib/ and
responders/, which the offline simulator and pytest drive directly with
zero AWS dependencies (IR_SIMULATE=1).
"""

from __future__ import annotations

import logging

from responders import quarantine_iam, remediate_sg, triage

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def triage_handler(event: dict, context=None) -> dict:
    """One security event in, one triage decision out."""
    logger.info("triage received: %s / %s",
                event.get("source"), event.get("detail-type"))
    summary = triage.handle(event)
    logger.info("triage result: %s", summary)
    return summary


def remediation_handler(event: dict, context=None) -> dict:
    """Async action worker. Payload: {"incident_id", "action", ...}."""
    action = event.get("action")
    incident_id = event.get("incident_id", "unknown")
    logger.info("remediation %s for %s", action, incident_id)

    if action == "close_public_ports":
        result = remediate_sg.lambda_handler(event, context)
    elif action == "quarantine_iam":
        result = quarantine_iam.lambda_handler(event, context)
    else:
        result = {"status": "skipped", "reason": f"unknown action {action}"}

    logger.info("remediation result: %s", result)
    return result
