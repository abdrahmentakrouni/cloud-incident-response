"""Alert delivery: detailed incident report -> human channel in seconds.

Three transports, all best-effort (one failing channel never blocks the
others, and nothing here can crash triage):

  - Slack / Discord webhook, URL fetched at runtime from AWS Secrets
    Manager so the secret is never in Lambda env vars or Terraform state.
  - SES email for a durable, searchable paper trail.
  - stdout print when IR_SIMULATE=1, which is what the offline simulator
    and CI use - you see exactly what the on-call channel would receive.

Only the Python standard library is used for HTTP (urllib), so the
package ships with zero runtime dependencies beyond boto3.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request

log = logging.getLogger(__name__)

_SIMULATE = os.environ.get("IR_SIMULATE") == "1"
_secret_cache: dict = {}


# ------------------------------------------------------------- the report --

def render_report(incident, action_taken: str = "pending") -> str:
    """One detailed, self-contained security report.

    Designed so that reading ONLY the alert is enough to start working:
    what happened, how bad, who did it, what the robot did, what the
    human should do next. Markdown-flavoured so it renders in Slack.
    """
    sev = incident.severity
    icon = {"P0": ":rotating_light:", "P1": ":warning:",
            "P2": ":large_blue_circle:", "P3": ":information_source:"}[sev.level]
    lines = [
        f"{icon} *[{sev.level}] {incident.title}*",
        "",
        f"*What:* {sev.reason}",
        f"*When:* {incident.detected_at} (UTC)",
        f"*Where:* {incident.region}",
        f"*Who:* `{incident.actor}`",
        f"*Incident ID:* `{incident.id}`",
        "",
        f"*Automated action:* {action_taken}",
    ]
    if incident.payload_ref:
        lines += ["", "*Evidence:*", "```" +
                  json.dumps(incident.payload_ref, indent=2, sort_keys=True) +
                  "```"]
    lines += ["", "_Next steps are in docs/runbook.md, section "
              f"{sev.level}._"]
    return "\n".join(lines)


# ------------------------------------------------------------- transports --

def _webhook_url(secret_arn_env: str) -> str | None:
    """Read the channel webhook from Secrets Manager (cached per container).

    The operator stores the webhook after deploy:
        aws secretsmanager put-secret-value \
            --secret-id security-alerts/slack \
            --secret-string 'https://hooks.slack.com/services/...'
    Until then the pipeline logs a warning and keeps working - a missing
    webhook degrades alerting, it never stops detection or response.
    """
    arn = os.environ.get(secret_arn_env)
    if not arn:
        return None
    if arn in _secret_cache:
        return _secret_cache[arn]

    try:
        import boto3  # imported lazily: simulator runs stay boto3-free
        client = boto3.client("secretsmanager")
        resp = client.get_secret_value(SecretId=arn)
        url = json.loads(resp["SecretString"]).get("webhook")
        _secret_cache[arn] = url
        return url
    except Exception as exc:  # noqa: BLE001 - degrade, never crash triage
        log.warning("could not fetch webhook secret %s: %s", arn, exc)
        return None


def send_slack(report: str) -> str:
    """Post the report to the Slack webhook. Returns delivery status."""
    url = _webhook_url("SLACK_WEBHOOK_SECRET_ARN")
    if not url:
        return "skipped (no webhook configured)"
    if _SIMULATE:
        return "simulated"
    payload = json.dumps({"text": report}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return "sent" if resp.status == 200 else f"http {resp.status}"


def send_discord(report: str) -> str:
    """Same webhook shape works for Discord (content field instead of text)."""
    url = _webhook_url("DISCORD_WEBHOOK_SECRET_ARN")
    if not url:
        return "skipped (no webhook configured)"
    if _SIMULATE:
        return "simulated"
    payload = json.dumps({"content": report[:1900]}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return "sent" if resp.status in (200, 204) else f"http {resp.status}"


def send_email(incident, report: str) -> str:
    """SES email to the on-call address (must be verified in SES first)."""
    to_addr = os.environ.get("ALERT_EMAIL")
    if not to_addr:
        return "skipped (no ALERT_EMAIL configured)"
    if _SIMULATE:
        return "simulated"

    import boto3
    ses = boto3.client("ses")
    ses.send_email(
        Source=os.environ.get("ALERT_FROM", "alerts@example.com"),
        Destination={"ToAddresses": [to_addr]},
        Message={
            "Subject": {"Data": f"[{incident.severity.level}] {incident.title}"},
            "Body": {"Text": {"Data": report}},
        },
    )
    return "sent"


# ------------------------------------------------------------ entry point --

def dispatch(incident, action_taken: str) -> dict:
    """Fan one incident report out to every configured channel."""
    report = render_report(incident, action_taken)

    if _SIMULATE:
        print("\n" + "=" * 62)
        print("ALERT -> security-engineers channel (simulated)")
        print("=" * 62)
        print(report)
        print("=" * 62 + "\n")
        return {"slack": "simulated", "discord": "simulated",
                "email": "simulated"}

    statuses = {}
    for name, fn in (("slack", send_slack), ("discord", send_discord)):
        try:
            statuses[name] = fn(report)
        except Exception as exc:  # noqa: BLE001
            log.error("%s delivery failed: %s", name, exc)
            statuses[name] = f"failed: {exc}"
    try:
        statuses["email"] = send_email(incident, report)
    except Exception as exc:  # noqa: BLE001
        log.error("email delivery failed: %s", exc)
        statuses["email"] = f"failed: {exc}"
    return statuses
