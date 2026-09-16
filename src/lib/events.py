"""Event normalizer: raw EventBridge payloads -> one Incident shape.

Everything EventBridge can throw at us arrives here first. Three families
of events are understood today:

  1. CloudTrail API calls          (AWS API Call via CloudTrail)
  2. Sign-in events                (AWS Console Sign In via CloudTrail)
  3. GuardDuty findings            (GuardDuty Finding)

Anything else returns None and the triage lambda logs-and-ignores, so a
new AWS source can never crash the pipeline silently.

The CloudTrail shapes intentionally handle both real-world serializations
of nested lists ("items"-wrapped from CloudTrail, plain lists from some
SDK logs) because they differ and nobody remembers which is which.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .severity import P0, P1, P2, Severity, guardduty_level

# Ports that should never be reachable from the whole internet. Telnet and
# FTP are here for completeness; SSH/RDP/DB engines are the usual suspects.
DANGEROUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# CIDRs that mean "the entire internet".
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

DETECTOR = "1.0"


@dataclass
class Incident:
    """The one shape every downstream step (store, notify, remediate) uses."""

    id: str
    detected_at: str
    title: str
    source: str                 # root-login | sg-ingress | guardduty | iam-key
    severity: Severity
    actor: str                  # who/what triggered it, best effort
    region: str
    remediable: bool = False
    remediation: str | None = None   # action name for the remediator
    payload_ref: dict = field(default_factory=dict)  # fields kept for the store

    def to_store_item(self) -> dict:
        """Flat dict for the DynamoDB incident log (JSON-friendly values)."""
        return {
            "incident_id": self.id,
            "detected_at": self.detected_at,
            "ttl": _ttl_epoch(),
            "title": self.title,
            "source": self.source,
            "severity": self.severity.level,
            "severity_reason": self.severity.reason,
            "actor": self.actor,
            "region": self.region,
            "remediable": self.remediable,
            "remediation": self.remediation or "none",
            "payload": self.payload_ref,
        }


def _ttl_epoch(hours: int | None = None) -> int:
    """Incident records expire from the store after N days (TTL sweeper).

    The retention is deployment policy, not code policy: Terraform passes
    INCIDENT_TTL_DAYS from the incident_retention_days variable.
    """
    if hours is None:
        days = int(os.environ.get("INCIDENT_TTL_DAYS", "90"))
        hours = days * 24
    return int(datetime.now(UTC).timestamp()) + hours * 3600


def new_incident_id() -> str:
    return f"IR-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"


def _items(node: Any, key: str) -> list:
    """Read a CloudTrail nested list in either serialization."""
    if not isinstance(node, dict):
        return []
    val = node.get(key)
    if isinstance(val, dict) and isinstance(val.get("items"), list):
        return val["items"]
    if isinstance(val, list):
        return val
    return []


def _root_actor(detail: dict) -> str:
    identity = detail.get("userIdentity") or {}
    return identity.get("arn") or identity.get("userName") or identity.get("type", "unknown")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# ---------------------------------------------------------------- parsers --

def parse_guardduty(raw: dict) -> Incident | None:
    """Map a GuardDuty finding onto the incident shape.

    Findings that reference IAM users are marked remediable: the quarantine
    responder can disable that user's access keys while the attacker holds
    them. Everything else is alert-only (stopping a compromised instance,
    for example, is a decision we leave to the runbook, not to a robot).
    """
    detail = raw.get("detail") or {}
    sev_raw = detail.get("severity")
    if sev_raw is None:
        return None
    level = guardduty_level(float(sev_raw))

    finding_type = detail.get("type", "unknown")
    title = detail.get("title") or f"GuardDuty finding: {finding_type}"
    actor = "unknown"
    remediable = False
    resource = detail.get("resource") or {}

    access_keys = resource.get("accessKeyDetails") or {}
    user_name = access_keys.get("userName")
    if user_name:
        actor = user_name
        # Credential-focused findings: someone is abusing keys that can be
        # switched off. Instance-level findings stay alert-only on purpose.
        remediable = True
    else:
        actor = resource.get("instanceDetails", {}).get("instanceId", "unknown")

    if level == P0:
        reason = "GuardDuty High severity finding"
        remediation = "quarantine_iam" if remediable else None
    elif level == P1:
        reason = "GuardDuty Medium severity finding"
        remediation = None
    else:
        reason = "GuardDuty Low severity finding"
        remediation = None

    return Incident(
        id=new_incident_id(),
        detected_at=detail.get("createdAt") or _now_iso(),
        title=title,
        source="guardduty",
        severity=Severity(level, reason),
        actor=actor,
        region=detail.get("region", "unknown"),
        remediable=remediable and remediation is not None,
        remediation=remediation,
        payload_ref={
            "finding_type": finding_type,
            "severity_raw": sev_raw,
            "account": detail.get("accountId"),
            "resource_type": resource.get("resourceType", "unknown"),
            "finding_user": user_name,
        },
    )


def parse_signin(raw: dict) -> Incident | None:
    """Root console activity - success OR failure - is always P0.

    Root is the one identity that can destroy every guardrail in the
    account, so the pipeline treats any attempt (even a failed one, which
    is exactly what a credential-stuffing run looks like) as critical.
    """
    detail = raw.get("detail") or {}
    identity = detail.get("userIdentity") or {}
    if identity.get("type") != "Root":
        return None

    failed = "errorMessage" in detail
    if failed:
        title = "Failed ROOT console sign-in attempt"
        reason = "Failed root logins are the signature of credential stuffing"
    else:
        title = "ROOT console sign-in"
        reason = "Root signed in - highest-privilege identity in the account"

    return Incident(
        id=new_incident_id(),
        detected_at=detail.get("eventTime") or _now_iso(),
        title=title,
        source="root-login",
        severity=Severity(P0, reason),
        actor=_root_actor(detail),
        region=detail.get("awsRegion", "global"),
        remediable=False,
        remediation=None,  # root cannot be "disabled" by design - humans act
        payload_ref={
            "event_name": detail.get("eventName"),
            "failed": failed,
            "account": detail.get("accountId") or identity.get("accountId"),
            "source_ip": (detail.get("sourceIPAddress") or "unknown"),
        },
    )


def _group_id(params: dict) -> str:
    """Find the target security group id in either request shape."""
    if params.get("groupId"):
        return params["groupId"]
    if params.get("securityGroupId"):
        return params["securityGroupId"]
    sgids = params.get("securityGroupIds")
    if isinstance(sgids, dict) and isinstance(sgids.get("items"), list) and sgids["items"]:
        return sgids["items"][0]
    return "unknown-sg"


def _open_ranges(permission: dict) -> list:
    """Return the world-open CIDRs inside one ipPermission."""
    ranges = _items(permission, "ranges")
    if not ranges and isinstance(permission.get("cidr"), list):
        ranges = permission["cidr"]  # ipv6/ipv4 unified shape
    open_cidrs = []
    for r in ranges:
        cidr = r.get("cidrIp") or r.get("CidrIp") or r.get("cidrIpV6") or r.get("cidrIpv6")
        if cidr in OPEN_CIDRS:
            open_cidrs.append(cidr)
    return open_cidrs


def parse_sg_change(raw: dict) -> Incident | None:
    """AuthorizeSecurityGroupIngress: did someone just expose a dangerous port?

    If a world-open range lands on a dangerous port the incident is marked
    remediable and the SG responder revokes exactly those tuples. Every
    other ingress change is recorded as P2 - visible, but not touched.
    """
    detail = raw.get("detail") or {}
    if detail.get("eventName") not in ("AuthorizeSecurityGroupIngress",):
        return None

    params = detail.get("requestParameters") or {}
    group_id = _group_id(params)

    opened = []
    for perm in _items(params, "ipPermissions"):
        proto = perm.get("ipProtocol", perm.get("IpProtocol", "tcp"))
        lo = perm.get("fromPort", perm.get("FromPort", -1))
        hi = perm.get("toPort", perm.get("ToPort", -1))
        open_cidrs = _open_ranges(perm)
        if not open_cidrs:
            continue
        service = DANGEROUS_PORTS.get(lo if lo == hi else -1)
        opened.append({
            "group_id": group_id,
            "protocol": proto,
            "from_port": lo,
            "to_port": hi,
            "cidrs": open_cidrs,
            "service": service or f"{proto}/{lo}-{hi}",
        })

    # A tuple is "dangerous" only when a single known-bad port (from == to)
    # is exposed to the whole world at once.
    dangerous = [p for p in opened
                 if p["from_port"] == p["to_port"]
                 and p["from_port"] in DANGEROUS_PORTS]

    if dangerous:
        names = ", ".join(sorted({p['service'] for p in dangerous}))
        title = f"Public exposure opened on {group_id}: {names}"
        reason = "World-open ingress on a management/DB port - auto-revoked"
        return Incident(
            id=new_incident_id(),
            detected_at=detail.get("eventTime") or _now_iso(),
            title=title,
            source="sg-ingress",
            severity=Severity(P1, reason),
            actor=_root_actor(detail),
            region=detail.get("awsRegion", "unknown"),
            remediable=True,
            remediation="close_public_ports",
            payload_ref={
                "group_id": group_id,
                "opened": opened,
                "dangerous": dangerous,
            },
        )

    if opened:
        title = f"Public ingress change on {group_id}"
        reason = "World-open range on a non-flagged port - recorded, not acted on"
        return Incident(
            id=new_incident_id(),
            detected_at=detail.get("eventTime") or _now_iso(),
            title=title,
            source="sg-ingress",
            severity=Severity(P2, reason),
            actor=_root_actor(detail),
            region=detail.get("awsRegion", "unknown"),
            remediable=False,
            remediation=None,
            payload_ref={"group_id": group_id, "opened": opened},
        )

    return None


def parse_iam_key(raw: dict) -> Incident | None:
    """A new access key exists: P2, alert-only.

    Key creation is routine for some teams, so it never auto-quarantines -
    but every creation lands in the incident log and the security channel,
    which makes rogue keys visible within seconds instead of at audit time.
    """
    detail = raw.get("detail") or {}
    if detail.get("eventName") not in ("CreateAccessKey",):
        return None
    params = detail.get("requestParameters") or {}
    target = params.get("userName") or _root_actor(detail)

    return Incident(
        id=new_incident_id(),
        detected_at=detail.get("eventTime") or _now_iso(),
        title=f"New IAM access key created for {target}",
        source="iam-key",
        severity=Severity(P2, "New long-lived credentials are a standing risk"),
        actor=_root_actor(detail),
        region="global",
        remediable=False,
        remediation=None,
        payload_ref={"target_user": target},
    )


# --------------------------------------------------------------- dispatch --

def normalize(raw: dict) -> Incident | None:
    """Route one EventBridge payload to the right parser.

    Returns None for events this pipeline does not track - that is a
    feature: unknown event families can never break triage.
    """
    if not isinstance(raw, dict):
        return None
    detail_type = raw.get("detail-type", "")
    source = raw.get("source", "")

    if source == "aws.guardduty" and detail_type == "GuardDuty Finding":
        return parse_guardduty(raw)
    if detail_type == "AWS Console Sign In via CloudTrail":
        return parse_signin(raw)
    if detail_type == "AWS API Call via CloudTrail":
        detail = raw.get("detail") or {}
        if detail.get("eventSource") == "ec2.amazonaws.com":
            return parse_sg_change(raw)
        if detail.get("eventSource") == "iam.amazonaws.com":
            return parse_iam_key(raw)
        # Root can act purely through the API (no console), so check the
        # identity on every CloudTrail call before giving up.
        inc = parse_signin(raw)
        if inc:
            return inc
    return None
