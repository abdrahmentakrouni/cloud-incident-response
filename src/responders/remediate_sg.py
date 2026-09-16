"""SG responder: close world-open management ports, within seconds.

Runs in its own lambda with its own IAM role that can do exactly two
things: describe security groups and revoke ingress. It cannot touch
anything else, so even a bug in this file has a blast radius of one
API call family.

The revoke targets are computed from the incident payload, and only for
ports the catalog flags as dangerous (see lib/events.DANGEROUS_PORTS).
A DRY_RUN=1 deploy plans everything but calls nothing - the safe way to
audit what the robot WOULD close on day one.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_SIMULATE = os.environ.get("IR_SIMULATE") == "1"
_DRY_RUN = os.environ.get("DRY_RUN") == "1"


# ------------------------------------------------------------------ plan --

def plan_revokes(dangerous: list) -> list:
    """Turn incident payload tuples into AWS revoke_permissions shapes.

    Input items look like:
      {"group_id": "sg-...", "protocol": "tcp", "from_port": 22,
       "to_port": 22, "cidrs": ["0.0.0.0/0"], "service": "SSH"}

    Output is one IpPermissions dict per protocol/port tuple, with v4 and
    v6 ranges split the way the EC2 API expects them.
    """
    grouped: dict = {}
    for p in dangerous:
        key = (p.get("group_id"), p.get("protocol", "tcp"),
               p.get("from_port"), p.get("to_port"))
        entry = grouped.setdefault(key, {"ipv4": [], "ipv6": []})
        for cidr in p.get("cidrs", []):
            if ":" in cidr:
                entry["ipv6"].append({"CidrIpv6": cidr})
            else:
                entry["ipv4"].append({"CidrIp": cidr})

    plan = []
    for (group_id, proto, lo, hi), ranges in grouped.items():
        if not ranges["ipv4"] and not ranges["ipv6"]:
            continue
        perm = {
            "GroupId": group_id,
            "IpPermissions": [{
                "IpProtocol": proto,
                "FromPort": int(lo),
                "ToPort": int(hi),
            }],
        }
        if ranges["ipv4"]:
            perm["IpPermissions"][0]["IpRanges"] = ranges["ipv4"]
        if ranges["ipv6"]:
            perm["IpPermissions"][0]["Ipv6Ranges"] = ranges["ipv6"]
        plan.append(perm)
    return plan


def describe_plan(plan: list) -> str:
    """One-line human summary of a revoke plan, for alerts and logs."""
    parts = []
    for p in plan:
        perm = p["IpPermissions"][0]
        v4 = [r["CidrIp"] for r in perm.get("IpRanges", [])]
        v6 = [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
        parts.append(f"{p['GroupId']} {perm['IpProtocol']}/"
                     f"{perm['FromPort']}-{perm['ToPort']} from "
                     f"{', '.join(v4 + v6)}")
    return "; ".join(parts) if parts else "nothing to revoke"


# --------------------------------------------------------------- execute --

def execute(plan: list) -> dict:
    """Revoke every planned tuple. Returns a result summary for the store."""
    if not plan:
        return {"status": "no-op", "revoked": 0}

    summary = f"revoking {describe_plan(plan)}"
    if _SIMULATE or _DRY_RUN:
        mode = "DRY-RUN" if _DRY_RUN else "SIMULATED"
        print(f"REMEDIATOR [{mode}] -> {summary}")
        return {"status": mode.lower(), "plan": describe_plan(plan)}

    import boto3
    ec2 = boto3.client("ec2")
    revoked = 0
    failures = []
    for p in plan:
        try:
            ec2.revoke_security_group_ingress(**p)
            revoked += 1
        except Exception as exc:  # noqa: BLE001 - collect, report, continue
            log.error("revoke failed for %s: %s", p["GroupId"], exc)
            failures.append({"group": p["GroupId"], "error": str(exc)})

    result = {"status": "revoked" if revoked and not failures else
              ("partial" if revoked else "failed"),
              "revoked": revoked}
    if failures:
        result["failures"] = failures
    return result


def respond(incident) -> dict:
    """Entry point used by the remediation lambda and the simulator."""
    dangerous = (incident.payload_ref or {}).get("dangerous", [])
    plan = plan_revokes(dangerous)
    result = execute(plan)
    result["action"] = "close_public_ports"
    return result


# -------------------------------------------------------- aws entrypoint --

def lambda_handler(event: dict, context=None) -> dict:  # pragma: no cover
    """AWS Lambda entrypoint. Receives the envelope triage sent us."""
    incident_id = event.get("incident_id", "unknown")
    payload = event.get("payload") or {}
    dangerous = payload.get("dangerous", [])
    plan = plan_revokes(dangerous)
    result = execute(plan)
    result["incident_id"] = incident_id

    from ..lib import incident_store
    incident_store.append_action(incident_id, "close_public_ports",
                                 result.get("status", "unknown"),
                                 {"plan": describe_plan(plan)})
    return result
