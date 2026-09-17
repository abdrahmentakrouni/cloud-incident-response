# Detection catalog

Every event family the pipeline recognizes, what severity it gets, and what
happens automatically. The same mapping lives in code (`src/lib/events.py` +
`src/responders/triage.py`); this document is the human-readable contract.
When the table and the code disagree, file an issue - one of them is wrong.

## Severity scale

| Level | Meaning | Channel alert | Automated action |
|---|---|---|---|
| P0 CRITICAL | Account-level risk. Act now. | yes | only pre-approved safe actions |
| P1 HIGH | Contained but urgent | yes | yes - pre-approved remediations |
| P2 MEDIUM | Review today | yes | never |
| P3 LOW | Audit-trail only | no (record-only) | never |

## 1. Root account activity

**Source:** EventBridge → CloudTrail sign-in / API events where
`userIdentity.type = Root` (the `root-activity` rule catches console AND API).

| Case | Severity | Why | Automated action |
|---|---|---|---|
| Root console sign-in **succeeded** | P0 | The most powerful identity in the account was used - legitimate or not, it must be reviewed within minutes | Alert + record. Root cannot be disabled by a robot. |
| Root console sign-in **failed** | P0 | Failed root logins are the signature of credential stuffing. AWS does not lock the account after failures, so the only defense is noticing | Alert + record |

Why so aggressive? Root can delete every guardrail in the account - CloudTrail,
GuardDuty, this pipeline itself. A successful root sign-in at 3am is either an
emergency or an emergency-in-progress, and both deserve the same first five
minutes of attention.

## 2. Security group ingress opened

**Source:** CloudTrail `AuthorizeSecurityGroupIngress` (the `sg-ingress-open`
rule).

| Case | Severity | Automated action |
|---|---|---|
| World-open range (`0.0.0.0/0` or `::/0`) on a dangerous port (SSH 22, RDP 3389, Telnet 23, FTP 21, MSSQL 1433, MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017) | P1 | **Revoke within seconds.** Only the exact offending tuples (protocol + port + CIDR) are revoked - the rest of the group is untouched |
| World-open range on any other port (e.g. 8443) | P2 | Alert + record. Could be legitimate; a human decides |
| Internal CIDR change (e.g. `10.0.0.0/8`) | - | Not an incident. Never touches the pipeline |

The dangerous-port list lives in `DANGEROUS_PORTS` in `src/lib/events.py`.
It is intentionally short: every port on it should never be world-readable,
so the robot needs no context to act.

## 3. GuardDuty findings

**Source:** EventBridge `aws.guardduty` (the `guardduty-findings` rule).
GuardDuty severity is mapped: ≥7 → P0, ≥4 → P1, ≥2 → P2, else P3.

| Case | Severity | Automated action |
|---|---|---|
| High finding naming an IAM user (credential exfiltration, malicious API use from known-bad infrastructure) | P0 | **Quarantine:** every access key of that user is set to `Inactive` |
| High finding on an instance (crypto mining, malware) | P0 | Alert + record. Isolating a production instance is a business decision - runbook, not robot |
| Medium finding | P1 | Alert + record |
| Low finding | P3 | Record-only |

Quarantine is deliberately minimal and reversible: `UpdateAccessKey →
Inactive` breaks the attack path instantly, and restoring service means
issuing a fresh key (rotation), never un-quarantining a leaked one.

## 4. New IAM access keys

**Source:** CloudTrail `CreateAccessKey` (the `iam-key-created` rule).

| Case | Severity | Automated action |
|---|---|---|
| Any new long-lived access key | P2 | Alert + record |

Key creation is routine for some teams, which is exactly why it is P2 and not
P0: the goal is visibility, not noise elimination. Every rogue key is now on
the record within seconds of its creation.

## What the alert contains

Every P0-P2 alert carries: title, severity + reason, timestamp, region,
actor (identity ARN or GuardDuty subject), incident ID, the automated action
taken, and the evidence JSON. Example (from the recorded simulator events):

```
🚨 [P0] Failed ROOT console sign-in attempt

*What:* Failed root logins are the signature of credential stuffing
*When:* 2026-09-16T02:41:07Z (UTC)
*Where:* us-east-1
*Who:* `arn:aws:iam::111122223333:root`
*Incident ID:* `IR-20260916-1a2b3c4d`

*Automated action:* no safe automated action - human runbook step

*Evidence:*
{
  "event_name": "ConsoleLogin",
  "failed": true,
  "account": "111122223333",
  "source_ip": "45.155.205.233"
}

_Next steps are in docs/runbook.md, section P0._
```

## Extending the catalog

Adding a detection is three steps, and CI guards all three:

1. A parser in `src/lib/events.py` returning an `Incident` (or `None`)
2. A rule in `infra/events.tf` with a matching EventBridge pattern
3. Tests: parser decisions in `tests/test_events.py`, end-to-end behavior in
   `tests/test_triage.py`

The recorded sample events in `simulator/events/` double as executable
documentation: a new detection is only done when its sample event replays
correctly in `python3 simulator/simulate.py --all`.
