# Architecture

## The one-paragraph version

Every interesting security event in an AWS account already flows through
EventBridge. This project registers four narrow rules on that stream, routes
them to a triage Lambda that normalizes and scores them, writes every incident
to a KMS-encrypted DynamoDB table, fans a detailed report out to Slack /
Discord / email, and - when policy says so - hands a single, pre-scoped action
to a dedicated remediator Lambda that fixes the problem in seconds.

## Event flow

```
                        ┌──────────────────────────────────────────────┐
                        │                  AWS ACCOUNT                 │
                        │                                              │
 Root signs in ─────────┐ │  GuardDuty detector ──── findings ──────┐    │
 (success OR failure)   │ │                       (P0/P1/P2/P3)    │    │
                        │ │                                        ▼    │
 AuthorizeSecurityGroup │ │  ┌─────────────────────────────────────────┐ │
 Ingress (port opened) ─┼─┼─▶              EventBridge                │ │
                        │ │  │   4 rules:  root / sg / guardduty /    │ │
 CreateAccessKey ───────┘ │  │             iam-key                    │ │
                          │  └───────────────────┬─────────────────────┘ │
                          │                      │ ~1 second             │
                          │                      ▼                       │
                          │  ┌─────────────────────────────────────────┐ │
                          │  │            TRIAGE LAMBDA                │ │
                          │  │  normalize → record → decide → alert    │ │
                          │  └───┬──────────────┬──────────────┬───────┘ │
                          │      │              │              │         │
                          │      ▼              │              ▼         │
                          │  ┌──────────────┐   │      ┌───────────────┐ │
                          │  │  DYNAMODB    │   │      │     SNS/SES   │ │
                          │  │ incidents    │   │      │  email report │ │
                          │  │ (KMS + TTL)  │   │      └───────────────┘ │
                          │  └──────────────┘   │                        │
                          │      async invoke   ▼                        │
                          │  ┌─────────────────────────────────────────┐ │
                          │  │  Secrets Manager (webhooks) ──▶ SLACK / │ │
                          │  │  KMS-encrypted                 DISCORD  │ │
                          │  └─────────────────────────────────────────┘ │
                          └──────────────────────────────────────────────┘
```

## The three Lambda functions and why they are separate

| Function | IAM role can only | Blast radius |
|---|---|---|
| `cir-triage` | Put/Update the incident table, send email, read webhook secrets, **invoke** the two remediators | Nothing is mutated. Even fully compromised, triage cannot change infrastructure. |
| `cir-remediate-sg` | `ec2:RevokeSecurityGroupIngress` (+ Describe) | Worst case: one ingress rule revoked wrongly. Cannot read secrets, logs, or the incident table. |
| `cir-remediate-iam` | `iam:ListAccessKeys`, `iam:UpdateAccessKey` | Worst case: keys disabled wrongly (reversible in one call). |

This is the core design decision. Detection and response live in different
trust domains: the thing that *knows about secrets and channels* cannot act on
infrastructure, and the things that *act* cannot read secrets. A bug or a
compromised deployment can therefore never become "read every secret AND
modify every security group", which is exactly what a single do-everything
lambda's role would grant.

## Decision policy

Triage follows one table, encoded in `src/responders/triage.py`:

| Severity | Store | Alert channels | Auto-remediation |
|---|---|---|---|
| P0 CRITICAL | yes | Slack + Discord + email | only when a safe action exists (key quarantine) |
| P1 HIGH | yes | Slack + Discord + email | yes - revoke public ports |
| P2 MEDIUM | yes | Slack + Discord + email | never |
| P3 LOW | yes | skipped (record-only) | never |

Root activity is P0 but never auto-remediated - root cannot be "disabled" by
design, and half-measures (SCP emergency lockouts) can brick an account if
they misfire. Humans handle root, with the runbook ready.

## Safety switches

- `auto_remediation` (Terraform variable → `AUTO_REMEDIATION` env): master
  switch. `false` = the pipeline detects, records and alerts, but never acts.
- `dry_run` (→ `DRY_RUN` env): remediators compute and log every action but
  call no mutating API. Deploy with `dry_run = true` for the first days -
  the logs then tell you exactly what WOULD have been closed.
- Reserved concurrency caps both the cost and the pace of response.
- DLQs catch every failed invocation; CloudWatch alarms page when a DLQ is
  not empty, so a silently failed response is impossible.

## Failure modes

| Failure | Consequence | Recovery |
|---|---|---|
| Slack webhook not configured (secret empty) | Slack skipped; email + store still work | Put the webhook in the secret (see output `slack_secret_id`) |
| SES identity unverified | Email skipped; webhooks + store still work | Verify the identity in the SES console |
| Triage fails | Event retried, then parked in `cir-triage-dlq` | Redrive per runbook; alarm fires |
| Remediator fails | Incident already alerted; action flagged in timeline | Alarm on DLQ; runbook carries the manual commands |
| GuardDuty disabled by mistake | No GuardDuty findings flow | Its absence is visible in the detector output / AWS Health |

## What is deliberately out of scope

- **Closing compromised instances** - GuardDuty instance findings stay
  alert-only: isolating a production box is a business decision, not a reflex.
- **Cross-region aggregation** - each region runs its own pipeline; the
  incident table is regional by design (blast radius of a table outage).
- **Automatic GuardDuty-to-S3 exports** - the EventBridge stream is real-time;
  S3 export is for archival, which the CloudTrail bucket in the VPC project
  already covers.
- **Code signing for the Lambda packages** - roadmap item for teams with a
  signer workflow; single-maintainer repos gain little from it today.
