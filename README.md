# cloud-incident-response

[![CI](https://github.com/abdrahmentakrouni/cloud-incident-response/actions/workflows/ci.yml/badge.svg)](https://github.com/abdrahmentakrouni/cloud-incident-response/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/abdrahmentakrouni/cloud-incident-response)](https://github.com/abdrahmentakrouni/cloud-incident-response/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB)](src/)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D%201.5-7B42BC)](infra/)
[![Scanned by Checkov + tfsec](https://img.shields.io/badge/scanned%20by-checkov%20%2B%20tfsec-2EC4B6)](.github/workflows/ci.yml)

**A security robot for an AWS account.** It watches for the events that
actually matter - root sign-ins, world-open management ports, GuardDuty
findings, new long-lived keys - writes every one of them to an encrypted
incident log, alerts a security channel within seconds with a full report,
and for the dangerous-but-measurable cases **fixes the problem itself
before a human has even read the alert**.

This is the detection-and-response layer of a defense-in-depth portfolio:
host hardening → app hardening → backup & DR → network baseline → **this**.
A firewall that never watches its own logs is a locked door nobody patrols.

---

## Why

Most AWS accounts have logs. Almost none have *behavior*. CloudTrail records
everything and changes nothing; GuardDuty finds problems that then sit in a
console nobody opens at 3am; and the moment between "security group opened to
the world" and "a human noticed" is exactly the window an attacker needs.

This project closes that window. The design rule everywhere: **every alert
must be detailed enough to act on without opening the console, and every
automated action must be small enough to be obviously safe.**

## The 60-second demo

No AWS account needed - the recorded events replay through the *real* code:

```text
$ python3 simulator/simulate.py --all

# EVENT FILE: sg-port-22-open.json
STORE -> incident saved (simulated): IR-20260916-672cd823 [P1]
REMEDIATOR [SIMULATED] -> revoking sg-0a1b2c3d4e5f60011 tcp/22-22 from 0.0.0.0/0
REMEDIATOR -> close_public_ports = simulated

==============================================================
ALERT -> security-engineers channel (simulated)
==============================================================
⚠️ * [P1] Public exposure opened on sg-0a1b2c3d4e5f60011: SSH*

*What:* World-open ingress on a management/DB port - auto-revoked
*When:* 2026-09-16T03:12:44Z (UTC)
*Who:* `arn:aws:iam::111122223333:user/devops-junior`
*Incident ID:* `IR-20260916-672cd823`

*Automated action:* executed in simulation: simulated
...
RECAP
event file                       sev  result
guardduty-crypto.json            P0   no safe automated action - human runbook step
guardduty-key-exfil.json         P0   executed in simulation: simulated
iam-new-access-key.json          P2   none (alert and record only)
root-failed-login.json           P0   no safe automated action - human runbook step
sg-port-22-open.json             P1   executed in simulation: simulated
```

Five recorded attacks, five correct decisions. That recap table is the
whole project in ten lines.

## How it works

```
Root login ─────┐   GuardDuty finding ──┐     SG port opened ──┐   New IAM key ──┐
                ▼                      ▼                      ▼                 ▼
┌────────────────────────────────── EventBridge (4 rules) ──────────────────────────────┐
└──────────────────────────────────────────┬───────────────────────────────────────────┘
                                           ▼ ~1s
                              ┌────────────────────┐    ┌──────────────────────┐
                              │   TRIAGE LAMBDA    │───▶│  DynamoDB incident   │
                              │ score → decide →   │    │  log (KMS, 90d TTL)  │
                              │ record → alert     │    └──────────────────────┘
                              └───┬──────────┬─────┘    ┌──────────────────────┐
                    Slack/Discord│          │async     │  SES / SNS email     │
                    (KMS secret) ▼          ▼          └──────────────────────┘
                     ┌─────────────┐  ┌──────────────────┐
                     │ SLACK /     │  │  REMEDIATORS     │ separate IAM roles:
                     │ DISCORD     │  │  - close port 22 │ one revoke call
                     └─────────────┘  │  - freeze keys   │ one key flip
                                      └──────────────────┘
```

The separation is the security model: triage knows secrets and channels but
**cannot touch infrastructure**; remediators **touch one thing each** and
cannot read secrets. Even a fully compromised lambda can do exactly one
narrow thing - details in [docs/architecture.md](docs/architecture.md).

## What it watches

| Event | Severity | Automated response |
|---|---|---|
| Root sign-in (success **or** failure) | P0 | Alert - root can't be disabled by a robot, humans follow [the runbook](docs/runbook.md) |
| GuardDuty credential exfiltration (High) | P0 | **Quarantine:** every access key of that user → Inactive, in seconds |
| GuardDuty instance findings (High) | P0 | Alert - isolating prod is a business decision, not a reflex |
| SSH/RDP/DB port opened to `0.0.0.0/0` | P1 | **Revoke that exact tuple** within seconds, log the incident |
| World-open range on a non-flagged port | P2 | Alert + record - could be legitimate |
| New IAM access key | P2 | Alert + record |
| GuardDuty low findings | P3 | Record-only (the audit trail matters too) |

The full mapping with reasoning lives in [docs/detection-catalog.md](docs/detection-catalog.md).

## Quick start

### 0. Kick the tires (offline, 30 seconds)

```bash
git clone https://github.com/abdrahmentakrouni/cloud-incident-response.git
cd cloud-incident-response
pip install -r requirements-dev.txt
make test      # 37 unit tests
make simulate  # the demo above
```

### 1. Deploy (Terraform, ~2 minutes)

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # set alert_email

terraform init
terraform plan -out=tfplan   # read it - it is short and readable
terraform apply tfplan

# Recommended first day: dry_run = true in terraform.tfvars
# The remediators log every action they WOULD take. Flip to false when you trust the plans.
```

### 2. Finish the wiring (3 console clicks)

```bash
terraform output post_deploy_steps   # the ordered checklist:
```
1. Confirm the SNS subscription email (SES/SNS sandbox quirk: verify both addresses)
2. Store the channel webhook:
   ```bash
   aws secretsmanager put-secret-value \
     --secret-id $(terraform output -raw slack_secret_id) \
     --secret-string '{"webhook": "https://hooks.slack.com/services/..."}'
   ```
3. Try it: `python3 simulator/`'s root event is real-world shaped - or just
   attempt a (failing) root console login and watch the channel light up.

## Learning notes (the why behind the choices)

- **Event-driven, not cron.** Polling finds breaches after the report runs.
  EventBridge pushes each matching event in roughly a second, which is what
  makes "auto-closed within seconds" an architectural property, not a hope.
- **Separate remediator roles.** A single do-everything lambda means a single
  bug can read every secret AND mutate every SG. Three roles = three blast
  radii, each one API-call sized.
- **Root gets alerted, never acted on.** Robots that lock root accounts can
  brick the account they protect. Half-measures are worse than a loud page.
- **Quarantine is reversible, rotation is forever.** Disabling a key breaks
  the attack in one call; re-enabling a leaked key is never correct - so the
  runbook only ever says "issue a fresh one".
- **DLQ + alarms on the robot itself.** A response pipeline that dies quietly
  is worse than none. Every failed invocation parks in a queue that pages.

## Cost

GuardDuty is the only meaningful line item (~$4-5/month baseline for a
quiet account, plus ~$0.25/GB of DNS/flow-log analysis). Everything else -
Lambda, DynamoDB on-demand, SNS, SQS, Secrets Manager - sits comfortably
inside the free tier at portfolio scale. Delete the detector when done:
`terraform destroy` removes everything cleanly.

## Repo map

```
src/lib/          severity model, event normalizer, notify, incident store
src/responders/   triage (the brain) + the two single-purpose remediators
src/handler.py    the only AWS-facing surface (Lambda entrypoints)
simulator/        5 recorded events + the offline pipeline runner
tests/            37 tests: parsing, severity, planning, end-to-end triage
infra/            Terraform: 4 EventBridge rules, 3 lambdas, DynamoDB, SNS,
                  SES, Secrets Manager, KMS, DLQs, GuardDuty, alarms
docs/             architecture, detection catalog, runbook
```
