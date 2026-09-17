# Incident response runbook

The robot does the first ten seconds. This runbook is the next ten minutes.
It is written for the on-call engineer who just received a P0/P1 alert and
needs to know, in order: contain, verify, fix, learn.

Before anything: the incident ID in the alert (e.g. `IR-20260916-1a2b3c4d`)
is the key to the full story - query the incident table with it and you get
every action the pipeline already took, with timestamps.

```bash
aws dynamodb get-item --table-name cir-incidents \
  --key '{"incident_id": {"S": "IR-20260916-1a2b3c4d"}}'
```

## P0 - Root activity

Either you (or a teammate) signed in as root, or someone is trying to.

1. **Verify intent** (2 minutes): ask in the team channel whether anyone used
   root. Nobody? Continue.
2. **Check the source IP** in the incident evidence. Unknown country / VPN
   exit node / hosting provider = treat as attacker.
3. **Harden immediately**:
   - Confirm root MFA is still enabled (`IAM → Root user → Security
     recommendations` - never disable root MFA "to test").
   - Rotate the root password.
   - Review CloudTrail for the last 24h filtered on
     `userIdentity.type = Root` - list every action the session (if any)
     actually performed.
4. **If actions happened that nobody owns**: assume account compromise.
   Contact AWS Support (account & billing category), rotate every credential
   mentioned in section P0 of the AWS incident response guide, and check the
   CloudTrail data-event history for tampering.
5. **Close the loop**: append findings to the incident timeline with
   `aws dynamodb update-item`, then file the retro.

## P0 - GuardDuty credential finding (keys auto-quarantined)

The pipeline already disabled the user's access keys. Your job is the
aftermath:

1. **Identify the blast radius**: `aws iam list-access-keys --user-name
   <user>` (should show all keys Inactive), then look at CloudTrail for
   everything that identity did in the last 24 hours.
2. **Find the leak source**: the finding type says where the key surfaced
   (public repo, exfiltrated instance role, phishing). Fix that source
   before ANY new key is issued - otherwise you are handing the same
   attacker a fresh key.
3. **Re-issue, never re-enable**: create a new key, update the workload's
   secret store, verify the old key is gone. Re-enabling a leaked key is
   never correct.
4. **If the user had privileged policies**: review every API call made with
   the exfiltrated key (CloudTrail `userIdentity.accessKeyId` filter).

## P1 - Public SSH/RDP opened (port auto-closed)

The robot already revoked the exact tuple. Now determine whether it was an
accident or a reconnaissance step:

1. **Ask who made the change** - the incident actor field names the IAM
   identity. Console click by a teammate at 2pm is an accident; API call
   from a bare automation role at 3am deserves a closer look.
2. **Check for siblings**: `aws ec2 describe-security-groups --filters
   Name=ip-permission.cidr,Values=0.0.0.0/0` - are there other world-open
   management ports the one event didn't cover?
3. **Check CloudTrail** for `AuthorizeSecurityGroupIngress` across all
   regions for the last 7 days. One mistake is a mistake; a pattern is
   an investigation.
4. **If the port was needed**: use SSM Session Manager or a bastion instead
   of re-opening. If it truly must be open, scope the CIDR to the office/VPN
   range - the pipeline only fires on world-open ranges.

## P1 - GuardDuty medium findings

1. Read the finding in the GuardDuty console (the incident carries the
   finding type; the console has the full context and sample evidence).
2. GuardDuty Medium findings are frequently noise from aggressive scanners -
   archive them in GuardDuty if verified benign, and note the decision in
   the incident timeline.

## P2 - New IAM access key

1. Confirm the key is expected: ask the team channel, check the incident's
   `target_user`.
2. Unexpected? Disable it (or let this pipeline's P0 path quarantine it),
   then find out who/what created it and why.
3. Expected? Consider whether it can be a short-lived role session instead -
   every long-lived key is a future incident in waiting.

## DLQ alarms (`*-dlq-not-empty`)

A response action failed after retries. Nothing was silently dropped:

1. List the messages: `aws sqs receive-message --queue-url
   <dlq-url-from-outputs> --max-number-of-messages 10`
2. Each message body is the remediation payload triage sent. The common
   causes are IAM drift (a role policy was edited) or a quota/rate error
   during a burst.
3. Fix the cause, then redrive:
   `aws sqs start-message-move-task --source-arn <dlq-arn> --destination-arn <triage/remediator-function-arn>`
4. If the action is no longer relevant (incident already handled manually),
   delete the message and note that in the incident timeline instead.

## Redriving and replaying

Every incident is data. To rebuild what happened during a postmortem:

1. Query the table by date (`detected_at` begins with the date prefix) or
   pull the specific incident IDs from the channel history.
2. For any incident, the raw event can be replayed offline through the
   simulator to see exactly which decision branch ran:
   `python3 simulator/simulate.py --event path/to/event.json`

## Weekly hygiene (5 minutes)

- Skim `aws dynamodb scan --table-name cir-incidents` for P3 patterns
  becoming frequent - new detections are born from recurring P3s.
- Confirm both DLQ alarms and both secret webhooks are still configured.
- Review GuardDuty's suppressed findings - suppression lists rot.
