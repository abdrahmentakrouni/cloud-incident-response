# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-09-16

### Added
- Event-driven detection pipeline: four EventBridge rules covering root
  account activity, security group ingress changes, GuardDuty findings and
  new IAM access keys.
- Triage lambda: normalizes every tracked event into one incident shape,
  records it to a KMS-encrypted DynamoDB table (90-day TTL), scores it on a
  four-level policy (P0-P3) and fans a detailed report out to Slack,
  Discord and SES email.
- Auto-remediation plane with hard role separation:
  - SG responder revokes world-open ingress on dangerous ports (SSH, RDP,
    Telnet, FTP, MySQL, PostgreSQL, MSSQL, Redis, MongoDB) in seconds,
  - IAM quarantine responder disables all access keys named in GuardDuty
    credential-exfiltration findings.
- Safety switches: `auto_remediation` master switch, `dry_run` mode,
  reserved concurrency, dead-letter queues + CloudWatch alarms on errors
  and DLQ depth.
- Offline simulator (`simulator/simulate.py`) replaying five recorded
  real-world-shaped events through the production code paths.
- 37-test pytest suite covering parsing, severity bands, revoke planning
  (v4/v6 grouping) and the end-to-end triage decision tree.
- Terraform deployment in `infra/` (validated by fmt/validate/tflint and
  scanned by Checkov + tfsec in CI, 125 checks passing, 14 justified skips).
- Docs: architecture with threat-model reasoning, full detection catalog,
  on-call runbook (root compromise, key quarantine aftermath, DLQ redrive).
