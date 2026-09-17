# GuardDuty is the threat-intelligence feed. One detector covers the
# whole account in this region: runtime malware, credential exfiltration,
# Tor exit-node use, unusual API patterns - without a single agent to
# install. Findings flow to EventBridge automatically.

resource "aws_guardduty_detector" "main" {
  enable = true
  # checkov:skip=CKV2_AWS_3:standalone account deployment - AWS Organizations delegation does not apply

  # Findings also ship to the detector's own console and can be exported
  # to S3 separately; this pipeline consumes the real-time EventBridge
  # stream, which needs no extra configuration.
}
