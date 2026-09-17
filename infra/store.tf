# Memory plane: the incident store, the alert fan-out, and the webhook
# secret shells. Everything here is encrypted with the pipeline CMK.

# ------------------------------------------------------------ incidents --

resource "aws_dynamodb_table" "incidents" {
  name         = "${local.name_prefix}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.pipeline.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ---------------------------------------------------------------- alerts --

resource "aws_sns_topic" "alerts" {
  name              = "${local.name_prefix}-security-alerts"
  kms_master_key_id = aws_kms_key.pipeline.arn
}

resource "aws_sns_topic_subscription" "on_call_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email # operator must click the confirmation mail
}

resource "aws_ses_email_identity" "alerts" {
  email = var.alert_from_email
}

# --------------------------------------------------------------- secrets --

resource "aws_secretsmanager_secret" "slack" {
  # checkov:skip=CKV2_AWS_57:Slack/Discord webhooks are static URLs with no rotation API - rotation is manual, per docs/runbook.md
  name                    = local.slack_secret_name
  description             = "Slack webhook of the security-engineers channel. Value is stored by the operator AFTER deploy - never in Terraform state."
  kms_key_id              = aws_kms_key.pipeline.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret" "discord" {
  # checkov:skip=CKV2_AWS_57:Slack/Discord webhooks are static URLs with no rotation API - rotation is manual, per docs/runbook.md
  name                    = local.discord_secret_name
  description             = "Discord webhook of the private security channel. Value is stored by the operator AFTER deploy."
  kms_key_id              = aws_kms_key.pipeline.arn
  recovery_window_in_days = 7
}
