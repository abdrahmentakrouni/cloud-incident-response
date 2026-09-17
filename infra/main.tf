# Compute plane: one triage lambda + two single-purpose remediators,
# all bundled from the same Python sources by the archive provider.

data "archive_file" "pipeline" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/pipeline.zip"
}

# ------------------------------------------------------------ log groups --

resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${local.name_prefix}-triage"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pipeline.arn
}

resource "aws_cloudwatch_log_group" "remediate_sg" {
  name              = "/aws/lambda/${local.name_prefix}-remediate-sg"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pipeline.arn
}

resource "aws_cloudwatch_log_group" "remediate_iam" {
  name              = "/aws/lambda/${local.name_prefix}-remediate-iam"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pipeline.arn
}

# ----------------------------------------------------------------- DLQs --

resource "aws_sqs_queue" "triage_dlq" {
  name                      = "${local.name_prefix}-triage-dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600 # 14 days to redrive
  tags                      = local.tags
}

resource "aws_sqs_queue" "sg_dlq" {
  name                      = "${local.name_prefix}-remediate-sg-dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600
  tags                      = local.tags
}

resource "aws_sqs_queue" "iam_dlq" {
  name                      = "${local.name_prefix}-remediate-iam-dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600
  tags                      = local.tags
}

# --------------------------------------------------------------- triage --

resource "aws_lambda_function" "triage" {
  # checkov:skip=CKV_AWS_117:calls public AWS service endpoints only - VPC attach adds ENI cold starts and NAT cost with no data-path security gain
  # checkov:skip=CKV_AWS_272:single-maintainer pipeline; signer infrastructure is roadmap (docs/architecture.md)
  function_name = "${local.name_prefix}-triage"
  description   = "Triage security events: record, decide, dispatch, alert."
  role          = aws_iam_role.triage.arn

  filename         = data.archive_file.pipeline.output_path
  source_code_hash = data.archive_file.pipeline.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.triage_handler"
  timeout          = 30
  memory_size      = 256

  reserved_concurrent_executions = var.triage_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  kms_key_arn = aws_kms_key.pipeline.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.triage_dlq.arn
  }

  environment {
    variables = {
      INCIDENTS_TABLE            = aws_dynamodb_table.incidents.name
      INCIDENT_TTL_DAYS          = var.incident_retention_days
      ALERT_EMAIL                = var.alert_email
      ALERT_FROM                 = var.alert_from_email
      SLACK_WEBHOOK_SECRET_ARN   = aws_secretsmanager_secret.slack.arn
      DISCORD_WEBHOOK_SECRET_ARN = aws_secretsmanager_secret.discord.arn
      REMEDIATOR_SG_ARN          = aws_lambda_function.remediate_sg.arn
      REMEDIATOR_IAM_ARN         = aws_lambda_function.remediate_iam.arn
      AUTO_REMEDIATION           = tostring(var.auto_remediation)
      LOG_LEVEL                  = "INFO"
    }
  }

  depends_on = [aws_cloudwatch_log_group.triage]
}

# ------------------------------------------------------- sg remediator --

resource "aws_lambda_function" "remediate_sg" {
  # checkov:skip=CKV_AWS_117:calls public AWS service endpoints only - VPC attach adds ENI cold starts and NAT cost with no data-path security gain
  # checkov:skip=CKV_AWS_272:single-maintainer pipeline; signer infrastructure is roadmap (docs/architecture.md)
  function_name = "${local.name_prefix}-remediate-sg"
  description   = "Close world-open management ports inside seconds."
  role          = aws_iam_role.remediate_sg.arn

  filename         = data.archive_file.pipeline.output_path
  source_code_hash = data.archive_file.pipeline.output_base64sha256
  runtime          = "python3.12"
  handler          = "responders.remediate_sg.lambda_handler"
  timeout          = 15
  memory_size      = 128

  reserved_concurrent_executions = var.remediator_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  kms_key_arn = aws_kms_key.pipeline.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.sg_dlq.arn
  }

  environment {
    variables = {
      DRY_RUN         = tostring(var.dry_run)
      INCIDENTS_TABLE = aws_dynamodb_table.incidents.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.remediate_sg]
}

# ------------------------------------------------------ iam remediator --

resource "aws_lambda_function" "remediate_iam" {
  # checkov:skip=CKV_AWS_117:calls public AWS service endpoints only - VPC attach adds ENI cold starts and NAT cost with no data-path security gain
  # checkov:skip=CKV_AWS_272:single-maintainer pipeline; signer infrastructure is roadmap (docs/architecture.md)
  function_name = "${local.name_prefix}-remediate-iam"
  description   = "Disable access keys named in GuardDuty credential findings."
  role          = aws_iam_role.remediate_iam.arn

  filename         = data.archive_file.pipeline.output_path
  source_code_hash = data.archive_file.pipeline.output_base64sha256
  runtime          = "python3.12"
  handler          = "responders.quarantine_iam.lambda_handler"
  timeout          = 15
  memory_size      = 128

  reserved_concurrent_executions = var.remediator_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  kms_key_arn = aws_kms_key.pipeline.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.iam_dlq.arn
  }

  environment {
    variables = {
      DRY_RUN         = tostring(var.dry_run)
      INCIDENTS_TABLE = aws_dynamodb_table.incidents.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.remediate_iam]
}
