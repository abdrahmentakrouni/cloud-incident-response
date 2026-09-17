# IAM for the pipeline: three roles, hard separation between detection
# and response.
#
#   triage        - record, notify, hand off. Cannot touch infrastructure.
#   remediate-sg  - revoke ingress. Cannot read secrets or the incident table.
#   remediate-iam - freeze access keys. Nothing else.
#
# Even a fully compromised responder lambda can only do the one thing it
# was built to do - that is the whole point of the split.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ------------------------------------------------------------------ triage --

resource "aws_iam_role" "triage" {
  name               = "${local.name_prefix}-triage"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "triage" {
  statement {
    sid    = "WriteIncidentLog"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [aws_dynamodb_table.incidents.arn]
  }

  statement {
    sid    = "SendAlertEmail"
    effect = "Allow"
    actions = [
      "ses:SendEmail",
      "ses:SendRawEmail",
    ]
    resources = [aws_ses_email_identity.alerts.arn]
  }

  statement {
    sid     = "ReadChannelWebhooks"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.slack.arn,
      aws_secretsmanager_secret.discord.arn,
    ]
  }

  statement {
    sid    = "DispatchRemediators"
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
      "lambda:InvokeAsync",
    ]
    resources = [
      aws_lambda_function.remediate_sg.arn,
      aws_lambda_function.remediate_iam.arn,
    ]
  }

  statement {
    sid    = "ParkFailedInvocations"
    effect = "Allow"
    actions = [
      "sqs:SendMessage",
      "sqs:SendMessageBatch",
    ]
    resources = [aws_sqs_queue.triage_dlq.arn]
  }

  statement {
    sid    = "PipelineCrypto"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.pipeline.arn]
  }

  statement {
    sid     = "LambdaLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    # tfsec:ignore:aws-iam-no-policy-wildcards the :* suffix is the canonical log-stream ARN form
    resources = ["${aws_cloudwatch_log_group.triage.arn}:*"]
  }

  statement {
    sid     = "XRayTracing"
    effect  = "Allow"
    actions = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    # tfsec:ignore:aws-iam-no-policy-wildcards xray write actions have no resource scope
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "triage" {
  name   = "triage-least-privilege"
  role   = aws_iam_role.triage.id
  policy = data.aws_iam_policy_document.triage.json
}

# ---------------------------------------------------------- sg remediator --

resource "aws_iam_role" "remediate_sg" {
  name               = "${local.name_prefix}-remediate-sg"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "remediate_sg" {
  statement {
    sid    = "ClosePublicPorts"
    effect = "Allow"
    actions = [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeSecurityGroups",
    ]
    # tfsec:ignore:aws-iam-no-policy-wildcards ec2 SG actions have no resource-level scope
    resources = ["*"]
    # checkov:skip=CKV_AWS_111:Revoke/Describe are the only writes this role may ever make; ec2 SG actions have no resource-level scope
    # checkov:skip=CKV_AWS_356:ec2 security group actions cannot be restricted by resource ARN
    # tfsec:ignore:aws-iam-no-policy-wildcards
  }

  statement {
    sid       = "AppendTimelineEntry"
    effect    = "Allow"
    actions   = ["dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }

  statement {
    sid       = "ParkFailedInvocations"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.sg_dlq.arn]
  }

  statement {
    sid    = "PipelineCrypto"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.pipeline.arn]
  }

  statement {
    sid     = "LambdaLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    # tfsec:ignore:aws-iam-no-policy-wildcards the :* suffix is the canonical log-stream ARN form
    resources = ["${aws_cloudwatch_log_group.remediate_sg.arn}:*"]
  }

  statement {
    sid       = "XRayTracing"
    effect    = "Allow"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
    # tfsec:ignore:aws-iam-no-policy-wildcards xray write actions have no resource scope
  }
}

resource "aws_iam_role_policy" "remediate_sg" {
  name   = "remediate-sg-least-privilege"
  role   = aws_iam_role.remediate_sg.id
  policy = data.aws_iam_policy_document.remediate_sg.json
}

# --------------------------------------------------------- iam remediator --

resource "aws_iam_role" "remediate_iam" {
  name               = "${local.name_prefix}-remediate-iam"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "remediate_iam" {
  statement {
    sid    = "FreezeCompromisedKeys"
    effect = "Allow"
    actions = [
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
    ]
    # tfsec:ignore:aws-iam-no-policy-wildcards affected user is only known at incident time
    resources = ["*"]
    # checkov:skip=CKV_AWS_107:UpdateAccessKey only flips Status to Inactive - no credential values are ever created or exposed
    # checkov:skip=CKV_AWS_109:metadata read plus a state flip; nothing here can grant permissions or expose secrets
    # checkov:skip=CKV_AWS_356:the compromised user is only known at incident time and cannot be pinned in Terraform
    # tfsec:ignore:aws-iam-no-policy-wildcards
  }

  statement {
    sid       = "AppendTimelineEntry"
    effect    = "Allow"
    actions   = ["dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }

  statement {
    sid       = "ParkFailedInvocations"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.iam_dlq.arn]
  }

  statement {
    sid    = "PipelineCrypto"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.pipeline.arn]
  }

  statement {
    sid     = "LambdaLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    # tfsec:ignore:aws-iam-no-policy-wildcards the :* suffix is the canonical log-stream ARN form
    resources = ["${aws_cloudwatch_log_group.remediate_iam.arn}:*"]
  }

  statement {
    sid     = "XRayTracing"
    effect  = "Allow"
    actions = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    # tfsec:ignore:aws-iam-no-policy-wildcards xray write actions have no resource scope
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediate_iam" {
  name   = "remediate-iam-least-privilege"
  role   = aws_iam_role.remediate_iam.id
  policy = data.aws_iam_policy_document.remediate_iam.json
}
