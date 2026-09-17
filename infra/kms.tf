# One customer-managed key encrypts the whole response plane:
# incident table, SNS topic, secrets, log groups, lambda env vars.
# Rotation is on; the key policy keeps the account root as recovery
# admin (AWS best practice - see the justified scanner skips below).

resource "aws_kms_key" "pipeline" {
  description             = "CMK for the cloud-incident-response pipeline"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "PipelineServicesUse"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.triage.arn,
            aws_iam_role.remediate_sg.arn,
            aws_iam_role.remediate_iam.arn,
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "pipeline" {
  name          = "alias/${local.name_prefix}-incident-response"
  target_key_id = aws_kms_key.pipeline.key_id
}

data "aws_caller_identity" "current" {}

# checkov:skip=CKV_AWS_109:Root-account statement is the AWS recovery pattern - the key would otherwise be unmanageable if the creating principal is deleted
# checkov:skip=CKV_AWS_111:Write actions intentionally scoped to this key only (kms:* on the key resource)
# checkov:skip=CKV_AWS_356:Wildcard in the root statement is required for account-level KMS administration
