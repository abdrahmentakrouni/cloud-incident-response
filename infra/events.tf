# Event plane: four EventBridge rules, one target. This is the
# "event-driven security" backbone - nothing polls, nothing schedules;
# AWS pushes each matching event to triage within roughly a second.

resource "aws_cloudwatch_event_rule" "root_activity" {
  name        = "${local.name_prefix}-root-activity"
  description = "Any console sign-in or API call made by the Root user (success or failure)."

  event_pattern = jsonencode({
    detail-type = [
      "AWS Console Sign In via CloudTrail",
      "AWS API Call via CloudTrail",
    ]
    detail = {
      userIdentity = { type = ["Root"] }
    }
  })
}

resource "aws_cloudwatch_event_rule" "sg_ingress" {
  name        = "${local.name_prefix}-sg-ingress-open"
  description = "Ingress rules being added - the raw feed the SG responder triages."

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${local.name_prefix}-guardduty-findings"
  description = "Every GuardDuty finding, from Low to Critical."

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_rule" "iam_keys" {
  name        = "${local.name_prefix}-iam-key-created"
  description = "New long-lived access keys - standing credentials appear here first."

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateAccessKey"]
    }
  })
}

# -------------------------------------------------------------- targets --

resource "aws_lambda_permission" "root_activity" {
  statement_id  = "allow-root-activity-rule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.root_activity.arn
}

resource "aws_lambda_permission" "sg_ingress" {
  statement_id  = "allow-sg-ingress-rule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_ingress.arn
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "allow-guardduty-rule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}

resource "aws_lambda_permission" "iam_keys" {
  statement_id  = "allow-iam-keys-rule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_keys.arn
}

resource "aws_cloudwatch_event_target" "triage" {
  for_each = {
    root_activity = aws_cloudwatch_event_rule.root_activity
    sg_ingress    = aws_cloudwatch_event_rule.sg_ingress
    guardduty     = aws_cloudwatch_event_rule.guardduty
    iam_keys      = aws_cloudwatch_event_rule.iam_keys
  }

  rule = each.value.name
  arn  = aws_lambda_function.triage.arn
}
