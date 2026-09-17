# Self-monitoring: a security pipeline that dies quietly is worse than
# none. Lambda errors and anything landing in a DLQ page the same
# channel the incidents do.

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = {
    triage        = aws_lambda_function.triage.function_name
    remediate_sg  = aws_lambda_function.remediate_sg.function_name
    remediate_iam = aws_lambda_function.remediate_iam.function_name
  }

  alarm_name          = "${local.name_prefix}-${each.key}-errors"
  alarm_description   = "Errors raised by ${each.key} - incidents may go unprocessed."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  for_each = {
    triage = aws_sqs_queue.triage_dlq.arn
    sg     = aws_sqs_queue.sg_dlq.arn
    iam    = aws_sqs_queue.iam_dlq.arn
  }

  alarm_name          = "${local.name_prefix}-${each.key}-dlq-not-empty"
  alarm_description   = "Failed invocations parked in ${each.key} DLQ - redrive per docs/runbook.md."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = split(":", each.value)[5]
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}
