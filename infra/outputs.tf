output "triage_function_name" {
  description = "Lambda triaging every security event."
  value       = aws_lambda_function.triage.function_name
}

output "incidents_table_name" {
  description = "DynamoDB table holding the incident audit trail."
  value       = aws_dynamodb_table.incidents.name
}

output "sns_topic_arn" {
  description = "Topic every infrastructure alarm lands on."
  value       = aws_sns_topic.alerts.arn
}

output "slack_secret_id" {
  description = "Put the Slack webhook here after deploy (see locals.tf comment)."
  value       = aws_secretsmanager_secret.slack.name
}

output "discord_secret_id" {
  description = "Put the Discord webhook here after deploy."
  value       = aws_secretsmanager_secret.discord.name
}

output "detector_id" {
  description = "GuardDuty detector feeding the pipeline."
  value       = aws_guardduty_detector.main.id
}

output "post_deploy_steps" {
  description = "Ordered manual steps that complete the deployment."
  value = [
    "1. Confirm the SNS subscription email sent to ${var.alert_email}",
    "2. Verify the SES identity ${var.alert_from_email} (sandbox: verify the recipient too)",
    "3. Store the channel webhook: aws secretsmanager put-secret-value --secret-id ${aws_secretsmanager_secret.slack.name} --secret-string '{\"webhook\": \"https://hooks.slack.com/services/...\"}'",
    "4. Optionally repeat step 3 for ${aws_secretsmanager_secret.discord.name}",
    "5. dry_run=true deploys should watch logs for a day before flipping: terraform apply -var dry_run=false",
  ]
}
