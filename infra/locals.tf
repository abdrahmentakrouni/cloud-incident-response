locals {
  name_prefix = var.project_name

  # The Slack/Discord webhooks are stored by the operator AFTER deploy:
  #   aws secretsmanager put-secret-value \
  #     --secret-id $(terraform output -raw slack_secret_id) \
  #     --secret-string '{"webhook": "https://hooks.slack.com/services/..."}'
  # Terraform creates the empty secret shells - it must never hold the
  # webhook value itself, or it would land in state in plaintext.
  slack_secret_name   = "${local.name_prefix}/alerts/slack-webhook"
  discord_secret_name = "${local.name_prefix}/alerts/discord-webhook"

  tags = merge(
    {
      Project   = "cloud-incident-response"
      ManagedBy = "terraform"
      Component = "security-automation"
    },
    var.tags,
  )
}
