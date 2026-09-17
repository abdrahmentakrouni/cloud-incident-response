variable "project_name" {
  description = "Short name used to prefix every resource."
  type        = string
  default     = "cir"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 2-20 chars: lowercase letters, digits, dashes."
  }
}

variable "aws_region" {
  description = "Region the pipeline is deployed into. Keep it close to your workloads - GuardDuty findings are regional."
  type        = string
  default     = "eu-west-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid AWS region, e.g. eu-west-1."
  }
}

variable "alert_email" {
  description = "On-call mailbox that receives every incident report via SES. Must confirm the SES subscription on first deploy."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "alert_from_email" {
  description = "SES-verified sender address for incident emails."
  type        = string
  default     = "alerts@example.com"
}

variable "auto_remediation" {
  description = "Master switch for automated response. false = detect, alert and record, but never touch infrastructure."
  type        = bool
  default     = true
}

variable "dry_run" {
  description = "DRY-RUN mode: responders compute and log every action but call no mutating AWS API. Deploy true first, watch the logs for a day, then flip."
  type        = bool
  default     = false
}

variable "incident_retention_days" {
  description = "How long incidents live in DynamoDB before the TTL sweeper deletes them."
  type        = number
  default     = 90

  validation {
    condition     = var.incident_retention_days >= 30 && var.incident_retention_days <= 365
    error_message = "incident_retention_days must be between 30 and 365."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the lambda log groups."
  type        = number
  default     = 365
}

variable "triage_reserved_concurrency" {
  description = "Reserved concurrent executions for triage. During a real campaign events arrive in bursts; do not set this below 10."
  type        = number
  default     = 20
}

variable "remediator_reserved_concurrency" {
  description = "Reserved concurrent executions for each remediator lambda."
  type        = number
  default     = 10
}

variable "tags" {
  description = "Extra tags merged onto every resource."
  type        = map(string)
  default     = {}
}
