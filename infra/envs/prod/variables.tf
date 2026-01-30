variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "aws_profile" {
  type        = string
  description = "AWS CLI profile name (SSO profile is fine)"
  default     = ""
}

variable "bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name"
}

variable "incoming_prefix" {
  type        = string
  description = "Incoming prefix for uploads"
  default     = "incoming/"
}

variable "artefacts_prefix" {
  type        = string
  description = "Artefacts prefix under incoming/"
  default     = "incoming/artefacts/"
}

variable "downloaded_prefix" {
  type        = string
  description = "Downloaded prefix for archived files"
  default     = "downloaded/"
}

variable "kms_alias" {
  type        = string
  description = "KMS alias name (e.g., alias/prod-secure-s3-transfer)"
}

variable "assume_role_principals" {
  type        = list(string)
  description = "Allow principals to assume uploader/ downloader roles."

  validation {
    condition     = length(var.assume_role_principals) > 0
    error_message = "assume_role_principals must contain at least one principal ARN."
  }
}

variable "assume_role_external_id" {
  type        = string
  description = "Optional ExternalId required for sts:AssumeRole."
  default     = ""
}

variable "audit_log_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for audit logs (CloudTrail)."
}

variable "audit_log_retention_days" {
  type        = number
  description = "Default Object Lock retention for audit logs."
  default     = 90
}

variable "lifecycle_expiration_days" {
  type        = number
  description = "Expire objects after this many days. Set to 0 to disable."
  default     = 2
}

variable "kms_admin_principals" {
  type        = list(string)
  description = "Optional IAM principal ARNs allowed to administer the KMS key."
  default     = []
}

variable "delete_allowed_principal_arn_patterns" {
  type        = list(string)
  description = "Optional ARN patterns allowed to delete objects."
  default     = []
}

variable "enable_alerting" {
  type        = bool
  description = "Enable alerting for critical changes"
  default     = true
}

variable "alert_email" {
  type        = string
  description = "Email address to receive alerts"
  default     = ""
}

variable "sns_kms_key_id" {
  type        = string
  description = "KMS key ID or alias for SNS topic encryption"
  default     = ""
}

variable "create_sns_cmk" {
  type        = bool
  description = "Create a customer-managed KMS key for SNS topic encryption"
  default     = true
}

variable "sns_kms_alias" {
  type        = string
  description = "KMS alias for SNS topic encryption key."
  default     = "alias/prod-secure-s3-transfer-sns"
}

variable "alerting_name_prefix" {
  type        = string
  description = "Name prefix for alerting resources (SNS topic, EventBridge rules)."
  default     = "prod-secure-s3-transfer"
}

variable "enable_incoming_env_email_notifications" {
  type        = bool
  description = "Enable simple email notifications for incoming .env files."
  default     = false
}

variable "incoming_env_notification_email" {
  type        = string
  description = "Email address to notify when a .env file is uploaded."
  default     = ""
}

variable "incoming_env_notification_prefix" {
  type        = string
  description = "S3 key prefix to match for incoming .env notifications."
  default     = "incoming/"
}

variable "incoming_env_notification_suffix" {
  type        = string
  description = "S3 key suffix to match for incoming .env notifications."
  default     = ".env"
}

variable "incoming_env_notification_message" {
  type        = string
  description = "Message body for incoming .env notifications."
  default     = "You have a new file to download from the bucket."
}
