variable "aws_region" {
  type        = string
  description = "AWS region for CloudTrail and log bucket."
}

variable "name_prefix" {
  type        = string
  description = "Prefix used for naming CloudTrail resources."
}

variable "audit_log_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for audit logs."
}

variable "monitored_bucket_arn" {
  type        = string
  description = "S3 bucket ARN to capture data events for."
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN to capture data events for."
}

variable "retention_days" {
  type        = number
  description = "Default Object Lock retention in days for audit logs."
  default     = 90
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to audit logging resources."
  default     = {}
}
