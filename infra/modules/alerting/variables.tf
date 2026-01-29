variable "enabled" {
  type        = bool
  description = "Enable alerting resources"
  default     = true
}

variable "name_prefix" {
  type        = string
  description = "Name prefix for alerting resources (SNS topic, EventBridge rules)."
  default     = "secure-s3-transfer"
}

variable "alert_email" {
  type        = string
  description = "Email address to receive alerts"
}

variable "sns_kms_key_id" {
  type        = string
  description = "KMS key ID or alias for SNS topic encryption."
  default     = ""
}

variable "create_sns_cmk" {
  type        = bool
  description = "Create a customer-managed KMS key for SNS topic encryption."
  default     = true
}

variable "sns_kms_alias" {
  type        = string
  description = "KMS alias for SNS topic encryption key."
  default     = "alias/secure-s3-transfer-sns"
}

variable "include_s3_alerts" {
  type        = bool
  description = "Enable S3-related alerts"
  default     = true
}

variable "include_kms_alerts" {
  type        = bool
  description = "Enable KMS-related alerts"
  default     = true
}

variable "include_iam_alerts" {
  type        = bool
  description = "Enable IAM-related alerts"
  default     = true
}

variable "bucket_name" {
  type        = string
  description = "S3 bucket name to monitor"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN to monitor"
}

variable "uploader_role_name" {
  type        = string
  description = "Uploader role name to monitor for policy changes"
}

variable "downloader_role_name" {
  type        = string
  description = "Downloader role name to monitor for policy changes"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to resources"
  default     = {}
}
