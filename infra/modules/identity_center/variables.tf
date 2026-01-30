variable "enabled" {
  description = "Whether to manage IAM Identity Center permission sets, groups, and assignments"
  type        = bool
  default     = false
}

variable "identity_center_instance_arn" {
  description = "Identity Center instance ARN (leave empty to auto-discover)"
  type        = string
  default     = ""
}

variable "identity_store_id" {
  description = "Identity Store ID (leave empty to auto-discover)"
  type        = string
  default     = ""
}

variable "account_id" {
  description = "AWS account ID for assignments (leave empty to use current account)"
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "AWS region for condition values"
  type        = string
}

variable "bucket_arn" {
  description = "S3 bucket ARN for policy resources"
  type        = string
}

variable "incoming_prefix" {
  description = "Incoming prefix (e.g., incoming/)"
  type        = string
}

variable "artefacts_prefix" {
  description = "Artefacts prefix (e.g., incoming/artefacts/)"
  type        = string
}

variable "downloaded_prefix" {
  description = "Downloaded prefix (e.g., downloaded/)"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN used for encryption"
  type        = string
}

variable "uploader_permission_set_name" {
  description = "Permission set name for uploader"
  type        = string
  default     = "SecureS3Transfer-Uploader"
}

variable "downloader_permission_set_name" {
  description = "Permission set name for downloader"
  type        = string
  default     = "SecureS3Transfer-Downloader"
}

variable "uploader_group_name" {
  description = "Identity Center group name for uploader"
  type        = string
  default     = "SecureS3Transfer-Uploader"
}

variable "downloader_group_name" {
  description = "Identity Center group name for downloader"
  type        = string
  default     = "SecureS3Transfer-Downloader"
}

variable "create_groups" {
  description = "Create Identity Center groups"
  type        = bool
  default     = true
}

variable "create_assignments" {
  description = "Create account assignments linking permission sets to groups"
  type        = bool
  default     = true
}

variable "session_duration" {
  description = "Session duration for permission sets (ISO 8601), e.g., PT8H"
  type        = string
  default     = "PT8H"
}

variable "tags" {
  description = "Tags applied to permission sets"
  type        = map(string)
  default     = {}
}
