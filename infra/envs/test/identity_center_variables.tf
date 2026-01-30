variable "enable_identity_center" {
  description = "Enable IAM Identity Center permission sets/groups/assignments"
  type        = bool
  default     = false
}

variable "identity_center_instance_arn" {
  description = "Identity Center instance ARN (optional; auto-discovered if empty)"
  type        = string
  default     = ""
}

variable "identity_store_id" {
  description = "Identity Store ID (optional; auto-discovered if empty)"
  type        = string
  default     = ""
}

variable "identity_center_account_id" {
  description = "Account ID for assignments (optional; defaults to current account)"
  type        = string
  default     = ""
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

variable "identity_center_create_groups" {
  description = "Create Identity Center groups"
  type        = bool
  default     = true
}

variable "identity_center_create_assignments" {
  description = "Create account assignments for groups"
  type        = bool
  default     = true
}

variable "identity_center_session_duration" {
  description = "Session duration for Identity Center permission sets (ISO 8601)"
  type        = string
  default     = "PT8H"
}
