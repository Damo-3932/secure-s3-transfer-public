variable "enabled" {
  type        = bool
  description = "Enable email notifications when new .env files arrive."
  default     = false
}

variable "bucket_name" {
  type        = string
  description = "S3 transfer bucket name."
}

variable "bucket_arn" {
  type        = string
  description = "S3 transfer bucket ARN."
}

variable "notification_email" {
  type        = string
  description = "Email address to notify."
  default     = ""
}

variable "notification_prefix" {
  type        = string
  description = "S3 key prefix to match for notifications."
  default     = "incoming/"
}

variable "notification_suffix" {
  type        = string
  description = "S3 key suffix to match for notifications."
  default     = ".env"
}

variable "notification_message" {
  type        = string
  description = "Message body sent in the notification email."
  default     = "You have a new file to download from the bucket."
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to resources."
  default     = {}
}
