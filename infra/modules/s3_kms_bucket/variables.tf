variable "bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name"
}

variable "aws_region" {
  type        = string
  description = "AWS region for region-scoped policy conditions"
}

variable "kms_alias" {
  type        = string
  description = "KMS alias name, e.g. alias/secure-s3-transfer"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}

variable "incoming_prefix" {
  type        = string
  description = "Prefix for uploads"
  default     = "incoming/"
}

variable "artefacts_prefix" {
  type        = string
  description = "Prefix for metadata artefacts (hashes/manifests)"
  default     = "incoming/artefacts/"
}

variable "download_prefix" {
  type        = string
  description = "Prefix for post-download storage"
  default     = "downloaded/"
}

variable "name_prefix" {
  type        = string
  description = "Name prefix for IAM roles/policies"
  default     = "secure-s3-transfer"
}

variable "assume_role_principals" {
  type        = list(string)
  description = "List of AWS principal ARNs allowed to assume the uploader/ downloader roles."

  validation {
    condition     = length(var.assume_role_principals) > 0
    error_message = "assume_role_principals must contain at least one principal ARN."
  }

  validation {
    condition = alltrue([
      for arn in var.assume_role_principals : (
        can(regex("^arn:aws(-[a-z]+)?:iam::[0-9]{12}:(role|user)/.+$", arn)) ||
        can(regex("^arn:aws(-[a-z]+)?:iam::[0-9]{12}:root$", arn))
      )
    ])
    error_message = "assume_role_principals must be IAM role/user/root ARNs."
  }
}

variable "assume_role_external_id" {
  type        = string
  description = "Optional ExternalId required when assuming roles. Leave empty to disable."
}

variable "enable_transfer_acceleration" {
  type        = bool
  description = "Enable S3 Transfer Acceleration for the bucket."
  default     = true
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

  validation {
    condition = alltrue([
      for arn in var.kms_admin_principals : (
        can(regex("^arn:aws(-[a-z]+)?:iam::[0-9]{12}:(role|user)/.+$", arn)) ||
        can(regex("^arn:aws(-[a-z]+)?:iam::[0-9]{12}:root$", arn))
      )
    ])
    error_message = "kms_admin_principals must be IAM role/user/root ARNs."
  }
}

variable "delete_allowed_principal_arn_patterns" {
  type        = list(string)
  description = "Optional ADDITIONAL ARN patterns allowed to delete objects from incoming/ and artefacts/ prefixes. The Terraform-created downloader role is automatically included. Use this for Identity Center roles, admin roles, or other trusted principals."
  default     = []
}
