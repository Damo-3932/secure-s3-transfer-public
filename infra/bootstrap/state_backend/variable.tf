variable "aws_region" {
  type        = string
  description = "AWS region for the Terraform state backend resources."
  default     = "ap-southeast-2"
}

variable "aws_profile" {
  type        = string
  description = "AWS CLI profile name (SSO)."
  default     = ""
}

variable "state_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name to store Terraform state."
}

variable "lock_table_name" {
  type        = string
  description = "DynamoDB table name for Terraform state locking."
  default     = "terraform-locks"
}

variable "kms_alias" {
  type        = string
  description = "KMS alias for encrypting the state bucket (e.g., alias/secure-s3-transfer-state)."
  default     = "alias/secure-s3-transfer-state"
}

variable "dynamodb_kms_alias" {
  type        = string
  description = "KMS alias for encrypting the DynamoDB lock table (e.g., alias/secure-s3-transfer-locks)."
  default     = "alias/secure-s3-transfer-locks"
}

variable "state_log_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for Terraform state access logs."
}

variable "tags" {
  type        = map(string)
  description = "Tages applied to backend resources."
  default = {
    Project   = "SecureS3Transfer"
    ManagedBy = "Terraform"
    Purpose   = "TerraformState"
  }
}
