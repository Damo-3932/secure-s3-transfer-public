provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
}

provider "aws" {
  alias   = "use1"
  region  = "us-east-1"
  profile = var.aws_profile != "" ? var.aws_profile : null
}

// Core transfer bucket + roles + KMS key.
module "secure_bucket" {
  source                                = "../../modules/s3_kms_bucket"
  bucket_name                           = var.bucket_name
  aws_region                            = var.aws_region
  kms_alias                             = var.kms_alias
  name_prefix                           = "prod-secure-s3-transfer"
  artefacts_prefix                      = "incoming/artefacts/"
  enable_transfer_acceleration          = true
  lifecycle_expiration_days             = var.lifecycle_expiration_days
  assume_role_principals                = var.assume_role_principals
  assume_role_external_id               = var.assume_role_external_id
  kms_admin_principals                  = var.kms_admin_principals
  delete_allowed_principal_arn_patterns = var.delete_allowed_principal_arn_patterns

  tags = {
    Project     = "SecureS3Transfer"
    Environment = "Prod"
    ManagedBy   = "Terraform"
  }
}


// CloudTrail + immutable audit log bucket.
module "audit_logging" {
  source                = "../../modules/audit_logging"
  name_prefix           = "prod-secure-s3-transfer"
  aws_region            = var.aws_region
  audit_log_bucket_name = var.audit_log_bucket_name
  retention_days        = var.audit_log_retention_days
  monitored_bucket_arn  = module.secure_bucket.bucket_arn
  kms_key_arn           = module.secure_bucket.kms_key_arn

  tags = {
    Project     = "SecureS3Transfer"
    Environment = "Prod"
    ManagedBy   = "Terraform"
  }
}

// Optional IAM Identity Center (SSO) permission sets/groups.
module "identity_center" {
  source = "../../modules/identity_center"

  enabled                      = var.enable_identity_center
  identity_center_instance_arn = var.identity_center_instance_arn
  identity_store_id            = var.identity_store_id
  account_id                   = var.identity_center_account_id

  aws_region        = var.aws_region
  bucket_arn        = module.secure_bucket.bucket_arn
  incoming_prefix   = var.incoming_prefix
  artefacts_prefix  = var.artefacts_prefix
  downloaded_prefix = var.downloaded_prefix
  kms_key_arn       = module.secure_bucket.kms_key_arn

  uploader_permission_set_name   = var.uploader_permission_set_name
  downloader_permission_set_name = var.downloader_permission_set_name
  uploader_group_name            = var.uploader_group_name
  downloader_group_name          = var.downloader_group_name
  create_groups                  = var.identity_center_create_groups
  create_assignments             = var.identity_center_create_assignments
  session_duration               = var.identity_center_session_duration

  tags = {
    Project     = "SecureS3Transfer"
    Environment = "Prod"
    ManagedBy   = "Terraform"
  }
}

module "incoming_env_email_notifications" {
  source = "../../modules/incoming_env_email_notifications"

  enabled             = var.enable_incoming_env_email_notifications
  bucket_name         = module.secure_bucket.bucket_name
  bucket_arn          = module.secure_bucket.bucket_arn
  notification_email  = var.incoming_env_notification_email
  notification_prefix = var.incoming_env_notification_prefix
  notification_suffix = var.incoming_env_notification_suffix
  notification_message = var.incoming_env_notification_message

  tags = {
    Project     = "SecureS3Transfer"
    Environment = "Prod"
    ManagedBy   = "Terraform"
  }
}

module "alerting" {
  source = "../../modules/alerting"

  enabled              = var.enable_alerting
  alert_email          = var.alert_email
  sns_kms_key_id       = var.sns_kms_key_id
  create_sns_cmk       = var.create_sns_cmk
  sns_kms_alias        = var.sns_kms_alias
  name_prefix          = var.alerting_name_prefix
  bucket_name          = module.secure_bucket.bucket_name
  kms_key_arn          = module.secure_bucket.kms_key_arn
  uploader_role_name   = module.secure_bucket.uploader_role_name
  downloader_role_name = module.secure_bucket.downloader_role_name
  include_iam_alerts   = false

  tags = {
    Project     = "SecureS3Transfer"
    Environment = "Prod"
    ManagedBy   = "Terraform"
  }
}

module "alerting_iam_global" {
  source = "../../modules/alerting"
  providers = {
    aws = aws.use1
  }

  enabled              = var.enable_alerting
  alert_email          = var.alert_email
  sns_kms_key_id       = var.sns_kms_key_id
  create_sns_cmk       = var.create_sns_cmk
  sns_kms_alias        = var.sns_kms_alias
  name_prefix          = var.alerting_name_prefix
  bucket_name          = module.secure_bucket.bucket_name
  kms_key_arn          = module.secure_bucket.kms_key_arn
  uploader_role_name   = module.secure_bucket.uploader_role_name
  downloader_role_name = module.secure_bucket.downloader_role_name
  include_s3_alerts    = false
  include_kms_alerts   = false
  include_iam_alerts   = true

  tags = {
    Project     = "SecureS3Transfer"
    Environment = "Prod"
    ManagedBy   = "Terraform"
  }
}
