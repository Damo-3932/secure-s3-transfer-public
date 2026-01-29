output "bucket_name" {
  value = module.secure_bucket.bucket_name
}

output "aws_region" {
  value = var.aws_region
}

output "bucket_arn" {
  value = module.secure_bucket.bucket_arn
}

output "kms_key_arn" {
  value = module.secure_bucket.kms_key_arn
}

output "kms_alias_name" {
  value = module.secure_bucket.kms_alias
}

output "uploader_role_arn" {
  value = module.secure_bucket.uploader_role_arn
}

output "uploader_role_name" {
  value = module.secure_bucket.uploader_role_name
}

output "downloader_role_arn" {
  value = module.secure_bucket.downloader_role_arn
}

output "downloader_role_name" {
  value = module.secure_bucket.downloader_role_name
}

output "incoming_prefix" {
  value = module.secure_bucket.incoming_prefix
}

output "artefacts_prefix" {
  value = module.secure_bucket.artefacts_prefix
}

output "download_prefix" {
  value = module.secure_bucket.download_prefix
}

output "downloaded_artefacts_prefix" {
  value = module.secure_bucket.downloaded_artefacts_prefix
}

output "audit_log_bucket_name" {
  value = module.audit_logging.audit_log_bucket_name
}

output "cloudtrail_name" {
  value = module.audit_logging.cloudtrail_name
}

output "cloudwatch_log_group_name" {
  value = module.audit_logging.cloudwatch_log_group_name
}
