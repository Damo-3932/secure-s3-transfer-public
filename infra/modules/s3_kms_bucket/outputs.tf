output "bucket_name" {
  value       = aws_s3_bucket.this.bucket
  description = "S3 bucket name"
}

output "bucket_arn" {
  value       = aws_s3_bucket.this.arn
  description = "S3 bucket ARN"
}

output "kms_key_arn" {
  value       = aws_kms_key.this.arn
  description = "KMS key ARN used for bucket encryption"
}

output "kms_alias" {
  value       = aws_kms_alias.this.name
  description = "KMS alias name"
}

output "uploader_role_arn" {
  value       = aws_iam_role.uploader.arn
  description = "Uploader role ARN"
}

output "uploader_role_name" {
  value       = aws_iam_role.uploader.name
  description = "Uploader role name"
}

output "downloader_role_arn" {
  value       = aws_iam_role.downloader.arn
  description = "Downloader role ARN"
}

output "downloader_role_name" {
  value       = aws_iam_role.downloader.name
  description = "Downloader role name"
}

output "incoming_prefix" {
  value       = var.incoming_prefix
  description = "Incoming S3 prefix for uploads"
}

output "artefacts_prefix" {
  value       = var.artefacts_prefix
  description = "Artefacts S3 prefix for metadata (hashes/manifests)"
}

output "download_prefix" {
  value       = var.download_prefix
  description = "Download/archive S3 prefix"
}

output "downloaded_artefacts_prefix" {
  value       = "${var.download_prefix}artefacts/"
  description = "Download/archive prefix for artefacts"
}
