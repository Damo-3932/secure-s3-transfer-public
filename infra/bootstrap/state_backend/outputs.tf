output "state_bucket_name" {
  value       = aws_s3_bucket.tf_state.bucket
  description = "S3 bucket name for Terraform remote state."
}

output "lock_table_name" {
  value       = aws_dynamodb_table.tf_locks.name
  description = "DynamoDB table name used for Terraform state locking."
}

output "state_kms_key_arn" {
  value       = aws_kms_key.tf_state.arn
  description = "KMS key ARN for state bucket encryption."
}

output "state_kms_alias" {
  value       = aws_kms_alias.tf_state.name
  description = "KMS alias for the state bucket key."
}
