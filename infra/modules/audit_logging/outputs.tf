output "audit_log_bucket_name" {
  value = aws_s3_bucket.audit.bucket
}

output "cloudtrail_name" {
  value = aws_cloudtrail.trail.name
}

output "cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.trail.name
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.trail.arn
}
