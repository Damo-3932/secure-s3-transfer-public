output "sns_topic_arn" {
  value       = try(aws_sns_topic.alerts[0].arn, "")
  description = "SNS topic ARN for alerts"
}
