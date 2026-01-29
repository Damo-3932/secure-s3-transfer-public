output "uploader_permission_set_arn" {
  value       = try(aws_ssoadmin_permission_set.uploader[0].arn, "")
  description = "Uploader permission set ARN"
}

output "downloader_permission_set_arn" {
  value       = try(aws_ssoadmin_permission_set.downloader[0].arn, "")
  description = "Downloader permission set ARN"
}

output "uploader_group_id" {
  value       = try(aws_identitystore_group.uploader_group[0].group_id, data.aws_identitystore_group.uploader_group[0].group_id, "")
  description = "Uploader group ID"
}

output "downloader_group_id" {
  value       = try(aws_identitystore_group.downloader_group[0].group_id, data.aws_identitystore_group.downloader_group[0].group_id, "")
  description = "Downloader group ID"
}
