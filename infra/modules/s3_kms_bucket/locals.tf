locals {
  bucket_id  = aws_s3_bucket.this.id
  bucket_arn = aws_s3_bucket.this.arn

  # Common object ARNs for prefix-scoped permissions/policies
  incoming_objects_arn             = "${aws_s3_bucket.this.arn}/${var.incoming_prefix}*"
  artefacts_objects_arn            = "${aws_s3_bucket.this.arn}/${var.artefacts_prefix}*"
  downloaded_objects_arn           = "${aws_s3_bucket.this.arn}/${var.download_prefix}*"
  downloaded_artefacts_objects_arn = "${aws_s3_bucket.this.arn}/${var.download_prefix}artefacts/*"

  # Common tags for all resources in this module
  common_tags = merge(var.tags, {
    Module = "s3_kms_bucket"
  })

  # Automatically include the Terraform-created downloader role in delete exception list
  # Also include assumed-role pattern to cover when the role is assumed
  auto_allowed_delete_principals = [
    aws_iam_role.downloader.arn,
    "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.downloader.name}/*"
  ]

  # Merge auto-generated role ARNs with user-provided additional patterns
  all_delete_allowed_principals = concat(
    local.auto_allowed_delete_principals,
    var.delete_allowed_principal_arn_patterns
  )
}
