// Account ID is used to scope CloudTrail delivery paths.
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "audit_kms_policy" {
  // Root retains full control of the CMK.
  statement {
    sid       = "EnableRootAccountPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowDeployerKeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }
  }

  // Allow CloudTrail to encrypt log files.
  statement {
    sid    = "AllowCloudTrailKeyUsage"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  // Allow CloudWatch Logs to use the CMK for log group encryption.
  statement {
    sid    = "AllowCloudWatchLogsKeyUsage"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/cloudtrail/${var.name_prefix}"]
    }
  }

  // Allow S3 server access logging to use the CMK.
  statement {
    sid    = "AllowS3LogDeliveryKeyUsage"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

// CMK for CloudTrail log encryption and audit log bucket SSE-KMS.
resource "aws_kms_key" "audit" {
  description         = "CMK for CloudTrail audit logging"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.audit_kms_policy.json
  tags                = var.tags
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name_prefix}-audit"
  target_key_id = aws_kms_key.audit.key_id
}

// Dedicated, immutable bucket for CloudTrail logs.
resource "aws_s3_bucket" "audit" {
  bucket              = var.audit_log_bucket_name
  object_lock_enabled = true
  force_destroy       = false
  tags                = var.tags
}

// Block all public access to audit logs.
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

// Versioning is required for Object Lock retention.
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

// Enforce SSE-KMS for audit log storage.
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

// Dedicated bucket for access logs from the audit bucket.
// The suffix "-logs" keeps the log bucket distinct across environments.
resource "aws_s3_bucket" "audit_logs" {
  bucket        = "${var.audit_log_bucket_name}-logs"
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

// Object Lock retention enforces immutable log storage.
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }
}

data "aws_iam_policy_document" "audit_bucket_policy" {
  // Allow CloudTrail to validate bucket ACL.
  statement {
    sid     = "AllowCloudTrailGetBucketAcl"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.audit.arn
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  // Allow CloudTrail to deliver logs into the correct account prefix.
  statement {
    sid     = "AllowCloudTrailPutObject"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.audit.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

// Apply the CloudTrail delivery policy.
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket_policy.json
}

data "aws_iam_policy_document" "audit_logs_policy" {
  statement {
    sid     = "AllowS3LogDeliveryWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.audit_logs.arn}/audit/*"
    ]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.audit.arn]
    }
  }

  statement {
    sid     = "AllowS3LogDeliveryAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.audit_logs.arn
    ]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.audit.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = data.aws_iam_policy_document.audit_logs_policy.json
}

resource "aws_s3_bucket_logging" "audit" {
  bucket        = aws_s3_bucket.audit.id
  target_bucket = aws_s3_bucket.audit_logs.id
  target_prefix = "audit/"
}

// CloudWatch log group for CloudTrail events.
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.audit.arn
  tags              = var.tags
}

data "aws_iam_policy_document" "trail_assume_role" {
  // Allow CloudTrail service to write to CloudWatch Logs.
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_cloudwatch" {
  name               = "${var.name_prefix}-cloudtrail-cw"
  assume_role_policy = data.aws_iam_policy_document.trail_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "trail_cloudwatch_policy" {
  // Minimal CloudWatch Logs write permissions for CloudTrail.
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "${aws_cloudwatch_log_group.trail.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "trail_cloudwatch" {
  name   = "${var.name_prefix}-cloudtrail-cw"
  role   = aws_iam_role.trail_cloudwatch.id
  policy = data.aws_iam_policy_document.trail_cloudwatch_policy.json
}

// CloudTrail for S3 data events and management events.
resource "aws_cloudtrail" "trail" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.audit.bucket
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_cloudwatch.arn

  # Management events (IAM, S3 control, etc.)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${var.monitored_bucket_arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.audit]
  tags       = var.tags
}
