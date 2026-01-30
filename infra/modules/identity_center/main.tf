// Identity Center is optional. When disabled, we avoid all API calls entirely.
data "aws_ssoadmin_instances" "this" {
  // Auto-discover instance/store IDs only when needed.
  count = var.enabled && (var.identity_center_instance_arn == "" || var.identity_store_id == "") ? 1 : 0
}

data "aws_caller_identity" "current" {
  // Default to the current account when no explicit target account is set.
  count = var.enabled && var.account_id == "" ? 1 : 0
}

locals {
  // Resolve Identity Center and account context once to keep resources concise.
  instance_arn      = var.enabled ? (var.identity_center_instance_arn != "" ? var.identity_center_instance_arn : data.aws_ssoadmin_instances.this[0].arns[0]) : ""
  identity_store_id = var.enabled ? (var.identity_store_id != "" ? var.identity_store_id : data.aws_ssoadmin_instances.this[0].identity_store_ids[0]) : ""
  account_id        = var.enabled ? (var.account_id != "" ? var.account_id : data.aws_caller_identity.current[0].account_id) : ""

  // Object ARNs used in permission-set inline policies.
  incoming_objects_arn             = "${var.bucket_arn}/${trim(var.incoming_prefix, "/")}/*"
  artefacts_objects_arn            = "${var.bucket_arn}/${trim(var.artefacts_prefix, "/")}/*"
  downloaded_objects_arn           = "${var.bucket_arn}/${trim(var.downloaded_prefix, "/")}/*"
  downloaded_artefacts_objects_arn = "${var.bucket_arn}/${trim(var.downloaded_prefix, "/")}/artefacts/*"
}

resource "aws_ssoadmin_permission_set" "uploader" {
  count            = var.enabled ? 1 : 0
  name             = var.uploader_permission_set_name
  instance_arn     = local.instance_arn
  session_duration = var.session_duration
  tags             = var.tags
}

resource "aws_ssoadmin_permission_set" "downloader" {
  count            = var.enabled ? 1 : 0
  name             = var.downloader_permission_set_name
  instance_arn     = local.instance_arn
  session_duration = var.session_duration
  tags             = var.tags
}

// Inline policies mirror the least-privilege IAM roles used by uploaders/downloaders.
resource "aws_ssoadmin_permission_set_inline_policy" "uploader" {
  count              = var.enabled ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.uploader[0].arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListIncomingPrefix"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = var.bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              trim(var.incoming_prefix, "/"),
              var.incoming_prefix,
              "${var.incoming_prefix}*",
              trim(var.artefacts_prefix, "/"),
              var.artefacts_prefix,
              "${var.artefacts_prefix}*"
            ]
          }
        }
      },
      {
        Sid      = "GetBucketAccelerateConfig"
        Effect   = "Allow"
        Action   = "s3:GetAccelerateConfiguration"
        Resource = var.bucket_arn
      },
      {
        Sid      = "ListMultipartUploads"
        Effect   = "Allow"
        Action   = "s3:ListBucketMultipartUploads"
        Resource = var.bucket_arn
      },
      {
        Sid      = "PutIncomingObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = local.incoming_objects_arn
      },
      {
        Sid      = "PutArtefactObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = local.artefacts_objects_arn
      },
      {
        Sid    = "KmsEncryptForS3"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
          "kms:Decrypt",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo"
        ]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "KmsEncryptForClient"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
          "kms:Decrypt",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "downloader" {
  count              = var.enabled ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.downloader[0].arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListIncomingPrefix"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = var.bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              trim(var.incoming_prefix, "/"),
              var.incoming_prefix,
              "${var.incoming_prefix}*",
              trim(var.artefacts_prefix, "/"),
              var.artefacts_prefix,
              "${var.artefacts_prefix}*"
            ]
          }
        }
      },
      {
        Sid      = "GetBucketAccelerateConfig"
        Effect   = "Allow"
        Action   = "s3:GetAccelerateConfiguration"
        Resource = var.bucket_arn
      },
      {
        Sid      = "ListMultipartUploads"
        Effect   = "Allow"
        Action   = "s3:ListBucketMultipartUploads"
        Resource = var.bucket_arn
      },
      {
        Sid      = "GetIncomingObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionTagging"]
        Resource = local.incoming_objects_arn
      },
      {
        Sid      = "GetArtefactObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionTagging"]
        Resource = local.artefacts_objects_arn
      },
      {
        Sid      = "PutDownloadedObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = local.downloaded_objects_arn
      },
      {
        Sid      = "PutDownloadedArtefactObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = local.downloaded_artefacts_objects_arn
      },
      {
        Sid      = "DeleteIncomingObjects"
        Effect   = "Allow"
        Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = local.incoming_objects_arn
      },
      {
        Sid      = "DeleteArtefactObjects"
        Effect   = "Allow"
        Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = local.artefacts_objects_arn
      },
      {
        Sid      = "KmsDecryptForS3"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid      = "KmsEncryptForS3Archive"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid      = "KmsDecryptForClient"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_identitystore_group" "uploader_group" {
  count             = var.enabled && var.create_groups ? 1 : 0
  identity_store_id = local.identity_store_id
  display_name      = var.uploader_group_name
}

resource "aws_identitystore_group" "downloader_group" {
  count             = var.enabled && var.create_groups ? 1 : 0
  identity_store_id = local.identity_store_id
  display_name      = var.downloader_group_name
}

data "aws_identitystore_group" "uploader_group" {
  count             = var.enabled && !var.create_groups ? 1 : 0
  identity_store_id = local.identity_store_id
  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = var.uploader_group_name
    }
  }
}

data "aws_identitystore_group" "downloader_group" {
  count             = var.enabled && !var.create_groups ? 1 : 0
  identity_store_id = local.identity_store_id
  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = var.downloader_group_name
    }
  }
}

// Account assignments connect permission sets to the relevant groups.
resource "aws_ssoadmin_account_assignment" "uploader" {
  count              = var.enabled && var.create_assignments && var.create_groups ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.uploader[0].arn
  principal_id       = aws_identitystore_group.uploader_group[0].group_id
  principal_type     = "GROUP"
  target_id          = local.account_id
  target_type        = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "downloader" {
  count              = var.enabled && var.create_assignments && var.create_groups ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.downloader[0].arn
  principal_id       = aws_identitystore_group.downloader_group[0].group_id
  principal_type     = "GROUP"
  target_id          = local.account_id
  target_type        = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "uploader_existing" {
  count              = var.enabled && var.create_assignments && !var.create_groups ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.uploader[0].arn
  principal_id       = data.aws_identitystore_group.uploader_group[0].group_id
  principal_type     = "GROUP"
  target_id          = local.account_id
  target_type        = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "downloader_existing" {
  count              = var.enabled && var.create_assignments && !var.create_groups ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.downloader[0].arn
  principal_id       = data.aws_identitystore_group.downloader_group[0].group_id
  principal_type     = "GROUP"
  target_id          = local.account_id
  target_type        = "AWS_ACCOUNT"
}
