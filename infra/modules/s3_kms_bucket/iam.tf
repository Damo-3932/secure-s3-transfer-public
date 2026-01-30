data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "AllowAssumeRoleFromApprovedPrincipals"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.assume_role_principals
    }

    dynamic "condition" {
      for_each = var.assume_role_external_id != "" ? [1] : []
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [var.assume_role_external_id]
      }
    }
  }
}

// ---------- Uploader ----------
data "aws_iam_policy_document" "uploader_policy" {
  // Allow listing only the incoming/ prefix.
  statement {
    sid     = "ListIncomingPrefix"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    resources = [
      local.bucket_arn
    ]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        trim(var.incoming_prefix, "/"),
        "${var.incoming_prefix}",
        "${var.incoming_prefix}*",
        trim(var.artefacts_prefix, "/"),
        "${var.artefacts_prefix}",
        "${var.artefacts_prefix}*"
      ]
    }
  }

  // Required to check Transfer Acceleration status.
  statement {
    sid     = "GetBucketAccelerateConfig"
    effect  = "Allow"
    actions = ["s3:GetAccelerateConfiguration"]
    resources = [
      local.bucket_arn
    ]
  }

  // Multipart housekeeping at the bucket level.
  statement {
    sid     = "ListMultipartUploads"
    effect  = "Allow"
    actions = ["s3:ListBucketMultipartUploads"]
    resources = [
      local.bucket_arn
    ]
  }

  // Allow uploading only into incoming/.
  statement {
    sid    = "PutIncomingObjects"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      local.incoming_objects_arn
    ]
  }

  // Allow uploading artefacts (hashes/manifests) into incoming/artefacts/.
  statement {
    sid    = "PutArtefactObjects"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      local.artefacts_objects_arn
    ]
  }

  // Required for SSE-KMS writes performed by S3 on behalf of uploader.
  // Uses KMS alias to remain deployment-agnostic (no hard-coded key IDs).
  statement {
    sid    = "KmsEncryptForS3"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
      "kms:Decrypt",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ResourceAlias"
      values   = ["alias/${var.kms_alias}"]
    }

    // Restrict usage to S3 in this region (hardening step).
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  // Required for client-side encryption (CSE) using direct KMS calls.
  // Uses KMS alias to remain deployment-agnostic (no hard-coded key IDs).
  statement {
    sid    = "KmsEncryptForClient"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
      "kms:Decrypt",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ResourceAlias"
      values   = ["alias/${var.kms_alias}"]
    }
  }
}

resource "aws_iam_role" "uploader" {
  name               = "${var.name_prefix}-uploader"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_policy" "uploader" {
  name   = "${var.name_prefix}-uploader-policy"
  policy = data.aws_iam_policy_document.uploader_policy.json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "uploader" {
  role       = aws_iam_role.uploader.name
  policy_arn = aws_iam_policy.uploader.arn
}

// ---------- Downloader ----------
data "aws_iam_policy_document" "downloader_policy" {
  // Allow listing only the incoming/ prefix.
  statement {
    sid     = "ListIncomingPrefix"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    resources = [
      local.bucket_arn
    ]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        trim(var.incoming_prefix, "/"),
        "${var.incoming_prefix}",
        "${var.incoming_prefix}*",
        trim(var.artefacts_prefix, "/"),
        "${var.artefacts_prefix}",
        "${var.artefacts_prefix}*"
      ]
    }
  }

  // Required to check Transfer Acceleration status.
  statement {
    sid     = "GetBucketAccelerateConfig"
    effect  = "Allow"
    actions = ["s3:GetAccelerateConfiguration"]
    resources = [
      local.bucket_arn
    ]
  }

  // Allow downloading only from incoming/.
  statement {
    sid    = "GetIncomingObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:GetObjectVersion",
      "s3:GetObjectVersionTagging"
    ]
    resources = [
      local.incoming_objects_arn
    ]
  }

  // Allow reading artefacts (hashes/manifests).
  statement {
    sid    = "GetArtefactObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:GetObjectVersion",
      "s3:GetObjectVersionTagging"
    ]
    resources = [
      local.artefacts_objects_arn
    ]
  }

  // Allow writing to downloaded/ for archive moves (including multipart).
  statement {
    sid    = "PutDownloadedObjects"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      local.downloaded_objects_arn
    ]
  }

  // Allow writing artefacts to downloaded/artefacts/.
  statement {
    sid    = "PutDownloadedArtefactObjects"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      local.downloaded_artefacts_objects_arn
    ]
  }

  // Multipart housekeeping at the bucket level (archive uploads).
  statement {
    sid     = "ListMultipartUploads"
    effect  = "Allow"
    actions = ["s3:ListBucketMultipartUploads"]
    resources = [
      local.bucket_arn
    ]
  }

  // Allow deleting only from incoming/ after successful archive.
  statement {
    sid    = "DeleteIncomingObjects"
    effect = "Allow"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion"
    ]
    resources = [
      local.incoming_objects_arn
    ]
  }

  // Allow deleting artefacts from incoming/artefacts/ after archive.
  statement {
    sid    = "DeleteArtefactObjects"
    effect = "Allow"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion"
    ]
    resources = [
      local.artefacts_objects_arn
    ]
  }

  // Required for SSE-KMS reads.
  // Uses KMS alias to remain deployment-agnostic (no hard-coded key IDs).
  statement {
    sid    = "KmsDecryptForS3"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ResourceAlias"
      values   = ["alias/${var.kms_alias}"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  // Required for SSE-KMS writes performed by S3 when archiving to downloaded/.
  // Uses KMS alias to remain deployment-agnostic (no hard-coded key IDs).
  statement {
    sid    = "KmsEncryptForS3Archive"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ResourceAlias"
      values   = ["alias/${var.kms_alias}"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  // Required for client-side decryption (CSE) using direct KMS calls.
  // Uses KMS alias to remain deployment-agnostic (no hard-coded key IDs).
  statement {
    sid    = "KmsDecryptForClient"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ResourceAlias"
      values   = ["alias/${var.kms_alias}"]
    }
  }
}

resource "aws_iam_role" "downloader" {
  name               = "${var.name_prefix}-downloader"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_policy" "downloader" {
  name   = "${var.name_prefix}-downloader-policy"
  policy = data.aws_iam_policy_document.downloader_policy.json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "downloader" {
  role       = aws_iam_role.downloader.name
  policy_arn = aws_iam_policy.downloader.arn
}
