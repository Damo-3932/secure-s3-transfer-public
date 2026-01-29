terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

data "aws_caller_identity" "current" {
  count = var.enabled && var.create_sns_cmk && var.sns_kms_key_id == "" ? 1 : 0
}

locals {
  common_tags = merge(var.tags, {
    Module = "alerting"
  })
  sns_kms_alias = var.sns_kms_alias != "" ? var.sns_kms_alias : "alias/${var.name_prefix}-sns"
}

data "aws_iam_policy_document" "sns_kms_policy" {
  count = var.enabled && var.create_sns_cmk && var.sns_kms_key_id == "" ? 1 : 0

  statement {
    sid    = "EnableRootPermissions"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current[0].account_id}:root"]
    }
  }

  statement {
    sid    = "AllowDeployerKeyAdministration"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current[0].arn]
    }
  }

  statement {
    sid    = "AllowSnsUseOfKey"
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
      identifiers = ["sns.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "sns" {
  count                   = var.enabled && var.create_sns_cmk && var.sns_kms_key_id == "" ? 1 : 0
  description             = "CMK for SNS topic encryption (secure-s3-transfer alerts)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.sns_kms_policy[0].json
  tags                    = local.common_tags
}

resource "aws_kms_alias" "sns" {
  count         = var.enabled && var.create_sns_cmk && var.sns_kms_key_id == "" ? 1 : 0
  name          = local.sns_kms_alias
  target_key_id = aws_kms_key.sns[0].key_id
}

resource "aws_sns_topic" "alerts" {
  count             = var.enabled ? 1 : 0
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.sns_kms_key_id != "" ? var.sns_kms_key_id : aws_kms_key.sns[0].arn
  tags              = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.enabled ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "sns_topic_policy" {
  count = var.enabled ? 1 : 0
  statement {
    sid     = "AllowEventBridgePublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    resources = [
      aws_sns_topic.alerts[0].arn
    ]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  count  = var.enabled ? 1 : 0
  arn    = aws_sns_topic.alerts[0].arn
  policy = data.aws_iam_policy_document.sns_topic_policy[0].json
}

resource "aws_cloudwatch_event_rule" "s3_bucket_policy" {
  count       = var.enabled && var.include_s3_alerts ? 1 : 0
  name        = "${var.name_prefix}-s3-bucket-policy-changes"
  description = "Alerts on S3 bucket policy changes"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketPolicy", "DeleteBucketPolicy"]
      requestParameters = {
        bucketName = [var.bucket_name]
      }
    }
  })
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "s3_public_access" {
  count       = var.enabled && var.include_s3_alerts ? 1 : 0
  name        = "${var.name_prefix}-s3-public-access-changes"
  description = "Alerts on S3 public access block changes"
  event_pattern = jsonencode({
    source      = ["aws.s3", "aws.s3control"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com", "s3control.amazonaws.com"]
      eventName   = ["PutPublicAccessBlock", "DeletePublicAccessBlock"]
    }
  })
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "kms_policy" {
  count       = var.enabled && var.include_kms_alerts ? 1 : 0
  name        = "${var.name_prefix}-kms-policy-changes"
  description = "Alerts on KMS key policy changes"
  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["PutKeyPolicy"]
      requestParameters = {
        keyId = [var.kms_key_arn]
      }
    }
  })
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "kms_deletion" {
  count       = var.enabled && var.include_kms_alerts ? 1 : 0
  name        = "${var.name_prefix}-kms-deletion"
  description = "Alerts on KMS key deletion scheduling/cancel"
  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["ScheduleKeyDeletion", "CancelKeyDeletion"]
      requestParameters = {
        keyId = [var.kms_key_arn]
      }
    }
  })
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "iam_role_policy" {
  count       = var.enabled && var.include_iam_alerts ? 1 : 0
  name        = "${var.name_prefix}-iam-role-policy-changes"
  description = "Alerts on uploader/downloader role policy changes"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "PutRolePolicy",
        "DeleteRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "UpdateAssumeRolePolicy"
      ]
      requestParameters = {
        roleName = [var.uploader_role_name, var.downloader_role_name]
      }
    }
  })
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "s3_bucket_policy" {
  count     = var.enabled && var.include_s3_alerts ? 1 : 0
  rule      = aws_cloudwatch_event_rule.s3_bucket_policy[0].name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.alerts[0].arn

  input_transformer {
    input_paths = {
      time      = "$.time"
      region    = "$.region"
      account   = "$.account"
      eventName = "$.detail.eventName"
      bucket    = "$.detail.requestParameters.bucketName"
      actor     = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      requestId = "$.detail.requestID"
      userAgent = "$.detail.userAgent"
    }
    input_template = <<EOF
"ALERT: S3 bucket policy changed. Summary: event=<eventName>; bucket=<bucket>; time=<time> UTC; account=<account>; region=<region>; actor=<actor>; sourceIp=<sourceIp>. Technical: requestId=<requestId>; userAgent=<userAgent>"
EOF
  }
}

resource "aws_cloudwatch_event_target" "s3_public_access" {
  count     = var.enabled && var.include_s3_alerts ? 1 : 0
  rule      = aws_cloudwatch_event_rule.s3_public_access[0].name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.alerts[0].arn

  input_transformer {
    input_paths = {
      time      = "$.time"
      region    = "$.region"
      account   = "$.account"
      eventName = "$.detail.eventName"
      bucket    = "$.detail.requestParameters.bucketName"
      actor     = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      requestId = "$.detail.requestID"
      userAgent = "$.detail.userAgent"
    }
    input_template = <<EOF
"ALERT: S3 public access settings changed. Summary: event=<eventName>; bucket=<bucket>; time=<time> UTC; account=<account>; region=<region>; actor=<actor>; sourceIp=<sourceIp>. Technical: requestId=<requestId>; userAgent=<userAgent>"
EOF
  }
}

resource "aws_cloudwatch_event_target" "kms_policy" {
  count     = var.enabled && var.include_kms_alerts ? 1 : 0
  rule      = aws_cloudwatch_event_rule.kms_policy[0].name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.alerts[0].arn

  input_transformer {
    input_paths = {
      time      = "$.time"
      region    = "$.region"
      account   = "$.account"
      eventName = "$.detail.eventName"
      keyId     = "$.detail.requestParameters.keyId"
      actor     = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      requestId = "$.detail.requestID"
      userAgent = "$.detail.userAgent"
    }
    input_template = <<EOF
"ALERT: KMS key policy changed. Summary: event=<eventName>; key=<keyId>; time=<time> UTC; account=<account>; region=<region>; actor=<actor>; sourceIp=<sourceIp>. Technical: requestId=<requestId>; userAgent=<userAgent>"
EOF
  }
}

resource "aws_cloudwatch_event_target" "kms_deletion" {
  count     = var.enabled && var.include_kms_alerts ? 1 : 0
  rule      = aws_cloudwatch_event_rule.kms_deletion[0].name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.alerts[0].arn

  input_transformer {
    input_paths = {
      time      = "$.time"
      region    = "$.region"
      account   = "$.account"
      eventName = "$.detail.eventName"
      keyId     = "$.detail.requestParameters.keyId"
      actor     = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      requestId = "$.detail.requestID"
      userAgent = "$.detail.userAgent"
    }
    input_template = <<EOF
"ALERT: KMS key deletion action. Summary: event=<eventName>; key=<keyId>; time=<time> UTC; account=<account>; region=<region>; actor=<actor>; sourceIp=<sourceIp>. Technical: requestId=<requestId>; userAgent=<userAgent>"
EOF
  }
}

resource "aws_cloudwatch_event_target" "iam_role_policy" {
  count     = var.enabled && var.include_iam_alerts ? 1 : 0
  rule      = aws_cloudwatch_event_rule.iam_role_policy[0].name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.alerts[0].arn

  input_transformer {
    input_paths = {
      time      = "$.time"
      region    = "$.region"
      account   = "$.account"
      eventName = "$.detail.eventName"
      roleName  = "$.detail.requestParameters.roleName"
      actor     = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      requestId = "$.detail.requestID"
      userAgent = "$.detail.userAgent"
    }
    input_template = <<EOF
"ALERT: IAM role policy/trust changed. Summary: event=<eventName>; role=<roleName>; time=<time> UTC; account=<account>; region=<region>; actor=<actor>; sourceIp=<sourceIp>. Technical: requestId=<requestId>; userAgent=<userAgent>"
EOF
  }
}
