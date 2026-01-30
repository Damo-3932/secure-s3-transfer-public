terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    archive = {
      source = "hashicorp/archive"
    }
  }
}

locals {
  enabled = var.enabled
}

data "archive_file" "lambda_zip" {
  count       = local.enabled ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda/package.zip"
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  count              = local.enabled ? 1 : 0
  name               = "secure-s3-transfer-incoming-env-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowSnsPublish"
    effect = "Allow"
    actions = [
      "sns:Publish"
    ]
    resources = [
      aws_sns_topic.incoming_env[0].arn
    ]
  }
}

resource "aws_iam_role_policy" "lambda" {
  count  = local.enabled ? 1 : 0
  name   = "secure-s3-transfer-incoming-env-lambda"
  role   = aws_iam_role.lambda[0].id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  count             = local.enabled ? 1 : 0
  name              = "/aws/lambda/secure-s3-transfer-incoming-env"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_sns_topic" "incoming_env" {
  count = local.enabled ? 1 : 0
  name  = "secure-s3-transfer-incoming-env"
  tags  = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = local.enabled ? 1 : 0
  topic_arn = aws_sns_topic.incoming_env[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_lambda_function" "incoming_env" {
  count         = local.enabled ? 1 : 0
  function_name = "secure-s3-transfer-incoming-env"
  role          = aws_iam_role.lambda[0].arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.11"
  filename      = data.archive_file.lambda_zip[0].output_path
  source_code_hash = data.archive_file.lambda_zip[0].output_base64sha256
  timeout       = 10
  memory_size   = 128
  tags          = var.tags

  environment {
    variables = {
      NOTIFICATION_SUFFIX  = var.notification_suffix
      NOTIFICATION_MESSAGE = var.notification_message
      SNS_TOPIC_ARN         = aws_sns_topic.incoming_env[0].arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda
  ]
}

resource "aws_lambda_permission" "allow_s3_invoke" {
  count         = local.enabled ? 1 : 0
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.incoming_env[0].arn
  principal     = "s3.amazonaws.com"
  source_arn    = var.bucket_arn
}

resource "aws_s3_bucket_notification" "incoming_env" {
  count  = local.enabled ? 1 : 0
  bucket = var.bucket_name

  lambda_function {
    lambda_function_arn = aws_lambda_function.incoming_env[0].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = var.notification_prefix
    filter_suffix       = var.notification_suffix
  }

  depends_on = [
    aws_lambda_permission.allow_s3_invoke
  ]
}
