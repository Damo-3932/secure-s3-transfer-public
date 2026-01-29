# Terraform State Backend (Bootstrap)

This folder bootstraps the remote Terraform state backend:
- S3 bucket (versioned, SSE-KMS encrypted, TLS-only, public access blocked)
- DynamoDB lock table (prevents concurrent state writes)

## When to run this
Run this **once** per AWS account before enabling remote state in environment deployments.

## Commands (when AWS auth is available)
From this folder:

```bash
terraform init
terraform plan
terraform apply
```

## Required variables
- aws_region
- state_bucket_name
- state_log_bucket_name

## Optional variables
- aws_profile
- lock_table_name
- kms_alias
- dynamodb_kms_alias
