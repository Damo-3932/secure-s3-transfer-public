# 40 – Troubleshooting and FAQ

## Common errors (cause → fix)

| Error / symptom | Likely cause | Fix |
|---|---|---|
| `GetRoleCredentials: No access` | User not assigned to permission set or wrong role name in SSO profile | Verify Identity Center assignments, confirm role name, re-run SSO login |
| `KMS GenerateDataKey AccessDenied` | IAM role lacks `kms:GenerateDataKey` or key policy missing principal | Update IAM policy or KMS key policy; confirm key ARN |
| `s3:DeleteObject AccessDenied` | Bucket policy delete guardrail allowlist does not include principal | Add principal ARN patterns to `delete_allowed_principal_arn_patterns` |
| Transfer Acceleration errors | Acceleration disabled or profile misconfigured | Disable acceleration in config or enable on bucket |
| Hash mismatch / integrity failure | File changed, partial download, or wrong file | Re-download; compare manifest and `.sha256` |
| Defender scan timeout | Defender service unavailable or slow | Retry or run with `-SkipDefenderScan` |
| `No valid credential sources found` | AWS CLI profile not configured or not logged in | Run `aws sso login --profile <profile>` |
| `Failed to list incoming/ objects` | Missing `s3:ListBucket` permissions | Verify downloader permissions and bucket policy |
| `Invalid KMS key` or `key does not exist or is not allowed` | Wrong KMS key ARN or key policy missing CloudWatch Logs principal | Verify CMK ARN and key policy for CloudWatch Logs |
| `Topic already exists with different tags` | Repeated apply without state import | Import existing SNS topic or reconcile state before apply |
| Installer exits immediately | Missing `.env` next to installer EXE or missing prerequisites | Ensure `.env` is provided; re-run installer |

## Diagnostic commands
Identity:
```
aws sts get-caller-identity --profile SecureUpload
```

KMS test:
```
aws kms generate-data-key --key-id <KMS_KEY_ARN> --key-spec AES_256 --profile SecureUpload --region <REGION>
```

KMS alias check:
```
aws kms list-aliases --profile SecureUpload --region <REGION>
```

Bucket policy check:
```
aws s3api get-bucket-policy --bucket <BUCKET> --profile SecureDownload
```

S3 object access:
```
aws s3api head-object --bucket <BUCKET> --key incoming/<OBJECT> --profile SecureDownload
```

List incoming:
```
aws s3api list-objects-v2 --bucket <BUCKET> --prefix incoming/ --profile SecureDownload
```

Transfer Acceleration:
```
aws s3api get-bucket-accelerate-configuration --bucket <BUCKET> --profile SecureUpload
```

## Log locations
- Upload logs: `%USERPROFILE%\Documents\SecureUploadLogs`
- Download logs: `%USERPROFILE%\Documents\SecureDownloadLogs`

## When to escalate
- Repeated `AccessDenied` on KMS or S3 after correct role assignment
- Unexpected deletes or policy changes (confirm via SNS alerts)
- Integrity verification failures for multiple files

## FAQ
**Q: Do users need the repo?**
A: No. Use the USB installer (EXE + ClientPack.zip + `.env`).

**Q: Can we disable client-side encryption?**
A: It is configurable in client config; disabling reduces security and is not recommended.

**Q: Why are deletes blocked?**  
A: Deletes are controlled to prevent accidental loss; allowlist can be configured for approved principals.

**See also:** [00-overview.md](00-overview.md)
