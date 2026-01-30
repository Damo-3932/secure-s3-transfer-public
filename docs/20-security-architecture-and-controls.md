# 20 – Security Architecture and Controls

This document describes the security model, controls, and evidence locations. Claims are mapped to Terraform or script paths for verification.

## Security model
- **Trust boundaries:** Client endpoints (untrusted network), AWS control plane, AWS data plane.
- **Primary goals:** confidentiality, integrity, least privilege, auditability.
- **Roles:** uploader (write-only), downloader (read + archive), admin/deployer (Terraform).

## Encryption controls
**In transit**
- TLS is enforced by S3 bucket policy (`aws:SecureTransport = false` deny).

**At rest (cloud)**
- S3 uses SSE-KMS with a customer-managed key (CMK).
- Bucket policy enforces `s3:x-amz-server-side-encryption = aws:kms` and pins the CMK.

**Client-side encryption (CSE)**
- AES-256-GCM chunked encryption using a KMS GenerateDataKey (wrapped key stored in manifest).
- Plaintext key exists only in memory on the client; encrypted key stored in artefacts.

## Key lifecycle & ownership
- **Key creation:** CMKs are created by Terraform for the transfer bucket, audit logging, and alerting.
- **Admin control:** Key policies grant root + deployer role administration; least-privilege roles are scoped to usage actions only.
- **Usage scope:** IAM policies constrain KMS usage by alias and service (`kms:ResourceAlias`, `kms:ViaService`) to prevent cross-service misuse.
- **Rotation:** CMKs have rotation enabled; operational processes should document rotation audits.

## Access control (IAM/SSO)
- Identity Center (SSO) permission sets map to uploader/downloader access.
- Roles are assumed via SSO or explicit IAM principals (configurable in Terraform).
- Optional ExternalId support for cross-account assumption.
- Default permission set names are `SecureS3Transfer-Uploader` and `SecureS3Transfer-Downloader` (configurable).
- KMS usage in uploader/downloader policies is constrained by alias and service conditions to limit misuse outside S3 (`kms:ResourceAlias`, `kms:ViaService`).

## Guardrails (S3 bucket policy)
- **TLS-only**: deny non-TLS requests.
- **SSE-KMS required**: deny uploads without `aws:kms`.
- **CMK pinned**: deny uploads using an unexpected key.
- **Optional delete guardrail**: deny deletes unless principal ARN matches allowlist patterns.

## Audit logging and evidence
- **CloudTrail**: multi-region trail with global service events and log validation.
- **Audit bucket**: Object Lock + versioning + SSE-KMS.
- **CloudWatch Logs**: encrypted log group for CloudTrail.
- **Access logs**: S3 access logging enabled for transfer + audit buckets.

## Alerting and change detection
EventBridge rules trigger alerts on:
- S3 bucket policy changes
- S3 public access block changes
- KMS policy changes and deletion scheduling
- IAM role policy/trust changes (IAM rules in us-east-1)

SNS topics are encrypted with CMKs and deliver email notifications.

## Controls table
| Control | Objective | Implementation | Evidence | Residual risk |
|---|---|---|---|---|
| TLS-only S3 access | Prevent MITM and plaintext | Bucket policy deny `aws:SecureTransport=false` | `infra/modules/s3_kms_bucket/main.tf` | Client must use HTTPS-capable tools |
| SSE-KMS required | Enforce encryption at rest | Bucket policy deny if SSE missing | `infra/modules/s3_kms_bucket/main.tf` | Misconfigured clients blocked |
| CMK pinning | Prevent wrong-key encryption | Bucket policy deny on key mismatch | `infra/modules/s3_kms_bucket/main.tf` | Requires correct KMS key ID |
| Block Public Access | Prevent public exposure | Public access block + ownership controls | `infra/modules/s3_kms_bucket/main.tf` | Admins with access could override |
| Least-privilege roles | Limit access to prefixes | IAM policies for uploader/downloader | `infra/modules/s3_kms_bucket/iam.tf` | Role assignment must be correct |
| Client-side encryption | Protect plaintext | AES-256-GCM + KMS GenerateDataKey | `scripts/upload/Upload_To_S3.ps1` | Client compromise still possible |
| Integrity validation | Detect tampering | SHA-256 + manifest | `scripts/upload/Upload_To_S3.ps1`, `scripts/download/Download_From_S3.ps1` | Hash verifies only what is uploaded |
| Immutable audit logs | Non-repudiation | CloudTrail + Object Lock | `infra/modules/audit_logging/main.tf` | Audit bucket retention policy must be managed |
| Alerting on changes | Detect security drift | EventBridge → SNS | `infra/modules/alerting/main.tf` | Email alerts require monitoring |

## Explicit deny behavior (delete guardrail)
The bucket policy can deny deletes unless the principal ARN matches the allowlist patterns (`delete_allowed_principal_arn_patterns`). The downloader role is explicitly permitted to delete in the `downloaded/` archive prefix, supporting the archive workflow while preserving the stricter deny on `incoming/`.

## Residual risks and compensating controls
- **Endpoint compromise:** plaintext exists on the client before encryption. Mitigate with endpoint protection and access controls.
- **User error:** wrong profile or missing permissions can block transfers; mitigated by setup tests and validation scripts.
- **Operational drift:** policy changes can be missed if alerts are ignored; mitigated by scheduled validation and audit log review.

## Traceability (controls → files)
| Control area | Primary files |
|---|---|
| S3 guardrails & encryption | `infra/modules/s3_kms_bucket/main.tf` |
| IAM role permissions | `infra/modules/s3_kms_bucket/iam.tf` |
| Identity Center automation | `infra/modules/identity_center/main.tf` |
| Audit logging | `infra/modules/audit_logging/main.tf` |
| Alerting | `infra/modules/alerting/main.tf` |
| Client-side encryption | `scripts/upload/Upload_To_S3.ps1` |
| Download verification | `scripts/download/Download_From_S3.ps1` |
| Validation checks | `scripts/run-validate.ps1` |

## TO DO
- If the organization requires automated malware scanning in AWS, this is not yet implemented.

**Next:** [30-operations-and-runbooks.md](30-operations-and-runbooks.md)
