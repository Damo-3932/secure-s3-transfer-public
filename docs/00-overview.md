# 00 – Overview (Governance Summary)

## Executive summary
Secure S3 Transfer provides a controlled, auditable file-transfer capability for external laptops over the public internet. It enforces encryption, least-privilege access, and continuous audit logging using AWS-native controls managed by Terraform. The design prioritizes confidentiality, integrity, and auditability while keeping operations simple for non-technical users.

## System context (actors & services)
**Actors**
- **Uploader**: can only write encrypted data to `incoming/` and artefacts to `incoming/artefacts/`.
- **Downloader**: can only read `incoming/`, verify integrity, and archive to `downloaded/`.
- **Admin/Deployer**: applies Terraform and manages Identity Center permissions.

**AWS services**
- **S3** (data storage + access logging)
- **KMS** (customer-managed encryption keys)
- **CloudTrail** (audit logging)
- **CloudWatch Logs** (log aggregation)
- **EventBridge + SNS** (security change alerting)
- **IAM / Identity Center** (least-privilege access)

## Capabilities (operational value)
- Secure transfer of large files without exposing plaintext to the cloud.
- Upload and download roles are separated to minimize data exposure risk.
- Immutable audit logs and automated security change alerts.
- One-step client onboarding (GUI + prerequisites + shortcuts).
- USB-friendly installer option for non-technical deployment.

## Non-goals & boundaries
- Not a malware scanning pipeline in AWS (local Windows Defender scan only).
- No automated incident response; alerts are email-based.
- Not a replacement for org-wide governance (SCPs, Security Hub, etc.).

## Dependencies & prerequisites
- AWS Identity Center (SSO) configured in the account.
- AWS CLI v2 and PowerShell 7 on client machines (installer can auto-install).
- Terraform for deployment and state management.

## High-level risk posture
- **Confidentiality**: client-side encryption + SSE-KMS at rest.
- **Integrity**: SHA-256 checksums + manifest-based decryption.
- **Auditability**: CloudTrail multi-region + immutable audit bucket.
- **Change detection**: EventBridge rules alert on critical changes.

**Next:** [10-architecture-and-data-flows.md](10-architecture-and-data-flows.md)
