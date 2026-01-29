# 30 – Operations and Runbooks

This document provides operational procedures for onboarding, daily use, and maintenance. It is written for operators and security reviewers.

## 1) New client onboarding (guided)
**Goal:** Configure a laptop as Uploader or Downloader with SSO and shortcuts.

**Checklist**
1. Provide a prefilled `.env` file (see `.env.example`).
2. Run the guided setup:
   ```powershell
   pwsh -File scripts\setup\setup-client.ps1 -Gui -RunTest
   ```
3. Confirm shortcut exists on desktop.
4. Confirm test passes.
5. Optional: sign in to SSO for the profile when prompted, or later via:
   ```powershell
   aws sso login --profile SecureUpload
   ```

**USB installer (preferred for non-technical users)**
- Build installer + pack:
  ```powershell
  pwsh -File scripts\installer\build-client-pack.ps1
  pwsh -File scripts\installer\build-bootstrapper.ps1
  ```
- Distribute `dist\SecureS3Transfer-Installer.exe`, `dist\ClientPack.zip`, and a prefilled `.env`.
- User runs the EXE and follows prompts.

## 2) Uploader daily use
**Checklist**
- Ensure you are logged into the SSO profile.
- Run upload:
  ```powershell
  pwsh -File scripts\upload\Upload_To_S3.ps1 -InputFilePath C:\path\file.ext -AutoStart
  ```
- Verify success in the console and in the log file under `SecureUploadLogs`.

## 3) Downloader daily use
**Checklist**
- Ensure you are logged into the SSO profile.
- Run download:
  ```powershell
  pwsh -File scripts\download\Download_From_S3.ps1 -DestinationPath C:\Downloads -AutoStart
  ```
- Confirm hash verification and archive moves.

## 4) Validation (security posture)
Local:
```powershell
pwsh -File scripts\run-validate.ps1 -EnvDir infra\envs\prod -SkipClientValidation
```

CI:
- Actions → **Terraform Validate (Prod)**

**Notes**
- Validation checks require backend access and Terraform outputs to resolve expected resource names.
- If backend credentials are not available locally, run validation in GitHub Actions.

## 5) Generate config files (optional)
If you prefer to generate client configs from Terraform outputs:
```powershell
pwsh -File scripts\config\generate-config.ps1 `
  -EnvDir infra\envs\prod `
  -UploadProfile SecureUpload `
  -DownloadProfile SecureDownload `
  -Force
```

Apply recommended AWS CLI transfer settings:
```powershell
pwsh -File scripts\setup\initialize-profiles.ps1 `
  -UploadProfile SecureUpload `
  -DownloadProfile SecureDownload `
  -Region ap-southeast-2 `
  -BucketName YOUR_BUCKET
```

## 6) Maintenance tasks
- Rotate CMKs (if policy requires manual rotation beyond AWS auto-rotation).
- Review Identity Center group membership for uploader/downloader.
- Review delete allowlist patterns in bucket policy if operational requirements change.
- Update AWS CLI and PowerShell 7 on client laptops.
- Re-run `setup-client.ps1 -RunTest` after major changes.

## 7) Monitoring & alerts
- Monitor SNS alerts for policy changes and key deletion events.
- Review CloudTrail logs and S3 access logs during audits.
- Investigate any unexpected access or delete attempts.

## 8) Incident response (basic)
- **Credential compromise:** Disable or remove user from the Identity Center group; force sign-out.
- **Integrity failure:** Quarantine file, re-download, compare hashes, and notify security.
- **Unexpected policy change:** Re-run Terraform plan/apply and review alert evidence.

## 9) Evidence for auditors
- `scripts/run-validate.ps1` output
- CloudTrail log files (audit bucket)
- SNS alert history (email)
- Client logs:
  - `%USERPROFILE%\Documents\SecureUploadLogs`
  - `%USERPROFILE%\Documents\SecureDownloadLogs`

## 10) Evidence & validation appendix (for governance review)
Use the following items as a minimum evidence pack for security review.

**Core evidence checklist**
1. Terraform validation output (`scripts/run-validate.ps1`)
2. S3 bucket policy and public access block (transfer + audit buckets)
3. KMS CMK aliases and key rotation enabled
4. CloudTrail trail settings (multi-region, global events, log validation)
5. CloudWatch log group encryption
6. SNS topic encryption + confirmed subscription
7. EventBridge rules present and targets attached

**Suggested AWS CLI commands**
```
aws s3api get-bucket-policy --bucket <TRANSFER_BUCKET> --profile <ADMIN_PROFILE>
aws s3api get-public-access-block --bucket <TRANSFER_BUCKET> --profile <ADMIN_PROFILE>
aws kms list-aliases --profile <ADMIN_PROFILE> --region <REGION>
aws cloudtrail get-trail --name <TRAIL_NAME> --profile <ADMIN_PROFILE>
aws logs describe-log-groups --log-group-name-prefix /aws/cloudtrail/ --profile <ADMIN_PROFILE>
aws sns get-topic-attributes --topic-arn <SNS_TOPIC_ARN> --profile <ADMIN_PROFILE> --region <REGION>
aws events list-rules --name-prefix <NAME_PREFIX> --profile <ADMIN_PROFILE> --region <REGION>
aws events list-targets-by-rule --rule <RULE_NAME> --profile <ADMIN_PROFILE> --region <REGION>
```

**Next:** [40-troubleshooting-and-faq.md](40-troubleshooting-and-faq.md)
