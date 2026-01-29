# Secure Download Script

This script downloads files from the S3 `incoming/` prefix, prepares (decrypts) them locally, verifies integrity, then archives objects to `downloaded/`.

## Prerequisites
- PowerShell 7+
- AWS CLI v2
- An AWS SSO profile configured locally
- Permissions to list/get objects and to call `kms:Decrypt` (if CSE is enabled)

## Configuration
1) Copy the example config:
```
copy ..\\config\\config.download.example.json ..\\config\\config.download.json
```
2) Edit `scripts/config/config.download.json` with your values:
- `aws_profile`, `aws_region`, `bucket_name`
- `incoming_prefix` and `downloaded_prefix`
- `artefacts_prefix` (defaults to `incoming/artefacts/`)
- `kms_key_id` (required; bucket policy enforces SSE-KMS on archive moves)

Note: `scripts/config/config.download.json` is gitignored to avoid committing sensitive values.

Optional: generate config from Terraform outputs:
```
pwsh -File ..\\config\\generate-config.ps1 -UploadProfile YOUR_UPLOAD_PROFILE -DownloadProfile YOUR_DOWNLOAD_PROFILE
```

## Run
From `scripts/download`:
```
pwsh -File .\\Download_From_S3.ps1
```
Optional:
```
pwsh -File .\\Download_From_S3.ps1 -ConfigPath ..\\config\\config.download.json
```

## Automation flags
These do not affect normal interactive usage unless passed.
```
pwsh -File .\\Download_From_S3.ps1 -AutoStart -DestinationPath C:\\Temp\\secure-s3-transfer-download
```

## Notes
- Integrity checks use the uploaded `.sha256` file if present.
- Files are only archived after size and hash checks pass.
