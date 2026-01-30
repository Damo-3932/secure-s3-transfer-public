# Secure Upload Script

This script securely uploads files to the S3 `incoming/` prefix with optional client-side encryption (CSE), checksum validation, and logging.

## Prerequisites
- PowerShell 7+
- AWS CLI v2
- An AWS SSO profile configured locally
- Permissions to put objects to the target bucket and to use the KMS key (if CSE is enabled)

## Configuration
1) Copy the example config:
```
copy ..\\config\\config.upload.example.json ..\\config\\config.upload.json
```
2) Edit `scripts/config/config.upload.json` with your values:
- `aws_profile`, `aws_region`, `bucket_name`
- `incoming_prefix` (defaults to `incoming/`)
- `artefacts_prefix` (defaults to `incoming/artefacts/`)
- `kms_key_id` (required; bucket policy enforces SSE-KMS on uploads)
- `ciphertext_extension` (optional, defaults to `.enc` when storing ciphertext with an extension)
- `use_transfer_acceleration` (required; must be true to use the accelerated S3 endpoint)

Note: `scripts/config/config.upload.json` is gitignored to avoid committing sensitive values.

Optional: generate config from Terraform outputs:
```
pwsh -File ..\\config\\generate-config.ps1 -UploadProfile YOUR_UPLOAD_PROFILE -DownloadProfile YOUR_DOWNLOAD_PROFILE
```

## Run
From `scripts/upload`:
```
pwsh -File .\\Upload_To_S3.ps1
```
Optional:
```
pwsh -File .\\Upload_To_S3.ps1 -ConfigPath ..\\config\\config.upload.json
```

## Automation flags
These do not affect normal interactive usage unless passed.
```
pwsh -File .\\Upload_To_S3.ps1 -AutoStart -InputFilePath C:\\path\\file.txt
pwsh -File .\\Upload_To_S3.ps1 -AutoStart -SkipDefenderScan
```

## Notes
- Transfer acceleration requires the profile to set `s3.use_accelerate_endpoint=true`.
- The script uploads a `.sha256` integrity file alongside the payload.
