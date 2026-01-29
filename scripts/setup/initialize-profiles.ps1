<#
Purpose:
  Apply recommended AWS CLI transfer settings to upload/download profiles.

When to use:
  - After creating profiles (SSO or role-based)
  - When troubleshooting transfer performance

Prerequisites:
  - AWS CLI v2 installed
  - Profiles already exist in ~/.aws/config

Inputs:
  - UploadProfile / DownloadProfile
  - Region
  - BucketName (optional; used to check acceleration)

Outputs:
  - Updates AWS CLI profile settings

Usage:
  pwsh -File scripts\setup\initialize-profiles.ps1 -UploadProfile SecureUpload -DownloadProfile SecureDownload -Region ap-southeast-2 -BucketName <S3_BUCKET>

Maintainer notes:
  - These settings favor reliable large transfers; adjust only if you understand the impact.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$UploadProfile,
    [Parameter(Mandatory=$true)][string]$DownloadProfile,
    [Parameter(Mandatory=$true)][string]$Region,
    [string]$BucketName = $null
)

$ErrorActionPreference = "Stop"

function Set-ProfileSetting {
    param([string]$Profile,[string]$Key,[string]$Value)
    aws configure set "profile.$Profile.$Key" $Value | Out-Null
}

function Apply-MaxSpeedSettings {
    param([string]$Profile)
    # Tuned for large files and variable network conditions.
    Set-ProfileSetting -Profile $Profile -Key "s3.multipart_chunksize" -Value "256MB"
    Set-ProfileSetting -Profile $Profile -Key "s3.max_concurrent_requests" -Value "10"
    Set-ProfileSetting -Profile $Profile -Key "max_attempts" -Value "10"
    Set-ProfileSetting -Profile $Profile -Key "retry_mode" -Value "adaptive"
    Set-ProfileSetting -Profile $Profile -Key "s3.use_accelerate_endpoint" -Value "true"
}

function Check-Acceleration {
    param([string]$Profile,[string]$Bucket)
    if (-not $Bucket) { return }
    # Only warn on mismatch; we do not fail setup if acceleration is disabled.
    $json = aws s3api get-bucket-accelerate-configuration --bucket $Bucket --profile $Profile --region $Region --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $json) {
        Write-Host "WARN: Could not read acceleration status for $Bucket using $Profile." -ForegroundColor Yellow
        return
    }
    $cfg = ($json | Out-String | ConvertFrom-Json)
    if ($cfg.Status -ne "Enabled") {
        Write-Host ("WARN: Acceleration is not enabled (Status={0})." -f $cfg.Status) -ForegroundColor Yellow
    } else {
        Write-Host "OK: Transfer Acceleration enabled." -ForegroundColor Green
    }
}

Write-Host "Applying max-speed transfer settings..." -ForegroundColor Cyan
Apply-MaxSpeedSettings -Profile $UploadProfile
Apply-MaxSpeedSettings -Profile $DownloadProfile

Write-Host "Checking bucket acceleration (optional)..." -ForegroundColor Cyan
Check-Acceleration -Profile $UploadProfile -Bucket $BucketName

Write-Host "Done." -ForegroundColor Green
