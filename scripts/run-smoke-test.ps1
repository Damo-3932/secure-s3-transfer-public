<#
Purpose:
  End-to-end smoke test for role separation. Verifies uploader can write,
  uploader cannot read, and downloader cannot write to incoming/.

When to use:
  - After Terraform apply
  - After IAM/KMS policy changes

Prerequisites:
  - AWS CLI v2
  - SSO login for BaseProfile
  - Terraform outputs available in EnvDir

Inputs:
  - EnvDir, BaseProfile, UploadProfile, DownloadProfile

Outputs:
  - Console pass/fail signals; optional cleanup of test object

Usage:
  pwsh -File scripts\run-smoke-test.ps1 -EnvDir infra\envs\prod -BaseProfile Developer -Cleanup

Maintainer notes:
  - This test intentionally expects some operations to fail (negative tests).
#>
[CmdletBinding()]
param(
    [string]$EnvDir = (Join-Path $PSScriptRoot "..\infra\envs\test"),
    [string]$BaseProfile = "Developer",
    [string]$UploadProfile = "SecureUpload",
    [string]$DownloadProfile = "SecureDownload",
    [switch]$Cleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Wrapper around AWS CLI to capture output + exit code in a single object.
# This keeps error handling consistent and lets us report the exact CLI output.
function Invoke-Aws {
    param([string[]]$CliArgs)
    $out = & aws @CliArgs 2>&1
    return @{
        ExitCode = $LASTEXITCODE
        Output   = ($out | Out-String).Trim()
    }
}

# Reads Terraform outputs from the given env directory.
# We push/pop location instead of using -chdir to avoid CLI compatibility issues.
function Get-TerraformOutputs {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { throw "EnvDir not found: $Dir" }
    Push-Location -LiteralPath $Dir
    try {
        $json = & terraform output -json
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            throw "terraform output failed in $Dir. Ensure you ran terraform init/apply."
        }
        return ($json | ConvertFrom-Json)
    }
    finally {
        Pop-Location
    }
}

Write-Host "== Secure S3 Transfer Smoke Test ==" -ForegroundColor Cyan

# SSO login is required so the base profile can obtain/refresh credentials.
# The role-chained profiles (SecureUpload/SecureDownload) depend on this session.
Write-Host "Logging in to SSO ($BaseProfile)..." -ForegroundColor Gray
$login = Invoke-Aws -CliArgs @("sso","login","--profile",$BaseProfile)
if ($login.ExitCode -ne 0) { throw "SSO login failed: $($login.Output)" }

# Pull key Terraform outputs so the script doesn't need hard-coded names.
# This keeps the smoke test aligned with the deployed environment.
$tf = Get-TerraformOutputs -Dir $EnvDir
$bucket = $tf.bucket_name.value
$region = $tf.aws_region.value
$incoming = $tf.incoming_prefix.value
$kmsKeyArn = $tf.kms_key_arn.value

# Create a unique local test file for this run to avoid collisions.
$stamp = (Get-Date -Format "yyyyMMdd_HHmmss")
$tmpFile = Join-Path $env:TEMP "secure-s3-transfer-smoke-$stamp.txt"
"smoke-test $stamp" | Set-Content -LiteralPath $tmpFile -Encoding ASCII
$key = "$incoming" + "smoke-test-$stamp.txt"
$s3Uri = "s3://$bucket/$key"

# Upload using the uploader role. This should succeed.
# SSE-KMS headers are included to satisfy the bucket policy.
Write-Host "Upload (SecureUpload) -> $s3Uri" -ForegroundColor Gray
$up = Invoke-Aws -CliArgs @(
    "s3","cp",$tmpFile,$s3Uri,
    "--profile",$UploadProfile,
    "--region",$region,
    "--sse","aws:kms",
    "--sse-kms-key-id",$kmsKeyArn
)
if ($up.ExitCode -ne 0) {
    throw "Upload failed: $($up.Output)"
}

# Uploader should NOT be able to read objects (GetObject denied).
Write-Host "Check: uploader cannot read..." -ForegroundColor Gray
$read = Invoke-Aws -CliArgs @(
    "s3","cp",$s3Uri,(Join-Path $env:TEMP "smoke-read-$stamp.txt"),
    "--profile",$UploadProfile,
    "--region",$region
)
if ($read.ExitCode -eq 0) {
    Write-Host "FAIL: uploader read succeeded (should be denied)" -ForegroundColor Red
} else {
    Write-Host "PASS: uploader read denied" -ForegroundColor Green
}

# Downloader should NOT be able to write into incoming/.
# This will usually fail at KMS (GenerateDataKey) due to missing permissions.
Write-Host "Check: downloader cannot write to incoming..." -ForegroundColor Gray
$write = Invoke-Aws -CliArgs @(
    "s3","cp",$tmpFile,"s3://$bucket/$incoming",
    "--profile",$DownloadProfile,
    "--region",$region,
    "--sse","aws:kms",
    "--sse-kms-key-id",$kmsKeyArn
)
if ($write.ExitCode -eq 0) {
    Write-Host "FAIL: downloader write succeeded (should be denied)" -ForegroundColor Red
} else {
    Write-Host "PASS: downloader write denied" -ForegroundColor Green
}

# Optional cleanup: attempt to delete the test object using downloader credentials.
# This may fail by design depending on the downloader's S3 permissions.
if ($Cleanup) {
    Write-Host "Cleanup: deleting $s3Uri with downloader..." -ForegroundColor Gray
    $rm = Invoke-Aws -CliArgs @(
        "s3","rm",$s3Uri,
        "--profile",$DownloadProfile,
        "--region",$region
    )
    if ($rm.ExitCode -ne 0) {
        Write-Host "Cleanup failed: $($rm.Output)" -ForegroundColor Yellow
    } else {
        Write-Host "Cleanup complete." -ForegroundColor Green
    }
}

Write-Host "Smoke test complete." -ForegroundColor Cyan
