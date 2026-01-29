<#
Purpose:
  Validate that a client profile has the minimum permissions required to upload
  or download securely. Optionally runs the actual client script.

When to use:
  - After setup-client.ps1
  - After role or KMS policy changes

Prerequisites:
  - AWS CLI v2 installed
  - config.upload.json or config.download.json present

Inputs:
  - Mode (upload/download)
  - Config paths

Outputs:
  - Console output with pass/fail checks

Common failure causes:
  - SSO profile not logged in
  - Missing KMS permissions
  - Bucket policy denies list access

Usage:
  pwsh -File scripts\setup\test-client.ps1 -Mode upload

Maintainer notes:
  - Keep checks aligned with IAM policies and bucket policies.
#>
[CmdletBinding()]
param(
    [ValidateSet("upload","download")][string]$Mode,
    [string]$UploadConfigPath = (Join-Path $PSScriptRoot "..\\config\\config.upload.json"),
    [string]$DownloadConfigPath = (Join-Path $PSScriptRoot "..\\config\\config.download.json"),
    [switch]$RunScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        # Avoid false negatives if AWS CLI is missing.
        throw "Required command not found: $Name"
    }
}

function Load-Config {
    param([string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath)) {
        return $null
    }
    $raw = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
}

function Normalize-Prefix {
    param([string]$Prefix)
    if (-not $Prefix.EndsWith("/")) { return ($Prefix + "/") }
    return $Prefix
}

Require-Command -Name "aws"

function Invoke-Aws {
    param(
        [Parameter(Mandatory=$true)][string]$Args,
        [string]$ErrorLabel
    )
    $cmd = "aws $Args"
    Write-Host $cmd
    & aws @($Args.Split(" ")) | Out-Host
    if ($LASTEXITCODE -ne 0) {
        $label = if ($ErrorLabel) { $ErrorLabel } else { "AWS CLI command failed" }
        throw ("{0}: {1}" -f $label, $cmd)
    }
}

$uploadCfg = Load-Config -Path $UploadConfigPath
$downloadCfg = Load-Config -Path $DownloadConfigPath

if (-not $Mode) {
    if ($uploadCfg -and -not $downloadCfg) {
        $Mode = "upload"
    } elseif ($downloadCfg -and -not $uploadCfg) {
        $Mode = "download"
    } elseif ($uploadCfg -and $downloadCfg) {
        throw "Both upload and download configs exist. Re-run with -Mode upload or -Mode download."
    } else {
        throw "No config files found. Run scripts/setup/setup-client.ps1 first."
    }
}

$cfg = if ($Mode -eq "upload") { $uploadCfg } else { $downloadCfg }
if (-not $cfg) {
    $path = if ($Mode -eq "upload") { $UploadConfigPath } else { $DownloadConfigPath }
    throw "Config file not found: $path"
}

$profile = $cfg.aws_profile
$region  = $cfg.aws_region
$bucket  = $cfg.bucket_name
$incoming = Normalize-Prefix $cfg.incoming_prefix
$kmsKey  = $cfg.kms_key_id

Write-Host ("Testing {0} client profile '{1}'..." -f $Mode,$profile) -ForegroundColor Cyan

Write-Host "1) Identity check" -ForegroundColor Cyan
Invoke-Aws -Args "sts get-caller-identity --profile $profile" -ErrorLabel "Identity check failed"

Write-Host "2) S3 list incoming/" -ForegroundColor Cyan
Invoke-Aws -Args "s3 ls s3://$bucket/$incoming --profile $profile" -ErrorLabel "S3 list failed"

Write-Host "3) KMS key describe" -ForegroundColor Cyan
Invoke-Aws -Args "kms describe-key --key-id $kmsKey --region $region --profile $profile" -ErrorLabel "KMS describe failed"

if ($Mode -eq "upload") {
    Write-Host "4) KMS data key (upload requires GenerateDataKey)" -ForegroundColor Cyan
    Invoke-Aws -Args "kms generate-data-key --key-id $kmsKey --region $region --profile $profile --key-spec AES_256" -ErrorLabel "KMS generate-data-key failed"
}

if ($RunScript) {
    Write-Host "5) Running client script..." -ForegroundColor Cyan
    if ($Mode -eq "upload") {
        $testFile = Join-Path $env:TEMP "secure-upload-test.txt"
        "test $(Get-Date -Format s)" | Set-Content -LiteralPath $testFile -Encoding UTF8
        pwsh -File (Join-Path $PSScriptRoot "..\\upload\\Upload_To_S3.ps1") -ConfigPath $UploadConfigPath -InputFilePath $testFile -AutoStart
        if ($LASTEXITCODE -ne 0) { throw "Upload script failed." }
    } else {
        $dest = Join-Path $env:TEMP "secure-download-test"
        if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest | Out-Null }
        pwsh -File (Join-Path $PSScriptRoot "..\\download\\Download_From_S3.ps1") -ConfigPath $DownloadConfigPath -DestinationPath $dest -AutoStart
        if ($LASTEXITCODE -ne 0) { throw "Download script failed." }
    }
}

Write-Host "Client test complete." -ForegroundColor Green
