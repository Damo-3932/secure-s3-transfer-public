<#
Purpose:
  Create a role-based AWS CLI profile and client config using Terraform outputs.
  Intended for operators who already have a source profile (e.g., admin/dev).

When to use:
  - After Terraform apply to generate role-based profiles for upload/download
  - When rotating KMS keys or changing prefixes

Prerequisites:
  - Terraform initialized for the target environment
  - AWS CLI v2 installed
  - Source profile with permission to assume roles

Inputs:
  - EnvDir (Terraform environment directory)
  - Mode (upload/download)
  - ProfileName (new profile to create)
  - SourceProfile (existing profile used to assume role)

Outputs / changes:
  - Writes AWS CLI profile settings (role_arn + source_profile)
  - Writes config.upload.json or config.download.json

Common failure causes:
  - Terraform outputs missing (no apply yet)
  - Source profile not present in ~/.aws/config
  - Role ARN not assumable (permissions/SSO)

Usage:
  pwsh -File scripts\setup\configure-user.ps1 -Mode upload -ProfileName SecureUpload -SourceProfile Developer -EnvDir infra\envs\prod

Maintainer notes:
  - Output keys must align with Terraform outputs (see infra/envs/*).
  - Changing prefixes or KMS IDs in Terraform requires regenerating configs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet("upload","download")][string]$Mode,
    [Parameter(Mandatory=$true)][string]$ProfileName,
    [Parameter(Mandatory=$true)][string]$SourceProfile,
    [string]$EnvDir = (Join-Path $PSScriptRoot "..\..\infra\envs\test"),
    [string]$OutDir = (Join-Path $PSScriptRoot "..\..\scripts\config"),
    [switch]$Force,
    [switch]$SkipConfigFile,
    [switch]$SkipProfileSettings
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        # Avoid generating partial configs if required tooling is missing.
        throw "Required command not found: $Name"
    }
}

function Assert-PathExists {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found: $Path"
    }
}

function Get-TerraformOutputs {
    param([string]$Path)
    Push-Location -LiteralPath $Path
    try {
        $json = & terraform output -json
    }
    finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0 -or -not $json) {
        # Outputs are the authoritative source of bucket/KMS values.
        throw "terraform output failed in $Path. Run terraform init/apply first."
    }
    return ($json | ConvertFrom-Json)
}

function Get-OutValue {
    param([object]$Obj,[string]$Name)
    if (-not $Obj.PSObject.Properties.Name -contains $Name) {
        throw "Terraform output '$Name' not found."
    }
    return $Obj.$Name.value
}

function Write-JsonFile {
    param([string]$Path,[object]$Obj,[switch]$Force)
    if (-not $Force -and (Test-Path -LiteralPath $Path)) {
        throw "File already exists: $Path. Use -Force to overwrite."
    }
    $json = $Obj | ConvertTo-Json -Depth 6
    $json | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Set-ProfileSetting {
    param([string]$Profile,[string]$Key,[string]$Value)
    aws configure set "profile.$Profile.$Key" $Value | Out-Null
}

function Apply-TransferSettings {
    param([string]$Profile)
    # These defaults improve reliability for large-file transfers.
    Set-ProfileSetting -Profile $Profile -Key "s3.multipart_chunksize" -Value "256MB"
    Set-ProfileSetting -Profile $Profile -Key "s3.max_concurrent_requests" -Value "10"
    Set-ProfileSetting -Profile $Profile -Key "max_attempts" -Value "10"
    Set-ProfileSetting -Profile $Profile -Key "retry_mode" -Value "adaptive"
    Set-ProfileSetting -Profile $Profile -Key "s3.use_accelerate_endpoint" -Value "true"
}

Require-Command -Name "terraform"
Assert-PathExists -Path $EnvDir -Label "EnvDir"

$tf = Get-TerraformOutputs -Path $EnvDir

$region    = Get-OutValue -Obj $tf -Name "aws_region"
$bucket    = Get-OutValue -Obj $tf -Name "bucket_name"
$incoming  = Get-OutValue -Obj $tf -Name "incoming_prefix"
$artefacts = Get-OutValue -Obj $tf -Name "artefacts_prefix"
$download  = Get-OutValue -Obj $tf -Name "download_prefix"
$kmsKeyArn = Get-OutValue -Obj $tf -Name "kms_key_arn"

if ($Mode -eq "upload") {
    $roleArn = Get-OutValue -Obj $tf -Name "uploader_role_arn"
} else {
    $roleArn = Get-OutValue -Obj $tf -Name "downloader_role_arn"
}

if (-not $SkipProfileSettings) {
    Require-Command -Name "aws"
    $profiles = @()
    try {
        $profiles = & aws configure list-profiles
    }
    catch {
        $profiles = @()
    }
    if ($profiles -and ($profiles -notcontains $SourceProfile)) {
        throw "Source profile not found in AWS config: $SourceProfile"
    }

    Set-ProfileSetting -Profile $ProfileName -Key "role_arn" -Value $roleArn
    Set-ProfileSetting -Profile $ProfileName -Key "source_profile" -Value $SourceProfile
    Set-ProfileSetting -Profile $ProfileName -Key "region" -Value $region
    Set-ProfileSetting -Profile $ProfileName -Key "role_session_name" -Value ("secure-s3-{0}-{1}" -f $Mode,$env:USERNAME)
    Apply-TransferSettings -Profile $ProfileName
}

if (-not $SkipConfigFile) {
    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }

    if ($Mode -eq "upload") {
        $configPath = Join-Path $OutDir "config.upload.json"
        $config = [ordered]@{
            aws_profile                       = $ProfileName
            aws_region                        = $region
            bucket_name                       = $bucket
            incoming_prefix                   = $incoming
            artefacts_prefix                  = $artefacts
            kms_key_id                        = $kmsKeyArn
            enable_client_side_encryption     = $true
            cse_chunk_size_mb                 = 4
            cse_manifest_suffix               = ".cse.manifest.json"
            ciphertext_extension              = ".enc"
            use_transfer_acceleration         = $true
            enable_upload_checksum            = $true
            upload_checksum_algorithm         = "SHA256"
            store_ciphertext_with_enc_extension = $true
            upload_progress_sample_ms         = 250
            enable_defender_scan              = $true
            defender_scan_poll_ms             = 500
            enable_log                        = $true
            upload_log_directory              = "%USERPROFILE%\\Documents\\SecureUploadLogs"
        }
    } else {
        $configPath = Join-Path $OutDir "config.download.json"
        $config = [ordered]@{
            aws_profile            = $ProfileName
            aws_region             = $region
            bucket_name            = $bucket
            incoming_prefix        = $incoming
            artefacts_prefix       = $artefacts
            downloaded_prefix      = $download
            kms_key_id             = $kmsKeyArn
            cse_manifest_suffix    = ".cse.manifest.json"
            ciphertext_extension   = ".enc"
            enable_log             = $true
            download_log_directory = "%USERPROFILE%\\Documents\\SecureDownloadLogs"
        }
    }

    Write-JsonFile -Path $configPath -Obj $config -Force:$Force
    Write-Host "Wrote config: $configPath" -ForegroundColor Green
}

Write-Host ("Configured {0} user profile: {1}" -f $Mode,$ProfileName) -ForegroundColor Green
