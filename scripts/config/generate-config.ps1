<#
Purpose:
  Generate upload/download JSON configs directly from Terraform outputs.

When to use:
  - After Terraform apply to populate config.upload.json/config.download.json
  - When KMS key or prefixes change

Prerequisites:
  - Terraform initialized in EnvDir
  - Access to the environment's state

Inputs:
  - EnvDir (Terraform environment path)
  - UploadProfile / DownloadProfile (AWS CLI profile names)

Outputs:
  - config.upload.json and config.download.json

Common failure causes:
  - Terraform outputs missing (apply not run)
  - EnvDir points to wrong environment

Usage:
  pwsh -File scripts\config\generate-config.ps1 -EnvDir infra\envs\prod -UploadProfile SecureUpload -DownloadProfile SecureDownload -Force

Maintainer notes:
  - Output fields must remain aligned with Upload_To_S3.ps1 and Download_From_S3.ps1 expectations.
#>
[CmdletBinding()]
param(
    [string]$EnvDir = (Join-Path $PSScriptRoot "..\..\infra\envs\test"),
    [string]$OutDir = $PSScriptRoot,
    [Parameter(Mandatory=$true)][string]$UploadProfile,
    [Parameter(Mandatory=$true)][string]$DownloadProfile,
    [string]$UploadConfigPath = (Join-Path $PSScriptRoot "config.upload.json"),
    [string]$DownloadConfigPath = (Join-Path $PSScriptRoot "config.download.json"),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-PathExists {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found: $Path"
    }
}

function Write-JsonFile {
    param([string]$Path,[object]$Obj,[switch]$Force)
    if (-not $Force -and (Test-Path -LiteralPath $Path)) {
        # Avoid overwriting existing configs unless explicitly requested.
        throw "File already exists: $Path. Use -Force to overwrite."
    }
    $json = $Obj | ConvertTo-Json -Depth 6
    $json | Set-Content -LiteralPath $Path -Encoding UTF8
}

Assert-PathExists -Path $EnvDir -Label "EnvDir"
Assert-PathExists -Path $OutDir -Label "OutDir"

Push-Location -LiteralPath $EnvDir
try {
    $tfOutJson = & terraform output -json
}
finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0 -or -not $tfOutJson) {
    # Terraform outputs are the source of truth for bucket/KMS IDs.
    throw "terraform output failed in $EnvDir. Ensure you ran terraform init/apply."
}

$tf = $tfOutJson | ConvertFrom-Json

function Get-OutValue {
    param([object]$Obj,[string]$Name)
    if (-not $Obj.PSObject.Properties.Name -contains $Name) {
        throw "Terraform output '$Name' not found."
    }
    return $Obj.$Name.value
}

$bucketName = Get-OutValue -Obj $tf -Name "bucket_name"
$region     = Get-OutValue -Obj $tf -Name "aws_region"
$incoming   = Get-OutValue -Obj $tf -Name "incoming_prefix"
$artefacts  = Get-OutValue -Obj $tf -Name "artefacts_prefix"
$downloaded = Get-OutValue -Obj $tf -Name "download_prefix"
$kmsKeyArn  = Get-OutValue -Obj $tf -Name "kms_key_arn"

$uploadConfig = [ordered]@{
    aws_profile                       = $UploadProfile
    aws_region                        = $region
    bucket_name                       = $bucketName
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

$downloadConfig = [ordered]@{
    aws_profile          = $DownloadProfile
    aws_region           = $region
    bucket_name          = $bucketName
    incoming_prefix      = $incoming
    artefacts_prefix     = $artefacts
    downloaded_prefix    = $downloaded
    kms_key_id           = $kmsKeyArn
    cse_manifest_suffix  = ".cse.manifest.json"
    ciphertext_extension = ".enc"
    enable_log           = $true
    download_log_directory = "%USERPROFILE%\\Documents\\SecureDownloadLogs"
}

Write-JsonFile -Path $UploadConfigPath -Obj $uploadConfig -Force:$Force
Write-JsonFile -Path $DownloadConfigPath -Obj $downloadConfig -Force:$Force

Write-Host "Wrote upload config: $UploadConfigPath"
Write-Host "Wrote download config: $DownloadConfigPath"
