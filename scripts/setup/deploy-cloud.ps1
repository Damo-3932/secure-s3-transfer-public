<#
Purpose:
  One-command deployment wrapper for bootstrap + environment Terraform stacks.
  Ensures config files exist, initializes backend, and applies/validates.

When to use:
  - Local deployment (first-time or repeat)
  - Validation/plan runs before CI

Prerequisites:
  - Terraform installed
  - AWS CLI configured (optional AWS_PROFILE)
  - backend.hcl and terraform.tfvars populated for the environment

Inputs:
  - EnvDir, BootstrapDir
  - backend.hcl path, terraform.tfvars path
  - Optional AWS profile

Outputs:
  - Applies Terraform changes and initializes backend
  - Optionally generates client configs

Common failure causes:
  - Missing backend.hcl / terraform.tfvars values
  - AWS permissions insufficient for bootstrap or environment apply

Usage:
  pwsh -File scripts\setup\deploy-cloud.ps1 -EnvDir infra\envs\prod -AutoApprove

Maintainer notes:
  - Keep backend.hcl in sync with bootstrap outputs (bucket/table/KMS).
  - This script does not manage state import; use reconcile in CI for drift.
#>
[CmdletBinding()]
param(
    [string]$EnvDir = (Join-Path $PSScriptRoot "..\..\infra\envs\test"),
    [string]$BootstrapDir = (Join-Path $PSScriptRoot "..\..\infra\bootstrap\state_backend"),
    [string]$BackendConfigPath = (Join-Path $EnvDir "backend.hcl"),
    [string]$BackendConfigExample = (Join-Path $EnvDir "backend.hcl.example"),
    [string]$TfvarsPath = (Join-Path $EnvDir "terraform.tfvars"),
    [string]$TfvarsExample = (Join-Path $EnvDir "terraform.tfvars.example"),
    [string]$AwsProfile,
    [switch]$SkipBootstrap,
    [switch]$SkipBackendInit,
    [bool]$MigrateState = $true,
    [switch]$PlanOnly,
    [switch]$ValidateOnly,
    [switch]$AutoApprove,
    [switch]$GenerateConfigs,
    [string]$UploadProfile,
    [string]$DownloadProfile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($AwsProfile) {
    $env:AWS_PROFILE = $AwsProfile
}

# Normalize paths to absolute so terraform can read backend/config files regardless of cwd.
$EnvDir = [System.IO.Path]::GetFullPath($EnvDir)
if (-not $SkipBootstrap) {
    $BootstrapDir = [System.IO.Path]::GetFullPath($BootstrapDir)
}
$BackendConfigPath = [System.IO.Path]::GetFullPath($BackendConfigPath)
$BackendConfigExample = [System.IO.Path]::GetFullPath($BackendConfigExample)
$TfvarsPath = [System.IO.Path]::GetFullPath($TfvarsPath)
$TfvarsExample = [System.IO.Path]::GetFullPath($TfvarsExample)

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        # Stop early to avoid partial infrastructure changes.
        throw "Required command not found: $Name"
    }
}

function Assert-PathExists {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found: $Path"
    }
}

function Ensure-FileFromExample {
    param([string]$Target,[string]$Example,[string]$Label)
    if (Test-Path -LiteralPath $Target) { return $false }
    if (-not (Test-Path -LiteralPath $Example)) {
        throw "$Label not found: $Target (example also missing: $Example)"
    }
    # Create a starter file for operators, then force them to edit before running.
    Copy-Item -LiteralPath $Example -Destination $Target
    Write-Host "Created $Label from example: $Target" -ForegroundColor Yellow
    return $true
}

function Assert-AwsProfile {
    param([string]$Profile,[string]$Label)
    if (-not $Profile) { return }
    if (-not (Get-Command "aws" -ErrorAction SilentlyContinue)) {
        throw "AWS CLI not found. Install AWS CLI v2 and configure profile '$Profile'."
    }
    $profiles = @()
    try {
        $profiles = & aws configure list-profiles
    }
    catch {
        $profiles = @()
    }
    if ($profiles -and ($profiles -notcontains $Profile)) {
        throw "$Label profile not configured locally: $Profile. Run: aws configure sso --profile $Profile"
    }
}

Require-Command -Name "terraform"

Assert-PathExists -Path $EnvDir -Label "EnvDir"
if (-not $SkipBootstrap) {
    Assert-PathExists -Path $BootstrapDir -Label "BootstrapDir"
}

$needsEdit = $false
$needsEdit = (Ensure-FileFromExample -Target $BackendConfigPath -Example $BackendConfigExample -Label "backend.hcl") -or $needsEdit
$needsEdit = (Ensure-FileFromExample -Target $TfvarsPath -Example $TfvarsExample -Label "terraform.tfvars") -or $needsEdit
if ($needsEdit) {
    throw "One or more config files were created from examples. Edit them and rerun."
}

Assert-AwsProfile -Profile $AwsProfile -Label "AWS"

if (-not $SkipBootstrap) {
    Push-Location -LiteralPath $BootstrapDir
    try {
        & terraform init
        if ($LASTEXITCODE -ne 0) { throw "terraform init failed in $BootstrapDir" }
        if ($ValidateOnly) {
            & terraform validate
            if ($LASTEXITCODE -ne 0) { throw "terraform validate failed in $BootstrapDir" }
        } elseif ($PlanOnly) {
            & terraform plan
            if ($LASTEXITCODE -ne 0) { throw "terraform plan failed in $BootstrapDir" }
        } else {
            $applyArgs = @("apply")
            if ($AutoApprove) { $applyArgs += "-auto-approve" }
            & terraform @applyArgs
            if ($LASTEXITCODE -ne 0) { throw "terraform apply failed in $BootstrapDir" }
        }
    }
    finally {
        Pop-Location
    }
}

Push-Location -LiteralPath $EnvDir
try {
    if (-not $SkipBackendInit) {
        if ($ValidateOnly) {
            # Validation does not need the remote backend.
            & terraform init -backend=false
            if ($LASTEXITCODE -ne 0) { throw "terraform init failed in $EnvDir (backend disabled for validation)" }
        } else {
            # Use backend.hcl to lock state and store it centrally.
            $initArgs = @("init", "-backend-config=$BackendConfigPath")
            if ($MigrateState) { $initArgs += "-migrate-state" }
            & terraform @initArgs
            if ($LASTEXITCODE -ne 0) { throw "terraform init failed in $EnvDir" }
        }
    }

    if ($ValidateOnly) {
        & terraform validate
        if ($LASTEXITCODE -ne 0) { throw "terraform validate failed in $EnvDir" }
    } elseif ($PlanOnly) {
        & terraform plan
        if ($LASTEXITCODE -ne 0) { throw "terraform plan failed in $EnvDir" }
    } else {
        $applyArgs = @("apply")
        if ($AutoApprove) { $applyArgs += "-auto-approve" }
        & terraform @applyArgs
        if ($LASTEXITCODE -ne 0) { throw "terraform apply failed in $EnvDir" }
    }
}
finally {
    Pop-Location
}

if ($GenerateConfigs -and -not $PlanOnly -and -not $ValidateOnly) {
    if (-not $UploadProfile -or -not $DownloadProfile) {
        throw "GenerateConfigs requires -UploadProfile and -DownloadProfile."
    }
    $genScript = Join-Path $PSScriptRoot "..\config\generate-config.ps1"
    & $genScript -EnvDir $EnvDir -UploadProfile $UploadProfile -DownloadProfile $DownloadProfile -Force
    if ($LASTEXITCODE -ne 0) { throw "Config generation failed." }
}

if ($ValidateOnly) {
    Write-Host "Validation complete." -ForegroundColor Green
} elseif ($PlanOnly) {
    Write-Host "Plan complete." -ForegroundColor Green
} else {
    Write-Host "Deployment complete." -ForegroundColor Green
}
