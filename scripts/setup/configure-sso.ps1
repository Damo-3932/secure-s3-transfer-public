<#
Purpose:
  Create/update an AWS CLI SSO profile using local .env values.

When to use:
  - Called by setup-client.ps1 during onboarding
  - Re-run if SSO role names or account change

Prerequisites:
  - AWS CLI v2 installed
  - .env populated with SSO settings

Inputs:
  - ProfileName (target AWS CLI profile)
  - Mode (upload/download)
  - .env file path

Outputs / changes:
  - Writes to ~/.aws/config (SSO profile entries)

Common failure causes:
  - Missing SSO values in .env
  - Role name mismatch with Identity Center permission sets
  - AWS CLI not installed

Usage:
  pwsh -File scripts\setup\configure-sso.ps1 -ProfileName SecureUpload -Mode upload

Maintainer notes:
  - Role name convention must match Identity Center permission sets.
  - Changing ENVIRONMENT or role naming in Terraform requires updates here.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ProfileName,
    [Parameter(Mandatory=$true)][ValidateSet("upload","download")][string]$Mode,
    [string]$EnvFile = (Join-Path $PSScriptRoot "..\\..\\.env")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        # Fail early to avoid creating partial profiles.
        throw "Required command not found: $Name"
    }
}

function Read-EnvFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Env file not found: $Path (copy .env.example to .env and fill values)."
    }
    $map = @{}
    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    foreach ($line in $lines) {
        $trim = $line.Trim()
        if (-not $trim -or $trim.StartsWith("#")) { continue }
        $idx = $trim.IndexOf("=")
        if ($idx -lt 1) { continue }
        $key = $trim.Substring(0, $idx).Trim()
        $val = $trim.Substring($idx + 1).Trim()
        if ($val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Trim('"') }
        if ($val.StartsWith("'") -and $val.EndsWith("'")) { $val = $val.Trim("'") }
        $map[$key] = $val
    }
    return $map
}

function Require-EnvValue {
    param([hashtable]$Map,[string]$Key)
    if (-not $Map.ContainsKey($Key) -or [string]::IsNullOrWhiteSpace($Map[$Key])) {
        throw "Missing $Key in env file."
    }
    return $Map[$Key]
}

Require-Command -Name "aws"

$envMap = Read-EnvFile -Path $EnvFile

$startUrl  = Require-EnvValue -Map $envMap -Key "SSO_START_URL"
$ssoRegion = Require-EnvValue -Map $envMap -Key "SSO_REGION"
$accountId = Require-EnvValue -Map $envMap -Key "SSO_ACCOUNT_ID"
$awsRegion = Require-EnvValue -Map $envMap -Key "AWS_REGION"
$awsOutput = Require-EnvValue -Map $envMap -Key "AWS_OUTPUT"
$environment = Require-EnvValue -Map $envMap -Key "ENVIRONMENT"

# Construct role name dynamically to align with Identity Center permission sets.
$capitalizedEnv = $environment.Substring(0,1).ToUpper() + $environment.Substring(1)
$modeCapitalized = if ($Mode -eq "upload") { "Uploader" } else { "Downloader" }
$roleName = "SecureS3Transfer-{0}-{1}" -f $capitalizedEnv, $modeCapitalized

aws configure set "profile.$ProfileName.sso_start_url" $startUrl | Out-Null
aws configure set "profile.$ProfileName.sso_region" $ssoRegion | Out-Null
aws configure set "profile.$ProfileName.sso_account_id" $accountId | Out-Null
aws configure set "profile.$ProfileName.sso_role_name" $roleName | Out-Null
aws configure set "profile.$ProfileName.region" $awsRegion | Out-Null
aws configure set "profile.$ProfileName.output" $awsOutput | Out-Null

Write-Host ("Configured SSO profile: {0} ({1})" -f $ProfileName, $roleName) -ForegroundColor Green
