<#
Purpose:
  Full operational test combining interactive upload/download with policy checks.
  Intended for deep validation after deployment or major changes.

When to use:
  - Pre-governance review or demo
  - After security policy or KMS key changes

Prerequisites:
  - AWS CLI v2
  - Terraform outputs available in EnvDir
  - SSO login for BaseProfile

Inputs:
  - Environment or EnvDir
  - BaseProfile / UploadProfile / DownloadProfile

Outputs:
  - Policy summary (PASS/WARN/FAIL)
  - Optional cleanup of test objects

Usage:
  pwsh -File scripts\run-full-test.ps1 -Environment prod -Cleanup

Maintainer notes:
  - This test includes negative checks that are expected to fail for security reasons.
#>
[CmdletBinding()]
param(
    [ValidateSet("test","prod")][string]$Environment = "test",
    [string]$EnvDir = $null,
    [string]$BaseProfile = "Developer",
    [string]$UploadProfile = "SecureUpload",
    [string]$DownloadProfile = "SecureDownload",
    [string]$UploadScript = (Join-Path $PSScriptRoot "upload\Upload_To_S3.ps1"),
    [string]$DownloadScript = (Join-Path $PSScriptRoot "download\Download_From_S3.ps1"),
    [switch]$SkipInteractive,
    [switch]$Cleanup,
    [switch]$VerifyWithBaseProfile
)

# Set EnvDir based on Environment parameter if not explicitly provided
if ([string]::IsNullOrWhiteSpace($EnvDir)) {
    $EnvDir = Join-Path $PSScriptRoot "..\infra\envs\$Environment"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Tracks policy check outcomes for a concise end-of-run summary.
# We store PASS/WARN/FAIL + details and print once at the end.
$policyResults = New-Object System.Collections.Generic.List[object]

# Helper: run AWS CLI with captured output and exit code.
# Keeping CLI calls in one place avoids repeated $LASTEXITCODE checks.
function Invoke-Aws {
    param([string[]]$CliArgs)
    $out = & aws @CliArgs 2>&1
    return @{
        ExitCode = $LASTEXITCODE
        Output   = ($out | Out-String).Trim()
    }
}

# Helper: read Terraform outputs from the env dir to avoid hard-coded values.
# This prevents drift between scripts and deployed infrastructure.
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

# Helper: stop execution with a clear label when a CLI call fails.
# Used for steps that must succeed (e.g., SSO login).
function Assert-Ok {
    param([string]$Label,[hashtable]$Result)
    if ($Result.ExitCode -ne 0) {
        throw "$Label failed: $($Result.Output)"
    }
}

Write-Host "== Secure S3 Transfer Full Test ==" -ForegroundColor Cyan

# Base SSO login is required for role-chaining profiles (SecureUpload/SecureDownload).
# If SSO is expired, all downstream AWS CLI calls will fail.
Write-Host "Logging in to SSO ($BaseProfile)..." -ForegroundColor Gray
$login = Invoke-Aws -CliArgs @("sso","login","--profile",$BaseProfile)
Assert-Ok -Label "SSO login" -Result $login

# Timestamp used to generate deterministic temp filenames.
$runStamp = (Get-Date -Format "yyyyMMdd_HHmmss")

# Pull outputs from Terraform so we always test the current env.
$tf = Get-TerraformOutputs -Dir $EnvDir
$bucket = $tf.bucket_name.value
$region = $tf.aws_region.value
$incoming = $tf.incoming_prefix.value
$artefacts = $tf.artefacts_prefix.value
$downloaded = $tf.download_prefix.value
$kmsKeyArn = $tf.kms_key_arn.value
$trailName = $null
if ($tf.PSObject.Properties.Name -contains "cloudtrail_name") {
    $trailName = $tf.cloudtrail_name.value
}
# Audit bucket output is optional (module may be disabled in some envs).
$auditBucket = $null
if ($tf.PSObject.Properties.Name -contains "audit_log_bucket_name") {
    $auditBucket = $tf.audit_log_bucket_name.value
}

if (-not $SkipInteractive) {
    if (-not (Test-Path -LiteralPath $UploadScript)) { throw "Upload script not found: $UploadScript" }
    if (-not (Test-Path -LiteralPath $DownloadScript)) { throw "Download script not found: $DownloadScript" }

    Write-Host ""
    Write-Host "Step 1/2: Upload (interactive)" -ForegroundColor Cyan
    Write-Host "A new PowerShell process will run the upload script (STA)." -ForegroundColor Gray
    Write-Host "Complete the upload, then return here." -ForegroundColor Gray
    # AutoStart removes prompts; SkipDefenderScan avoids a long-running scan during automation.
    $autoUploadArgs = @("-Sta","-File",$UploadScript,"-AutoStart","-SkipDefenderScan")
    if (-not [string]::IsNullOrWhiteSpace($Env:SECURE_S3_TEST_FILE)) {
        # Use a provided file if the caller supplied one.
        $autoUploadArgs += @("-InputFilePath",$Env:SECURE_S3_TEST_FILE)
    } else {
        # Generate a small temp file for a fully automated upload.
        $autoFile = Join-Path $env:TEMP "secure-s3-transfer-auto-upload-$runStamp.txt"
        "auto-upload $runStamp" | Set-Content -LiteralPath $autoFile -Encoding ASCII
        $autoUploadArgs += @("-InputFilePath",$autoFile)
    }
    & pwsh @autoUploadArgs

}

Write-Host ""
Write-Host "Policy checks..." -ForegroundColor Cyan

# Uploader can list incoming/ but should not be able to read objects.
# We use s3api to avoid prefix formatting quirks in the high-level CLI.
$listIncoming = Invoke-Aws -CliArgs @(
    "s3api","list-objects-v2",
    "--bucket",$bucket,
    "--prefix",$incoming,
    "--max-items","1",
    "--output","json",
    "--profile",$UploadProfile,
    "--region",$region
)
if ($listIncoming.ExitCode -ne 0) {
    $policyResults.Add([pscustomobject]@{ Check = "Uploader list incoming"; Result = "FAIL"; Detail = $listIncoming.Output }) | Out-Null
} else {
    $policyResults.Add([pscustomobject]@{ Check = "Uploader list incoming"; Result = "PASS"; Detail = "" }) | Out-Null
}

# Attempt to read the newest object (should fail if any exist).
$latestKey = $null
if ($listIncoming.Output) {
    try {
        $obj = $listIncoming.Output | ConvertFrom-Json
        if ($obj.Contents -and $obj.Contents.Count -gt 0) {
            $latestKey = $obj.Contents[0].Key
        }
    } catch {}
}

if ($latestKey) {
    # Attempt to read the newest object (expected deny).
    $read = Invoke-Aws -CliArgs @(
        "s3","cp","s3://$bucket/$latestKey",(Join-Path $env:TEMP "fulltest-read-$runStamp.txt"),
        "--profile",$UploadProfile,
        "--region",$region
    )
    if ($read.ExitCode -eq 0) {
        $policyResults.Add([pscustomobject]@{ Check = "Uploader read denied"; Result = "FAIL"; Detail = "Read succeeded" }) | Out-Null
    } else {
        $policyResults.Add([pscustomobject]@{ Check = "Uploader read denied"; Result = "PASS"; Detail = "" }) | Out-Null
    }
} else {
    $policyResults.Add([pscustomobject]@{ Check = "Uploader read denied"; Result = "WARN"; Detail = "No objects in incoming/ to test read denial" }) | Out-Null
}

# Downloader should not be able to write to incoming/.
$tmpFile = Join-Path $env:TEMP "fulltest-write.txt"
"full-test" | Set-Content -LiteralPath $tmpFile -Encoding ASCII
$write = Invoke-Aws -CliArgs @(
    "s3","cp",$tmpFile,"s3://$bucket/$incoming",
    "--profile",$DownloadProfile,
    "--region",$region,
    "--sse","aws:kms",
    "--sse-kms-key-id",$kmsKeyArn
)
if ($write.ExitCode -eq 0) {
    $policyResults.Add([pscustomobject]@{ Check = "Downloader write denied"; Result = "FAIL"; Detail = "Write succeeded" }) | Out-Null
} else {
    $policyResults.Add([pscustomobject]@{ Check = "Downloader write denied"; Result = "PASS"; Detail = "" }) | Out-Null
}

# Downloader should not be able to list downloaded/.
$listDownloaded = Invoke-Aws -CliArgs @(
    "s3","ls","s3://$bucket/$downloaded",
    "--profile",$DownloadProfile,
    "--region",$region
)
if ($listDownloaded.ExitCode -eq 0) {
    $policyResults.Add([pscustomobject]@{ Check = "Downloader list downloaded denied"; Result = "FAIL"; Detail = "List succeeded" }) | Out-Null
} else {
    $policyResults.Add([pscustomobject]@{ Check = "Downloader list downloaded denied"; Result = "PASS"; Detail = "" }) | Out-Null
}

# SSE-KMS enforcement: attempt upload without SSE headers (should fail).
$noSse = Invoke-Aws -CliArgs @(
    "s3","cp",$tmpFile,"s3://$bucket/$incoming",
    "--profile",$UploadProfile,
    "--region",$region
)
if ($noSse.ExitCode -eq 0) {
    $policyResults.Add([pscustomobject]@{ Check = "SSE-KMS enforcement"; Result = "FAIL"; Detail = "Upload without SSE-KMS succeeded" }) | Out-Null
} else {
    $policyResults.Add([pscustomobject]@{ Check = "SSE-KMS enforcement"; Result = "PASS"; Detail = "" }) | Out-Null
}

if ($VerifyWithBaseProfile) {
    Write-Host ""
    Write-Host "Verifying artefacts with base profile..." -ForegroundColor Cyan
    $artefactList = Invoke-Aws -CliArgs @(
        "s3","ls","s3://$bucket/$artefacts",
        "--profile",$BaseProfile,
        "--region",$region
    )
    if ($artefactList.ExitCode -eq 0 -and $artefactList.Output) {
        $policyResults.Add([pscustomobject]@{ Check = "Artefacts present (base profile)"; Result = "PASS"; Detail = "" }) | Out-Null
    } else {
        $policyResults.Add([pscustomobject]@{ Check = "Artefacts present (base profile)"; Result = "WARN"; Detail = "Not found or list denied" }) | Out-Null
    }
}

# Audit logging checks (non-blocking).
# These can be WARN if logs haven't been delivered yet.
if ($auditBucket -and $trailName) {
    $trailStatus = Invoke-Aws -CliArgs @(
        "cloudtrail","get-trail-status",
        "--name",$trailName,
        "--profile",$BaseProfile,
        "--region",$region,
        "--output","json"
    )
    if ($trailStatus.ExitCode -eq 0) {
        try {
            $ts = $trailStatus.Output | ConvertFrom-Json
            if ($ts.IsLogging -eq $true) {
                $policyResults.Add([pscustomobject]@{ Check = "Audit logging enabled"; Result = "PASS"; Detail = "" }) | Out-Null
            } else {
                $policyResults.Add([pscustomobject]@{ Check = "Audit logging enabled"; Result = "FAIL"; Detail = "CloudTrail IsLogging=false" }) | Out-Null
            }
        } catch {
            $policyResults.Add([pscustomobject]@{ Check = "Audit logging enabled"; Result = "WARN"; Detail = "Unable to parse CloudTrail status" }) | Out-Null
        }
    } else {
        $policyResults.Add([pscustomobject]@{ Check = "Audit logging enabled"; Result = "WARN"; Detail = $trailStatus.Output }) | Out-Null
    }

    $auditList = Invoke-Aws -CliArgs @(
        "s3","ls","s3://$auditBucket/cloudtrail/AWSLogs/",
        "--profile",$BaseProfile,
        "--region",$region
    )
    if ($auditList.ExitCode -eq 0 -and $auditList.Output) {
        $policyResults.Add([pscustomobject]@{ Check = "Audit log delivery"; Result = "PASS"; Detail = "" }) | Out-Null
    } else {
        $policyResults.Add([pscustomobject]@{
            Check  = "Audit log delivery"
            Result = "WARN"
            Detail = "No objects found yet. This can be normal due to CloudTrail delivery delays."
        }) | Out-Null
    }
}

if (-not $SkipInteractive) {
    Write-Host ""
    Write-Host "Step 2/2: Download (interactive)" -ForegroundColor Cyan
    Write-Host "Complete the download, then return here." -ForegroundColor Gray
    # Use a deterministic temp folder for automated downloads.
    $destRoot = Join-Path $env:TEMP "secure-s3-transfer-download"
    & pwsh -File $DownloadScript -AutoStart -DestinationPath $destRoot
}

if ($Cleanup) {
    Write-Host ""
    Write-Host "Cleanup (downloader)..." -ForegroundColor Cyan
    $rmIncoming = Invoke-Aws -CliArgs @(
        "s3","rm","s3://$bucket/$incoming",
        "--recursive",
        "--profile",$DownloadProfile,
        "--region",$region
    )
    if ($rmIncoming.ExitCode -ne 0) {
        Write-Host "Cleanup incoming failed: $($rmIncoming.Output)" -ForegroundColor Yellow
    } else {
        Write-Host "Cleanup incoming complete." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Policy summary:" -ForegroundColor Cyan
foreach ($r in $policyResults) {
    $color = if ($r.Result -eq "PASS") { "Green" } elseif ($r.Result -eq "WARN") { "Yellow" } else { "Red" }
    $suffix = if ($r.Detail) { " - $($r.Detail)" } else { "" }
    Write-Host ("{0}: {1}{2}" -f $r.Check, $r.Result, $suffix) -ForegroundColor $color
}

Write-Host ""
Write-Host "Full test complete." -ForegroundColor Cyan
