<#
Purpose:
  Secure upload client for the Secure S3 Transfer system. Performs optional malware
  scanning, client-side envelope encryption, SHA-256 integrity generation, and
  uploads payload + artefacts into controlled S3 prefixes.

When to use:
  - Daily uploader operations after setup-client.ps1 is complete
  - Automated test uploads in controlled environments

Prerequisites:
  - PowerShell 7 (required for AES-GCM + JSON behavior)
  - AWS CLI v2
  - Valid SSO profile with uploader permissions
  - config.upload.json (see scripts/config/config.upload.example.json)

Inputs:
  - config.upload.json
  - Input file path (via parameter or file picker)

Outputs / changes:
  - Encrypted payload in incoming/
  - SHA-256 file + manifest in incoming/artefacts/
  - Local logs in %USERPROFILE%\Documents\SecureUploadLogs

Logs:
  - %USERPROFILE%\Documents\SecureUploadLogs\UploadLog_*.log

Common failure causes:
  - KMS GenerateDataKey denied (key policy or IAM policy)
  - Missing/invalid SSO role assignment
  - Bucket policy denies SSE-KMS or wrong key
  - Transfer acceleration enabled in profile but disabled on bucket

Usage:
  pwsh -File scripts\upload\Upload_To_S3.ps1 -InputFilePath C:\path\file.ext -AutoStart

Maintainer notes:
  - CSE/manifest format must remain compatible with Download_From_S3.ps1.
  - Bucket policy enforces SSE-KMS; keep kms_key_id aligned with Terraform outputs.
  - Do not remove integrity hashing; it is the primary tamper check.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\config\config.upload.json"),
    [string]$InputFilePath = $null,
    [switch]$AutoStart,
    [switch]$SkipDefenderScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
$host.UI.RawUI.WindowTitle = "SECURE UPLOAD - DO NOT CLOSE THIS WINDOW"

# -------------------- HARD REQUIREMENTS --------------------
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script REQUIRES PowerShell 7+. You are running PowerShell $($PSVersionTable.PSVersion). Fix your shortcut to run pwsh.exe."
}

function Test-AesGcmAvailable {
    try {
        $key   = New-Object byte[] 32
        $nonce = New-Object byte[] 12
        $pt    = New-Object byte[] 1
        $ct    = New-Object byte[] 1
        $tag   = New-Object byte[] 16
        $gcm = [System.Security.Cryptography.AesGcm]::new($key)
        try { $gcm.Encrypt($nonce, $pt, $ct, $tag, $null) } finally { $gcm.Dispose() }
        return $true
    } catch { return $false }
}

function Load-ConfigFile {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Config file not found: $fullPath. Copy scripts/config/config.upload.example.json to scripts/config/config.upload.json and edit."
    }

    $raw = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
}

function Get-ConfigValue {
    param(
        [Parameter(Mandatory=$true)][object]$Config,
        [Parameter(Mandatory=$true)][string]$Name,
        [object]$Default = $null,
        [switch]$Required
    )

    $val = $Default
    if ($Config.PSObject.Properties.Name -contains $Name) {
        $val = $Config.$Name
    }

    if ($Required) {
        if ($null -eq $val) { throw "Config '$Name' is required." }
        if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { throw "Config '$Name' is required." }
    }

    return $val
}

function Normalize-Prefix {
    param(
        [Parameter(Mandatory=$true)][string]$Prefix,
        [Parameter(Mandatory=$true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Prefix)) { throw "Config '$Name' is required." }
    if (-not $Prefix.EndsWith("/")) { return ($Prefix + "/") }
    return $Prefix
}

# -------------------- CONFIG --------------------
# Config is loaded from JSON to keep environment-specific values out of source control
# and to allow different uploader profiles without changing script logic.
$ToolVersion = "v1.5.0-PS7-CSE-GCM-PROGRESS-REAL"

$cfg = Load-ConfigFile -Path $ConfigPath

$AwsProfile = Get-ConfigValue -Config $cfg -Name "aws_profile" -Required
$AwsRegion  = Get-ConfigValue -Config $cfg -Name "aws_region" -Required
$BucketName = Get-ConfigValue -Config $cfg -Name "bucket_name" -Required
# Uploads always go under the "incoming/" prefix so downloaders know where to read.
$KeyPrefix  = Normalize-Prefix -Prefix (Get-ConfigValue -Config $cfg -Name "incoming_prefix" -Required) -Name "incoming_prefix"
$ArtefactsPrefix = Normalize-Prefix -Prefix (Get-ConfigValue -Config $cfg -Name "artefacts_prefix" -Required) -Name "artefacts_prefix"

if (-not $ArtefactsPrefix.StartsWith($KeyPrefix)) {
    throw "artefacts_prefix must be under incoming_prefix (e.g., incoming/artefacts/)."
}

$UseTransferAcceleration = [bool](Get-ConfigValue -Config $cfg -Name "use_transfer_acceleration" -Default $true)
$script:AccelerationStatus = "unknown"

# Client-side encryption (CSE) is optional but recommended for defense in depth.
$EnableClientSideEncryption = [bool](Get-ConfigValue -Config $cfg -Name "enable_client_side_encryption" -Default $true)
$KmsKeyId = Get-ConfigValue -Config $cfg -Name "kms_key_id" -Default $null
$CseChunkSizeMb = [int](Get-ConfigValue -Config $cfg -Name "cse_chunk_size_mb" -Default 4)
$CseChunkSizeBytes = $CseChunkSizeMb * 1MB
$CseManifestSuffix = Get-ConfigValue -Config $cfg -Name "cse_manifest_suffix" -Default ".cse.manifest.json"

$EnableUploadChecksum = [bool](Get-ConfigValue -Config $cfg -Name "enable_upload_checksum" -Default $true)
$UploadChecksumAlgorithm = Get-ConfigValue -Config $cfg -Name "upload_checksum_algorithm" -Default "SHA256"

$StoreCiphertextWithEncExtension = [bool](Get-ConfigValue -Config $cfg -Name "store_ciphertext_with_enc_extension" -Default $true)
$CiphertextExtension = Get-ConfigValue -Config $cfg -Name "ciphertext_extension" -Default ".enc"
if ($CiphertextExtension -and -not $CiphertextExtension.StartsWith(".")) {
    $CiphertextExtension = "." + $CiphertextExtension
}

$UploadProgressSampleMs = [int](Get-ConfigValue -Config $cfg -Name "upload_progress_sample_ms" -Default 250)
$FinalizeTimeoutSec = 180
$FinalizePollSec = 5

$EnableDefenderScan = [bool](Get-ConfigValue -Config $cfg -Name "enable_defender_scan" -Default $true)
$DefenderScanPollMs = [int](Get-ConfigValue -Config $cfg -Name "defender_scan_poll_ms" -Default 500)

$EnableLog = [bool](Get-ConfigValue -Config $cfg -Name "enable_log" -Default $true)
$LogDirectory = Get-ConfigValue -Config $cfg -Name "upload_log_directory" -Default (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecureUploadLogs")
$LogDirectory = [Environment]::ExpandEnvironmentVariables([string]$LogDirectory)

# If CSE is enabled we must have a KMS key to mint data keys.
if ($EnableClientSideEncryption -and [string]::IsNullOrWhiteSpace($KmsKeyId)) {
    throw "Config 'kms_key_id' is required when enable_client_side_encryption is true."
}

# Bucket policy enforces SSE-KMS, so a key ID is always required even without CSE.
if ([string]::IsNullOrWhiteSpace($KmsKeyId)) {
    throw "Config 'kms_key_id' is required because the bucket policy enforces SSE-KMS on uploads."
}

if ($EnableClientSideEncryption -and -not (Test-AesGcmAvailable)) {
    throw "AesGcm is not usable in this runtime. This usually means the crypto provider isn't available. Update PS7/.NET or disable client-side encryption."
}

if ($SkipDefenderScan) {
    $EnableDefenderScan = $false
}

# AWS CLI retry behavior (network reliability over raw speed).
$env:AWS_RETRY_MODE   = "adaptive"
$env:AWS_MAX_ATTEMPTS = "20"
$env:AWS_PAGER        = ""

# -------------------- UI HELPERS --------------------
function Initialize-ProgressUi {
    try {
        if ($null -ne $PSStyle -and $PSStyle.Progress) {
            $PSStyle.Progress.View = "Classic"
        }
    } catch {}

    $global:ProgressPreference = "Continue"
    $script:LastStatusLineWrite = [DateTime]::MinValue

    try {
        $w = [Console]::WindowWidth
        if ($w -gt 0) { $script:StatusLineWidth = $w - 1 }
        else { $script:StatusLineWidth = 180 }
    } catch {
        $script:StatusLineWidth = 180
    }
}

function Write-StatusLine([string]$Text) {
    if ([Console]::IsOutputRedirected) {
        $now = [DateTime]::UtcNow
        if (($now - $script:LastStatusLineWrite).TotalSeconds -lt 1) { return }
        $script:LastStatusLineWrite = $now
        Write-Host $Text
        return
    }

    $width = if ($script:StatusLineWidth -gt 0) { $script:StatusLineWidth } else { 180 }
    if ($Text.Length -gt $width) { $Text = $Text.Substring(0, $width) }
    else { $Text = $Text.PadRight($width) }

    [Console]::Write("`r$Text")
    [Console]::Out.Flush()
}

function Clear-StatusLine {
    if ([Console]::IsOutputRedirected) { return }
    $width = if ($script:StatusLineWidth -gt 0) { $script:StatusLineWidth } else { 180 }
    [Console]::Write("`r" + (" " * $width) + "`r")
}

function Start-Step {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [string]$Description = $null
    )
    if ($script:LastStepStart) {
        $elapsed = (Get-Date) - $script:LastStepStart
        if ($script:LastStepTitle) {
            Write-Host ("  Completed: {0} in {1}" -f $script:LastStepTitle, (Format-Duration $elapsed)) -ForegroundColor DarkGray
        } else {
            Write-Host ("  Step time: {0}" -f (Format-Duration $elapsed)) -ForegroundColor DarkGray
        }
    }
    $script:LastStepStart = Get-Date
    $script:LastStepTitle = $Title
    $script:StepIndex++
    Write-Host ""
    Write-Host ("[STEP {0}/{1}] {2}" -f $script:StepIndex, $script:StepTotal, $Title) -ForegroundColor Cyan
    if ($Description) {
        Write-Host ("  {0}" -f $Description) -ForegroundColor Gray
    }
    Write-Host ""
}

function Write-Log([string]$Message) {
    if (-not $EnableLog) { return }
    if (-not $script:LogFilePath) { return }
    try {
        $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
        [System.IO.File]::AppendAllText($script:LogFilePath, $line + [Environment]::NewLine)
    } catch {}
}

function Initialize-Log {
    if (-not $EnableLog) { return }
    try { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null } catch {}
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:LogFilePath = Join-Path -Path $LogDirectory -ChildPath ("UploadLog_{0}.log" -f $stamp)
    Write-Log "Log started."
}

function Escape-PowerShellSingleQuote([string]$Text) {
    return ($Text -replace "'", "''")
}

function Format-Bytes([Int64]$Bytes) {
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Format-Duration([TimeSpan]$ts) {
    if ($ts.TotalHours -ge 1) { return "{0:00}h {1:00}m {2:00}s" -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds }
    if ($ts.TotalMinutes -ge 1) { return "{0:00}m {1:00}s" -f $ts.Minutes, $ts.Seconds }
    return "{0:00}s" -f $ts.Seconds
}

function Format-Speed([double]$BytesPerSec) {
    if ($BytesPerSec -le 0) { return "n/a" }
    if ($BytesPerSec -ge 1GB) { return ("{0:N2} GB/s" -f ($BytesPerSec / 1GB)) }
    if ($BytesPerSec -ge 1MB) { return ("{0:N2} MB/s" -f ($BytesPerSec / 1MB)) }
    if ($BytesPerSec -ge 1KB) { return ("{0:N2} KB/s" -f ($BytesPerSec / 1KB)) }
    return ("{0:N0} B/s" -f $BytesPerSec)
}

function Format-ETA([int64]$RemainingBytes, [double]$BytesPerSec) {
    if ($BytesPerSec -le 0 -or $RemainingBytes -le 0) { return "n/a" }
    $sec = [math]::Ceiling($RemainingBytes / $BytesPerSec)
    if ($sec -lt 0) { $sec = 0 }
    return (Format-Duration ([TimeSpan]::FromSeconds($sec)))
}

function Format-ProgressBar([double]$Percent, [int]$Width = 36) {
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    $filled = [int][math]::Round(($Percent / 100) * $Width)
    if ($filled -lt 0) { $filled = 0 }
    if ($filled -gt $Width) { $filled = $Width }
    return ("[" + ("#" * $filled) + ("-" * ($Width - $filled)) + "]")
}

function Show-Banner {
    Clear-Host
    Write-Host @"
============================================================
 SECURE S3 TRANSFER — UPLOAD TOOL
============================================================
"@ -ForegroundColor Red

    Write-Host ("Status      : READY") -ForegroundColor Green
    Write-Host ("Version     : {0}" -f $ToolVersion) -ForegroundColor Gray
    Write-Host ("Profile     : {0}" -f $AwsProfile) -ForegroundColor Gray
    Write-Host ("Region      : {0}" -f $AwsRegion) -ForegroundColor Gray
    Write-Host ("Bucket      : {0}" -f $BucketName) -ForegroundColor Gray
    Write-Host ("Upload Path : {0}" -f $KeyPrefix) -ForegroundColor Gray
    Write-Host ("Started     : {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -ForegroundColor Gray
    if ($EnableLog -and $script:LogFilePath) {
        Write-Host ("Log File    : {0}" -f $script:LogFilePath) -ForegroundColor Gray
    }
    Write-Host ("Connection  : {0}" -f ($(if ($UseTransferAcceleration) { "Optimized (Transfer Acceleration)" } else { "Standard" }))) -ForegroundColor Gray
    if ($EnableClientSideEncryption) {
        Write-Host "Security    : File is secured on this computer before upload" -ForegroundColor Gray
    } else {
        Write-Host "Security    : File is protected during upload and stored securely" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "What happens next:" -ForegroundColor Cyan
    Write-Host "  1) You select a file" -ForegroundColor Gray
    Write-Host "  2) We check it and secure it" -ForegroundColor Gray
    Write-Host "  3) We upload it safely" -ForegroundColor Gray
    Write-Host ""
}

function Wait-ForStart {
    if ($AutoStart) {
        Write-Host ""
        Write-Host "Status: IN PROGRESS" -ForegroundColor Green
        Write-Host ""
        return
    }
    $resp = Read-Host "Press ENTER to begin or type Q to quit"
    if ($resp -match '^(q|quit)$') { Write-Host "Exiting." -ForegroundColor Yellow; exit 0 }
    Write-Host ""
    Write-Host "Status: IN PROGRESS" -ForegroundColor Green
    Write-Host ""
}

function Invoke-DefenderScan {
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not $EnableDefenderScan) { return }

    Write-Host "Scanning the file with Windows Defender." -ForegroundColor Cyan
    Write-Log ("Defender scan started: {0}" -f $Path)

    $psExe = (Get-Command -Name "powershell.exe" -ErrorAction SilentlyContinue).Source
    if (-not $psExe) {
        Write-Host "Windows Defender scan is not available on this computer. Upload will continue without a scan." -ForegroundColor Yellow
        Write-Log "Defender scan unavailable (powershell.exe not found)."
        return
    }

    $pathEsc = Escape-PowerShellSingleQuote $Path
    $scanOut = Join-Path -Path $env:TEMP -ChildPath ("defender_scan_{0}.json" -f ([guid]::NewGuid().ToString("N")))
    $scanErr = Join-Path -Path $env:TEMP -ChildPath ("defender_scan_{0}.err" -f ([guid]::NewGuid().ToString("N")))
    $scanOutEsc = Escape-PowerShellSingleQuote $scanOut
    $scanErrEsc = Escape-PowerShellSingleQuote $scanErr

    $cmdTemplate = @'
try {
  Start-MpScan -ScanPath '__PATH__' -ErrorAction Stop
  $t = Get-MpThreatDetection | Where-Object { $_.Resources -contains '__PATH__' } | Select-Object ThreatName,Resources
  if ($t) { [System.IO.File]::WriteAllText('__OUT__', ($t | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8) }
  exit 0
} catch {
  [System.IO.File]::WriteAllText('__ERR__', ($_ | Out-String), [System.Text.Encoding]::UTF8)
  exit 2
}
'@
    $cmd = $cmdTemplate -replace "__PATH__", $pathEsc
    $cmd = $cmd -replace "__OUT__", $scanOutEsc
    $cmd = $cmd -replace "__ERR__", $scanErrEsc

    $pinfo = [System.Diagnostics.ProcessStartInfo]::new()
    $pinfo.FileName = $psExe
    $pinfo.RedirectStandardOutput = $false
    $pinfo.RedirectStandardError  = $false
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    [void]$pinfo.ArgumentList.Add("-NoProfile")
    [void]$pinfo.ArgumentList.Add("-Command")
    [void]$pinfo.ArgumentList.Add($cmd)

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $pinfo

    if (-not $proc.Start()) { throw "Security scan failed to start." }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $spin = @("|","/","-","\")
    $i = 0

    try {
        while (-not $proc.HasExited) {
            Start-Sleep -Milliseconds $DefenderScanPollMs
            $elapsed = Format-Duration $sw.Elapsed
            $line = ("{0} Scanning... Elapsed: {1}" -f $spin[$i % $spin.Length], $elapsed)
            Write-StatusLine $line
            Write-Progress -Activity "Scanning file (Windows Defender)" -Status $line
            $i++
        }

        Write-Progress -Activity "Scanning file (Windows Defender)" -Completed -Status "Done"
        Clear-StatusLine
        Write-Host ""
        $proc.WaitForExit()

        if ($proc.ExitCode -ne 0) {
            $msg = $null
            if (Test-Path -LiteralPath $scanErr) {
                $msg = (Get-Content -LiteralPath $scanErr -Raw -ErrorAction SilentlyContinue).Trim()
            }
            if (-not $msg) { $msg = "Windows Defender scan failed (exit code $($proc.ExitCode))." }
            Write-Log ("Defender scan failed: {0}" -f $msg)
            throw $msg
        }

        if (Test-Path -LiteralPath $scanOut) {
            $out = (Get-Content -LiteralPath $scanOut -Raw -ErrorAction SilentlyContinue).Trim()
        } else {
            $out = ""
        }
        if ($out) {
            $det = $out | ConvertFrom-Json
            $names = @()
            if ($det -is [System.Array]) {
                $names = $det | ForEach-Object { $_.ThreatName } | Where-Object { $_ } | Select-Object -Unique
            } else {
                if ($det.ThreatName) { $names = @($det.ThreatName) }
            }
            if ($names.Count -gt 0) {
                Write-Log ("Defender threats detected: {0}" -f ($names -join ", "))
                throw ("Security scan blocked the upload. Threat detected: {0}" -f ($names -join ", "))
            }
        }

        Write-Host "Security scan complete. No threats found." -ForegroundColor Green
        Write-Log "Defender scan complete. No threats found."
    }
    finally {
        try { if (-not $proc.HasExited) { $proc.Kill($true) | Out-Null } } catch {}
        $proc.Dispose()
        try { if (Test-Path -LiteralPath $scanOut) { Remove-Item -LiteralPath $scanOut -Force -ErrorAction SilentlyContinue } } catch {}
        try { if (Test-Path -LiteralPath $scanErr) { Remove-Item -LiteralPath $scanErr -Force -ErrorAction SilentlyContinue } } catch {}
    }
}

function Select-UploadFilePath {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "Select the file to upload"
    $dialog.Filter = "All files (*.*)|*.*"
    $dialog.Multiselect = $false

    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        $manual = Read-Host "File picker didn't open. Enter full path to file (or press ENTER to cancel)"
        if ([string]::IsNullOrWhiteSpace($manual)) { return $null }
        if (-not (Test-Path -LiteralPath $manual)) {
            Write-Host "File not found: $manual" -ForegroundColor Yellow
            return $null
        }
        return $manual
    }

    return $dialog.FileName
}

function Build-S3Uri([string]$Bucket, [string]$KeyPrefix, [string]$ObjectName) {
    return ("s3://{0}/{1}{2}" -f $Bucket, $KeyPrefix, $ObjectName)
}

function Wait-ForObjectVisible {
    param(
        [Parameter(Mandatory=$true)][string]$Bucket,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Profile,
        [int]$TimeoutSec = 180,
        [int]$PollSec = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $spin = @("|","/","-","\\")
    $i = 0
    while ((Get-Date) -lt $deadline) {
        $json = aws s3api list-objects-v2 --bucket $Bucket --prefix $Key --max-items 1 --profile $Profile --region $AwsRegion --output json 2>$null
        if ($LASTEXITCODE -eq 0 -and $json) {
            $obj = ($json | Out-String | ConvertFrom-Json)
            if ($obj.Contents -and $obj.Contents.Count -gt 0) {
                if ($obj.Contents[0].Key -eq $Key) { return $true }
            }
        }
        $elapsed = Format-Duration $sw.Elapsed
        $line = ("{0} Finalizing upload... Elapsed: {1}" -f $spin[$i % $spin.Length], $elapsed)
        Write-StatusLine $line
        $i++
        Start-Sleep -Seconds $PollSec
    }
    return $false
}

function Get-OpenMultipartUploadsForKey {
    param(
        [Parameter(Mandatory=$true)][string]$Bucket,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Profile
    )

    $json = aws s3api list-multipart-uploads --bucket $Bucket --prefix $Key --profile $Profile --region $AwsRegion --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $json) { return @() }
    $resp = ($json | Out-String | ConvertFrom-Json)
    if (-not $resp.Uploads) { return @() }
    return @($resp.Uploads | Where-Object { $_.Key -eq $Key })
}

# -------------------- AWS HELPERS --------------------
# Verifies the SSO session; kicks off login if the cached session is missing/expired.
function Ensure-SsoLogin([string]$Profile) {
    $null = aws sts get-caller-identity --profile $Profile 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Not logged in via SSO. Opening SSO login..." -ForegroundColor Yellow
        aws sso login --profile $Profile
        if ($LASTEXITCODE -ne 0) { throw "SSO login failed. Please try again." }
    }
}

# Checks whether the bucket has Transfer Acceleration enabled (read-only check).
function Ensure-TransferAccelerationConfigured([string]$Profile, [string]$Bucket) {
    if (-not $UseTransferAcceleration) {
        $script:AccelerationStatus = "disabled"
        return
    }

    # Avoid writing config here (profile/sso-session conflict risk on new machines).
    # Only check the bucket accelerate status for operator awareness.
    $cfgJson = aws s3api get-bucket-accelerate-configuration --bucket $Bucket --profile $Profile --region $AwsRegion --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $cfgJson) {
        $script:AccelerationStatus = "unverified"
        $warn = "Transfer Acceleration status could not be verified. Transfer will continue but may be slower. Please contact your system administrator if you expect optimized performance."
        Write-Host ("WARNING: {0}" -f $warn) -ForegroundColor Yellow
        Write-Log ("Acceleration check failed: {0}" -f $warn)
        return
    }
    $cfg = ($cfgJson | Out-String | ConvertFrom-Json)
    if ($cfg.Status -eq "Enabled") {
        $script:AccelerationStatus = "enabled"
        Write-Host "Acceleration: Enabled" -ForegroundColor Green
        Write-Host "Acceleration: Ready" -ForegroundColor Gray
    } else {
        $script:AccelerationStatus = "disabled"
        $warn = ("Transfer Acceleration is not enabled (Status={0}). Transfer will continue but may be slower. Please contact your system administrator if you expect optimized performance." -f $cfg.Status)
        Write-Host ("WARNING: {0}" -f $warn) -ForegroundColor Yellow
        Write-Log ("Acceleration not enabled: {0}" -f $warn)
    }
}

function Invoke-AwsS3CpSimple {
    param(
        [Parameter(Mandatory=$true)][string]$LocalPath,
        [Parameter(Mandatory=$true)][string]$DestUri,
        [Parameter(Mandatory=$true)][string]$Profile,
        [int]$ConnectTimeoutSec = 60,
        [int]$ReadTimeoutSec = 0,
        [string]$SseKmsKeyId = $null
    )

    $args = @(
        "s3","cp", $LocalPath, $DestUri,
        "--profile", $Profile,
        "--region", $AwsRegion,
        "--cli-connect-timeout", $ConnectTimeoutSec,
        "--cli-read-timeout", $ReadTimeoutSec
    )

    if (-not [string]::IsNullOrWhiteSpace($SseKmsKeyId)) {
        $args += @("--sse", "aws:kms", "--sse-kms-key-id", $SseKmsKeyId)
    }

    & aws @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Upload failed (aws s3 cp returned $LASTEXITCODE)." }
}

# -------------------- SLEEP PREVENTION --------------------
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PowerUtil {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint SetThreadExecutionState(uint esFlags);

    public const uint ES_CONTINUOUS       = 0x80000000;
    public const uint ES_SYSTEM_REQUIRED  = 0x00000001;
    public const uint ES_AWAYMODE_REQUIRED= 0x00000040;
}
"@

function Show-BatteryWarningIfNeeded {
    if ($AutoStart) { return }
    try {
        $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
        $isOnBattery = ($ps.PowerLineStatus -ne [System.Windows.Forms.PowerLineStatus]::Online)
        $pct = [math]::Round(($ps.BatteryLifePercent * 100), 0)
        if ($isOnBattery) {
            $msg = "WARNING: Running on battery ($pct%). Plug in power to avoid sleep/shutdown interrupting the upload."
            Write-Host $msg -ForegroundColor Yellow
            [void][System.Windows.Forms.MessageBox]::Show($msg, "Battery Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        }
    } catch {}
}

function Prevent-SystemSleep {
    [void][PowerUtil]::SetThreadExecutionState([PowerUtil]::ES_CONTINUOUS -bor [PowerUtil]::ES_SYSTEM_REQUIRED -bor [PowerUtil]::ES_AWAYMODE_REQUIRED)
}

function Restore-SystemSleepPolicy {
    [void][PowerUtil]::SetThreadExecutionState([PowerUtil]::ES_CONTINUOUS)
}

# -------------------- HASHING --------------------
# Computes a SHA-256 hash with a visible progress indicator so large files don't feel "stuck".
function Compute-Sha256WithProgress {
    param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][int64]$TotalBytes)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $bufferSize = 8MB
    $buffer = New-Object byte[] $bufferSize
    $outBuf = New-Object byte[] $bufferSize

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = $null
    $bytesReadTotal = 0L

    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        while (($read = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $null = $sha.TransformBlock($buffer, 0, $read, $outBuf, 0)
            $bytesReadTotal += $read

            $pct = if ($TotalBytes -gt 0) { [math]::Min(100, [math]::Round(($bytesReadTotal / [double]$TotalBytes) * 100, 1)) } else { 0 }
            $elapsed = $sw.Elapsed
            $bps = if ($elapsed.TotalSeconds -gt 0) { ($bytesReadTotal / $elapsed.TotalSeconds) } else { 0 }
            $eta = Format-ETA -RemainingBytes ($TotalBytes - $bytesReadTotal) -BytesPerSec $bps

            $status = ("{0}%  {1} / {2}   Read: {3}   ETA: {4}   Elapsed: {5}" -f $pct, (Format-Bytes $bytesReadTotal), (Format-Bytes $TotalBytes), (Format-Speed $bps), $eta, (Format-Duration $elapsed))
            Write-Progress -Activity "Hashing (SHA-256)" -Status $status -PercentComplete $pct
            Write-StatusLine $status
        }

        $null = $sha.TransformFinalBlock($buffer, 0, 0)
        Write-Progress -Activity "Hashing (SHA-256)" -Completed -Status "Done"
        Clear-StatusLine
        Write-Host ""
        return ([System.BitConverter]::ToString($sha.Hash) -replace "-", "").ToLowerInvariant()
    }
    finally {
        if ($fs) { $fs.Dispose() }
        if ($sha) { $sha.Dispose() }
    }
}

# -------------------- CSE (AES-GCM) --------------------
function New-RandomBytes([int]$Count) {
    $b = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return $b
}

function Get-KmsDataKey([string]$Profile,[string]$KeyId) {
    if ([string]::IsNullOrWhiteSpace($KeyId)) { throw "KmsKeyId is blank." }

    $json = aws kms generate-data-key --key-id $KeyId --key-spec AES_256 --profile $Profile --region $AwsRegion --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $json) { throw "Failed to generate data key via KMS. Check kms:GenerateDataKey permissions." }

    $obj = (($json | Out-String) | ConvertFrom-Json)
    if (-not $obj.Plaintext -or -not $obj.CiphertextBlob -or -not $obj.KeyId) {
        throw "KMS GenerateDataKey returned unexpected response."
    }

    return @{
        PlaintextBytes    = [Convert]::FromBase64String([string]$obj.Plaintext)
        CiphertextBlobB64 = [string]$obj.CiphertextBlob
        KeyId             = [string]$obj.KeyId
    }
}

# Encrypts the file locally using AES-256-GCM in chunks.
# This keeps memory use low and allows progress updates.
function Write-EncryptedFileAesGcmChunked {
    param(
        [Parameter(Mandatory=$true)][string]$InPath,
        [Parameter(Mandatory=$true)][string]$OutPath,
        [Parameter(Mandatory=$true)][byte[]]$KeyBytes,
        [Parameter(Mandatory=$true)][int]$ChunkSizeBytes,
        [Parameter(Mandatory=$true)][byte[]]$BaseNonce12
    )

    $MAGIC  = [System.Text.Encoding]::ASCII.GetBytes("CSECSE")
    $VER    = 1
    $TAGLEN = 16

    if ($BaseNonce12.Length -ne 12) { throw "Base nonce must be 12 bytes." }
    if ($KeyBytes.Length -ne 32)    { throw "AES-256-GCM requires a 32-byte key." }

    $fsIn  = $null
    $fsOut = $null
    $aes   = $null

    try {
        $fsIn  = [System.IO.File]::Open($InPath,  [System.IO.FileMode]::Open,   [System.IO.FileAccess]::Read,  [System.IO.FileShare]::Read)
        $fsOut = [System.IO.File]::Open($OutPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

        # Header: MAGIC(6) VER(1) CHSZ(4) NONCE(12)
        $fsOut.Write($MAGIC, 0, $MAGIC.Length)
        $fsOut.WriteByte([byte]$VER)
        $chBytes = [BitConverter]::GetBytes([UInt32]$ChunkSizeBytes)
        $fsOut.Write($chBytes, 0, $chBytes.Length)
        $fsOut.Write($BaseNonce12, 0, 12)

        $aes = [System.Security.Cryptography.AesGcm]::new($KeyBytes)

        $buffer = New-Object byte[] $ChunkSizeBytes
        $tag    = New-Object byte[] $TAGLEN

        $total = $fsIn.Length
        $done  = 0L
        $chunkIndex = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        while (($read = $fsIn.Read($buffer, 0, $buffer.Length)) -gt 0) {
            # Nonce = BaseNonce[0..7] + chunk counter in last 4 bytes
            $nonce = New-Object byte[] 12
            [Array]::Copy($BaseNonce12, 0, $nonce, 0, 12)
            $ctr = [BitConverter]::GetBytes([UInt32]$chunkIndex)
            [Array]::Copy($ctr, 0, $nonce, 8, 4)

            $pt = New-Object byte[] $read
            [Array]::Copy($buffer, 0, $pt, 0, $read)
            $ct = New-Object byte[] $read

            $aes.Encrypt($nonce, $pt, $ct, $tag, $null)

            $fsOut.Write($ct, 0, $ct.Length)
            $fsOut.Write($tag, 0, $tag.Length)

            $done += $read
            $chunkIndex++

            $pct = [math]::Min(100, [math]::Round(($done / [double]$total) * 100, 1))
            $elapsed = $sw.Elapsed
            $bps = if ($elapsed.TotalSeconds -gt 0) { ($done / $elapsed.TotalSeconds) } else { 0 }
            $eta = Format-ETA -RemainingBytes ($total - $done) -BytesPerSec $bps

            $status = ("{0}%  {1} / {2}   Encrypt: {3}   ETA: {4}   Elapsed: {5}" -f $pct, (Format-Bytes $done), (Format-Bytes $total), (Format-Speed $bps), $eta, (Format-Duration $elapsed))
            Write-Progress -Activity "Encrypting (AES-256-GCM)" -Status $status -PercentComplete $pct
            Write-StatusLine $status
        }

        Write-Progress -Activity "Encrypting (AES-256-GCM)" -Completed -Status "Done"
        Clear-StatusLine
        Write-Host ""
    }
    finally {
        if ($aes)   { $aes.Dispose() }
        if ($fsIn)  { $fsIn.Dispose() }
        if ($fsOut) { $fsOut.Dispose() }
    }
}

function New-CseManifestJson {
    param(
        [Parameter(Mandatory=$true)][string]$OriginalFileName,
        [Parameter(Mandatory=$true)][int64]$OriginalSize,
        [Parameter(Mandatory=$true)][string]$KmsKeyIdUsed,
        [Parameter(Mandatory=$true)][string]$EncryptedDataKeyB64,
        [Parameter(Mandatory=$true)][string]$BaseNonceB64,
        [Parameter(Mandatory=$true)][int]$ChunkSizeBytes
    )

    $manifest = [ordered]@{
        schema            = "secure-cse"
        schemaVersion     = 1
        cipherFormat      = "CSECSE"
        cipherFormatVer   = "1"
        algorithm         = "AES-256-GCM"
        chunkSizeBytes    = $ChunkSizeBytes
        kmsKeyId          = $KmsKeyIdUsed
        encryptedDataKey  = $EncryptedDataKeyB64
        baseNonce         = $BaseNonceB64
        originalFileName  = $OriginalFileName
        originalSizeBytes = $OriginalSize
        createdUtc        = ([DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"))
    }
    return ($manifest | ConvertTo-Json -Depth 6)
}

# -------------------- UPLOAD PROGRESS (REAL + VISIBLE) --------------------
# Wraps `aws s3 cp` and drives a progress UI by sampling process IO counters.
function Invoke-AwsS3CpWithProgress {
    param(
        [Parameter(Mandatory=$true)][string]$LocalPath,
        [Parameter(Mandatory=$true)][string]$DestUri,
        [Parameter(Mandatory=$true)][string]$Profile,
        [Parameter(Mandatory=$true)][int64]$TotalBytes,
        [int]$ConnectTimeoutSec = 60,
        [int]$ReadTimeoutSec = 0,
        [switch]$EnableChecksum,
        [string]$ChecksumAlgorithm = "SHA256",
        [bool]$SuppressAwsCliProgress = $true,
        [string]$SseKmsKeyId = $null
    )

    if (-not (Test-Path -LiteralPath $LocalPath)) { throw "Local path missing: $LocalPath" }

    Write-Log ("Upload started: {0} -> {1}" -f $LocalPath, $DestUri)

    # Build aws args
    $args = @(
        "s3","cp", $LocalPath, $DestUri,
        "--profile", $Profile,
        "--region", $AwsRegion,
        "--cli-connect-timeout", $ConnectTimeoutSec,
        "--cli-read-timeout", $ReadTimeoutSec
    )

    if ($SuppressAwsCliProgress) {
        $args += "--no-progress"
    }

    if ($EnableChecksum) {
        $args += @("--checksum-algorithm", $ChecksumAlgorithm)
    }

    if (-not [string]::IsNullOrWhiteSpace($SseKmsKeyId)) {
        $args += @("--sse", "aws:kms", "--sse-kms-key-id", $SseKmsKeyId)
    }

    # Process IO counters (bytes read by aws process)
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class IoCounters {
  [StructLayout(LayoutKind.Sequential)]
  public struct IO_COUNTERS {
    public ulong ReadOperationCount;
    public ulong WriteOperationCount;
    public ulong OtherOperationCount;
    public ulong ReadTransferCount;
    public ulong WriteTransferCount;
    public ulong OtherTransferCount;
  }

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);
}
"@ -ErrorAction SilentlyContinue | Out-Null

    $pinfo = [System.Diagnostics.ProcessStartInfo]::new()
    $pinfo.FileName = "aws"
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError  = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    foreach ($a in $args) { [void]$pinfo.ArgumentList.Add([string]$a) }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $pinfo

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $prevDone = 0L
    $prevTick = [DateTime]::UtcNow

    if (-not $proc.Start()) { throw "Failed to start aws process." }

    try {
        while (-not $proc.HasExited) {
            Start-Sleep -Milliseconds $UploadProgressSampleMs

            $done = $prevDone
            $c = New-Object IoCounters+IO_COUNTERS
            $ok = $false
            try { $ok = [IoCounters]::GetProcessIoCounters($proc.Handle, [ref]$c) } catch { $ok = $false }

            if ($ok) {
                $readBytes = [int64]$c.ReadTransferCount
                if ($readBytes -lt 0) { $readBytes = 0 }
                $done = [int64][math]::Min([double]$TotalBytes, [double]$readBytes)
                if ($done -lt $prevDone) { $done = $prevDone }
            }

            $now = [DateTime]::UtcNow
            $dt = ($now - $prevTick).TotalSeconds
            if ($dt -le 0) { $dt = 0.001 }

            $delta = $done - $prevDone
            if ($delta -lt 0) { $delta = 0 }

            $instBps = $delta / $dt
            $avgBps  = if ($sw.Elapsed.TotalSeconds -gt 0) { $done / $sw.Elapsed.TotalSeconds } else { 0 }

            $pct = if ($TotalBytes -gt 0) { [math]::Min(100, [math]::Round(($done / [double]$TotalBytes) * 100, 1)) } else { 0 }
            $eta = Format-ETA -RemainingBytes ($TotalBytes - $done) -BytesPerSec $avgBps

            $bar = Format-ProgressBar -Percent $pct
            $status = ("{0} {1}%  {2} / {3}   Avg: {4}   Now: {5}   ETA: {6}   Elapsed: {7}" -f
                $bar,
                $pct,
                (Format-Bytes $done),
                (Format-Bytes $TotalBytes),
                (Format-Speed $avgBps),
                (Format-Speed $instBps),
                $eta,
                (Format-Duration $sw.Elapsed)
            )

            # Always visible
            Write-StatusLine $status

            $prevDone = $done
            $prevTick = $now
        }

        Clear-StatusLine
        Write-Host ""
        $proc.WaitForExit()

        if ($proc.ExitCode -ne 0) {
            $errText = $proc.StandardError.ReadToEnd().Trim()
            $outText = $proc.StandardOutput.ReadToEnd().Trim()
            $msg = $errText
            if (-not $msg) { $msg = $outText }
            if (-not $msg) { $msg = "aws s3 cp failed with exit code $($proc.ExitCode)." }
            Write-Log ("Upload failed: {0}" -f $msg)
            throw $msg
        }

        $finalAvg = if ($sw.Elapsed.TotalSeconds -gt 0) { $TotalBytes / $sw.Elapsed.TotalSeconds } else { 0 }
        Write-Host ("Upload stream complete. Avg: {0}   Elapsed: {1}" -f (Format-Speed $finalAvg), (Format-Duration $sw.Elapsed)) -ForegroundColor Green
        Write-Log ("Upload completed: {0}" -f $DestUri)
    }
    finally {
        try { if (-not $proc.HasExited) { $proc.Kill($true) | Out-Null } } catch {}
        $proc.Dispose()
    }
}

# -------------------- RUN SUMMARY --------------------
# Captures a human-friendly summary that can be handed to support.
$runStatus = "NOT_STARTED"
$runError  = $null

$scriptStart = $null
$scanStart   = $null
$scanEnd     = $null
$hashStart   = $null
$hashEnd     = $null
$uploadStart = $null
$uploadEnd   = $null

$filePath = $null
$destUri  = $null
$shaUri   = $null
$cseManifestUri = $null

$bytesTotal = 0L
$bytesDone  = 0L
$SleepBlocked = $false

$uploadPath = $null
$tempEncPath = $null
$tempManifestPath = $null
$script:LastStepStart = $null
$script:LastStepTitle = $null

function Write-RunSummary {
    param([string]$Status,[string]$ErrorMessage)

    $endTime = Get-Date
    $totalElapsed = if ($scriptStart) { $endTime - $scriptStart } else { [TimeSpan]::Zero }

    $statusColor = if ($Status -eq "SUCCESS") { "Green" } elseif ($Status -eq "FAILED") { "Red" } else { "Yellow" }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host ("UPLOAD SUMMARY  [{0}]" -f $Status) -ForegroundColor $statusColor
    Write-Host "============================================================" -ForegroundColor DarkGray
    if ($filePath) { Write-Host ("File     : {0}" -f $filePath) -ForegroundColor Gray }
    if ($bytesTotal -gt 0) { Write-Host ("Size     : {0}" -f (Format-Bytes $bytesTotal)) -ForegroundColor Gray }
    if ($destUri) { Write-Host ("Dest     : {0}" -f $destUri) -ForegroundColor Gray }
    Write-Host ("Duration : {0}" -f (Format-Duration $totalElapsed)) -ForegroundColor Gray
    if ($EnableLog -and $script:LogFilePath) { Write-Host ("Log File : {0}" -f $script:LogFilePath) -ForegroundColor Gray }

    if ($Status -eq "SUCCESS") {
        Write-Host ""
        Write-Host "Status  : COMPLETE" -ForegroundColor Green
        Write-Host "Next    : You can close this window." -ForegroundColor Green
    }

    if ($Status -eq "FAILED" -and $ErrorMessage) {
        Write-Host ""
        Write-Host "Status  : ACTION REQUIRED" -ForegroundColor Yellow
        Write-Host "Reason  : Upload did not complete." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Technical details (send to your system administrator):" -ForegroundColor DarkGray
        Write-Host $ErrorMessage -ForegroundColor DarkGray
    }
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host ""
}

# -------------------- MAIN --------------------
# High-level flow:
# 1) Pick a file and (optionally) scan it
# 2) Hash the original for integrity tracking
# 3) Encrypt locally (optional)
# 4) Upload ciphertext + manifest + hash
try {
    $scriptStart = Get-Date
    $runStatus = "RUNNING"

    Initialize-Log
    Write-Log ("Version: {0}" -f $ToolVersion)
    Write-Log ("Profile: {0}" -f $AwsProfile)
    Write-Log ("Bucket: {0}" -f $BucketName)
    Write-Log ("Prefix: {0}" -f $KeyPrefix)
    Write-Log ("Region: {0}" -f $AwsRegion)

    Initialize-ProgressUi
    Show-Banner
    Wait-ForStart

    $script:StepIndex = 0
    $script:StepTotal = 7
    if ($EnableDefenderScan) { $script:StepTotal++ }
    if ($EnableClientSideEncryption) { $script:StepTotal += 2 }

    Start-Step -Title "Pre-flight checks" -Description "Confirming access and readiness."
    Ensure-SsoLogin -Profile $AwsProfile
    Ensure-TransferAccelerationConfigured -Profile $AwsProfile -Bucket $BucketName
    Show-BatteryWarningIfNeeded
    Write-Host "Checklist:" -ForegroundColor Cyan
    Write-Host "  [OK] Signed in" -ForegroundColor Green
    Write-Host "  [OK] Destination ready" -ForegroundColor Green
    switch ($script:AccelerationStatus) {
        "enabled"   { Write-Host "  [OK] Network optimized (transfer acceleration enabled)" -ForegroundColor Green }
        "disabled"  { Write-Host "  [WARN] Network not optimized (transfer acceleration disabled)" -ForegroundColor Yellow }
        "unverified"{ Write-Host "  [WARN] Network not optimized (transfer acceleration not verified)" -ForegroundColor Yellow }
        default     { Write-Host "  [INFO] Network optimization status unknown" -ForegroundColor Gray }
    }
    Write-Host ""

    Start-Step -Title "Choose a file" -Description "Select the file you want to upload."
    if (-not [string]::IsNullOrWhiteSpace($InputFilePath)) {
        $filePath = $InputFilePath
    } else {
        $filePath = Select-UploadFilePath
    }
    if (-not $filePath) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        $runStatus = "CANCELLED"
        return
    }

    if (-not (Test-Path -LiteralPath $filePath)) { throw "Selected file does not exist: $filePath" }

    Prevent-SystemSleep
    $SleepBlocked = $true

    if ($EnableDefenderScan) {
        Start-Step -Title "Security scan" -Description "Checking the file before upload."
        $scanStart = Get-Date
        Invoke-DefenderScan -Path $filePath
        $scanEnd = Get-Date
    }

    $zipName = [System.IO.Path]::GetFileName($filePath)
    $fileInfo  = Get-Item -LiteralPath $filePath -ErrorAction Stop
    $origBytes = [int64]$fileInfo.Length
    Write-Log ("Selected file: {0} ({1})" -f $filePath, (Format-Bytes $origBytes))

    Write-Host ""
    Write-Host "File selected:" -ForegroundColor Cyan
    Write-Host ("  Name : {0}" -f $zipName) -ForegroundColor Gray
    Write-Host ("  Size : {0}" -f (Format-Bytes $origBytes)) -ForegroundColor Gray
    Write-Host ""

    # Hash original file to provide an integrity check independent of encryption.
    Start-Step -Title "Integrity check" -Description "Creating a verification hash."
    $hashStart = Get-Date
    Write-Host "Creating a small integrity file to confirm the upload is correct." -ForegroundColor Cyan
    $sha256 = Compute-Sha256WithProgress -Path $filePath -TotalBytes $origBytes
    Write-Host ("SHA-256: {0}" -f $sha256) -ForegroundColor Green
    $hashEnd = Get-Date

    $shaLocalPath = Join-Path -Path ([System.IO.Path]::GetDirectoryName($filePath)) -ChildPath ($zipName + ".sha256")
    [System.IO.File]::WriteAllText($shaLocalPath, ("{0}  {1}" -f $sha256, $zipName), [System.Text.Encoding]::ASCII)
    Write-Host ("Saved hash file: {0}" -f $shaLocalPath) -ForegroundColor Gray

    # Client-side encryption ensures plaintext never reaches S3.
    $uploadPath = $filePath
    $payloadNameForS3 = $zipName
    $bytesTotal = $origBytes

    if ($EnableClientSideEncryption) {
    Start-Step -Title "Securing the file" -Description "Protecting the file before upload."
    Write-Host "Securing the file on this computer." -ForegroundColor Cyan
    Write-Log "Local file protection enabled."

        $dk = Get-KmsDataKey -Profile $AwsProfile -KeyId $KmsKeyId
        $plaintextKey = [byte[]]$dk.PlaintextBytes

        try {
            $tempEncPath = Join-Path -Path ([System.IO.Path]::GetDirectoryName($filePath)) -ChildPath ($zipName + ".enc")

            $baseNonce = New-RandomBytes -Count 12
            $baseNonceB64 = [Convert]::ToBase64String($baseNonce)

            Write-EncryptedFileAesGcmChunked -InPath $filePath -OutPath $tempEncPath -KeyBytes $plaintextKey -ChunkSizeBytes ([int]$CseChunkSizeBytes) -BaseNonce12 $baseNonce

            $tempManifestPath = Join-Path -Path ([System.IO.Path]::GetDirectoryName($filePath)) -ChildPath ($zipName + $CseManifestSuffix)
            $manifestJson = New-CseManifestJson -OriginalFileName $zipName -OriginalSize $origBytes -KmsKeyIdUsed $dk.KeyId -EncryptedDataKeyB64 $dk.CiphertextBlobB64 -BaseNonceB64 $baseNonceB64 -ChunkSizeBytes ([int]$CseChunkSizeBytes)
            [System.IO.File]::WriteAllText($tempManifestPath, $manifestJson, [System.Text.Encoding]::UTF8)

            Write-Host ("Encrypted file created: {0}" -f $tempEncPath) -ForegroundColor Green
            Write-Host ("Security manifest created: {0}" -f $tempManifestPath) -ForegroundColor Green

            $uploadPath = $tempEncPath
            $encInfo = Get-Item -LiteralPath $uploadPath -ErrorAction Stop
            $bytesTotal = [int64]$encInfo.Length

            if ($StoreCiphertextWithEncExtension) {
                $payloadNameForS3 = $zipName + $CiphertextExtension
            } else {
                $payloadNameForS3 = $zipName
            }

            Write-Host ("Upload payload size (ciphertext): {0}" -f (Format-Bytes $bytesTotal)) -ForegroundColor Gray
        }
        finally {
            if ($plaintextKey) { [Array]::Clear($plaintextKey, 0, $plaintextKey.Length) }
        }
    }

    # Build S3 URI
    $destUri = Build-S3Uri -Bucket $BucketName -KeyPrefix $KeyPrefix -ObjectName $payloadNameForS3
    Write-Log ("Destination: {0}" -f $destUri)

    Write-Host ("  Dest: {0}" -f $destUri) -ForegroundColor Gray
    Write-Host ""

    Write-Host "---------------------------------------------------" -ForegroundColor Red
    Write-Host "---UPLOAD IN PROGRESS - DO NOT CLOSE THIS WINDOW---" -ForegroundColor Red
    Write-Host "--------Closing it WILL cancel the upload----------" -ForegroundColor Red
    Write-Host "---------------------------------------------------" -ForegroundColor Red
    Write-Host ""

    # Upload payload with progress
    Start-Step -Title "Uploading file" -Description "Sending the encrypted file to the secure bucket."
    $connectTimeout = 60
    $readTimeout    = 0

    $uploadStart = Get-Date
    Invoke-AwsS3CpWithProgress -LocalPath $uploadPath -DestUri $destUri -Profile $AwsProfile -TotalBytes $bytesTotal `
        -ConnectTimeoutSec $connectTimeout -ReadTimeoutSec $readTimeout `
        -EnableChecksum:($EnableUploadChecksum) -ChecksumAlgorithm $UploadChecksumAlgorithm `
        -SuppressAwsCliProgress:$true -SseKmsKeyId $KmsKeyId
    $uploadEnd = Get-Date
    $bytesDone = $bytesTotal

    # Finalize check: confirm object is visible in the bucket without requiring read access.
    Start-Step -Title "Finalizing upload" -Description "Confirming the upload completed on the server."
    $uploadKey = $KeyPrefix + $payloadNameForS3
    $visible = Wait-ForObjectVisible -Bucket $BucketName -Key $uploadKey -Profile $AwsProfile -TimeoutSec $FinalizeTimeoutSec -PollSec $FinalizePollSec
    if (-not $visible) {
        $open = Get-OpenMultipartUploadsForKey -Bucket $BucketName -Key $uploadKey -Profile $AwsProfile
        if ($open.Count -gt 0) {
            throw "Upload reached 100% locally but was not finalized on S3 (open multipart upload still exists). Please retry."
        }
        throw "Upload reached 100% locally but the object is not visible in S3 yet. Please retry."
    }
    Clear-StatusLine
    Write-Host "Upload finished and verified." -ForegroundColor Green

    # Upload manifest (encrypted data key + metadata) so downloaders can decrypt.
    if ($EnableClientSideEncryption -and $tempManifestPath -and (Test-Path -LiteralPath $tempManifestPath)) {
        Start-Step -Title "Uploading security details" -Description "Saving information needed to decrypt later."
        $manifestName = "$zipName$CseManifestSuffix"
        $cseManifestUri = Build-S3Uri -Bucket $BucketName -KeyPrefix $ArtefactsPrefix -ObjectName $manifestName
        Write-Log ("Uploading security manifest: {0}" -f $cseManifestUri)
        Invoke-AwsS3CpSimple -LocalPath $tempManifestPath -DestUri $cseManifestUri -Profile $AwsProfile -ConnectTimeoutSec $connectTimeout -ReadTimeoutSec $readTimeout -SseKmsKeyId $KmsKeyId
        Write-Host "Security manifest uploaded." -ForegroundColor Green
        Write-Log "Security manifest uploaded."
    }

    # Upload hash so downloaders can verify integrity before decrypting.
    Start-Step -Title "Uploading integrity file" -Description "Uploading the hash for verification."
    $shaName = "$zipName.sha256"
    $shaUri  = Build-S3Uri -Bucket $BucketName -KeyPrefix $ArtefactsPrefix -ObjectName $shaName
    Write-Log ("Uploading integrity file: {0}" -f $shaUri)
    Invoke-AwsS3CpSimple -LocalPath $shaLocalPath -DestUri $shaUri -Profile $AwsProfile -ConnectTimeoutSec $connectTimeout -ReadTimeoutSec $readTimeout -SseKmsKeyId $KmsKeyId
    Write-Host "Integrity file uploaded." -ForegroundColor Green
    Write-Log "Integrity file uploaded."

    # Verification - intentionally skipped (write-only uploaders)
    Start-Step -Title "Wrap up" -Description "Completing system checks."
    Write-Host "Final checks completed." -ForegroundColor Gray
    if ($EnableUploadChecksum) {
        Write-Host ("Upload integrity validation: Enabled ({0})." -f $UploadChecksumAlgorithm) -ForegroundColor Gray
    }
    Write-Host ""

    Write-Host "Upload complete." -ForegroundColor Green
    Write-Host ("Destination : {0}" -f $destUri) -ForegroundColor Cyan
    Write-Host ("Integrity   : {0}" -f $shaUri) -ForegroundColor Cyan
    if ($EnableClientSideEncryption -and $cseManifestUri) { Write-Host ("Security    : {0}" -f $cseManifestUri) -ForegroundColor Cyan }
    Write-Host ""

    $runStatus = "SUCCESS"
    Write-Log "Run completed successfully."
}
catch {
    $runStatus = "FAILED"
    $runError  = $_.Exception.Message
    Write-Log ("Run failed: {0}" -f $runError)
    Write-Host ""
    Write-Host "Upload failed." -ForegroundColor Red
    Write-Host "What you can do next:" -ForegroundColor Yellow
    Write-Host "  1) Check your internet connection" -ForegroundColor Yellow
    Write-Host "  2) Retry the upload" -ForegroundColor Yellow
    Write-Host "  3) If it keeps failing, contact your system administrator" -ForegroundColor Yellow
    Write-Host "Note: If it reached 100% then failed, the upload did not finalize on the server." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Technical details (send to your system administrator):" -ForegroundColor DarkGray
    Write-Host $runError -ForegroundColor DarkGray
    if ($EnableLog -and $script:LogFilePath) {
        Write-Host ("Support log saved to: {0}" -f $script:LogFilePath) -ForegroundColor DarkGray
    }
}
finally {
    if ($SleepBlocked) { Restore-SystemSleepPolicy }

    # Cleanup temp encryption artifacts only
    try {
        if ($EnableClientSideEncryption -and $tempEncPath -and (Test-Path -LiteralPath $tempEncPath)) {
            Remove-Item -LiteralPath $tempEncPath -Force -ErrorAction SilentlyContinue
        }
        if ($EnableClientSideEncryption -and $tempManifestPath -and (Test-Path -LiteralPath $tempManifestPath)) {
            Remove-Item -LiteralPath $tempManifestPath -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    Write-RunSummary -Status $runStatus -ErrorMessage $runError
    Write-Log ("Run status: {0}" -f $runStatus)

    if (-not $AutoStart) {
        Write-Host ""
        Write-Host "Press Enter to close..."
        [void][System.Console]::ReadLine()
    }
}
