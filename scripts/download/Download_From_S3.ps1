<#
Purpose:
  Secure download client for the Secure S3 Transfer system. Downloads encrypted
  payloads and artefacts, verifies integrity, decrypts locally, then archives
  verified objects to the downloaded/ prefix.

When to use:
  - Daily downloader operations after setup-client.ps1 is complete
  - Controlled verification of incoming files

Prerequisites:
  - PowerShell 7
  - AWS CLI v2
  - Valid SSO profile with downloader permissions
  - config.download.json (see scripts/config/config.download.example.json)

Inputs:
  - config.download.json
  - DestinationPath (optional; GUI prompt otherwise)

Outputs / changes:
  - Decrypted files in local destination
  - Archived objects moved to downloaded/
  - Local logs in %USERPROFILE%\Documents\SecureDownloadLogs

Logs:
  - %USERPROFILE%\Documents\SecureDownloadLogs\DownloadLog_*.log

Common failure causes:
  - KMS Decrypt denied (key policy or IAM policy)
  - Missing manifests / hash files in artefacts prefix
  - Bucket policy denies delete during archive move
  - SSO profile not logged in

Usage:
  pwsh -File scripts\download\Download_From_S3.ps1 -DestinationPath C:\Downloads -AutoStart

Maintainer notes:
  - Archive uses s3 mv (copy + delete). If delete is denied, files remain in incoming/.
  - Manifest format must match Upload_To_S3.ps1.
  - Keep prefixes aligned with bucket policy and Terraform variables.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\config\config.download.json"),
    [string]$DestinationPath = $null,
    [switch]$AutoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms

# Window title to discourage closing
$host.UI.RawUI.WindowTitle = "SECURE DOWNLOAD - DO NOT CLOSE THIS WINDOW"

function Load-ConfigFile {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Config file not found: $fullPath. Copy scripts/config/config.download.example.json to scripts/config/config.download.json and edit."
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

$ToolVersion = "v1.2.0-PS7-CSE"

# Config is stored in JSON so each environment can supply its own settings safely
# without modifying the script or committing secrets.
$cfg = Load-ConfigFile -Path $ConfigPath

$AwsProfile     = Get-ConfigValue -Config $cfg -Name "aws_profile" -Required
$AwsRegion      = Get-ConfigValue -Config $cfg -Name "aws_region" -Required
$BucketName     = Get-ConfigValue -Config $cfg -Name "bucket_name" -Required
# Download performance (favor reliability for large files).
$UseTransferAcceleration = $true
$MultipartChunkSize = "256MB"
$MaxConcurrentRequests = "10"
# Download from incoming/ and archive into downloaded/ after verification to avoid
# destructive reads and to maintain an auditable record of downloads.
$IncomingPrefix = Normalize-Prefix -Prefix (Get-ConfigValue -Config $cfg -Name "incoming_prefix" -Required) -Name "incoming_prefix"
$ArtefactsPrefix = Normalize-Prefix -Prefix (Get-ConfigValue -Config $cfg -Name "artefacts_prefix" -Required) -Name "artefacts_prefix"
$DonePrefix     = Normalize-Prefix -Prefix (Get-ConfigValue -Config $cfg -Name "downloaded_prefix" -Required) -Name "downloaded_prefix"
$KmsKeyId       = Get-ConfigValue -Config $cfg -Name "kms_key_id" -Default $null

$CseManifestSuffix = Get-ConfigValue -Config $cfg -Name "cse_manifest_suffix" -Default ".cse.manifest.json"
$CiphertextExtension = Get-ConfigValue -Config $cfg -Name "ciphertext_extension" -Default ".enc"

# Client-side decryption is required for secure downloads.
$EnableClientSideDecryption = $true

# Artefacts are stored under incoming/artefacts/; compute relative prefix for lookups.
if (-not $ArtefactsPrefix.StartsWith($IncomingPrefix)) {
    throw "artefacts_prefix must be under incoming_prefix (e.g., incoming/artefacts/)."
}
$ArtefactsRelPrefix = $ArtefactsPrefix.Substring($IncomingPrefix.Length)
if (-not $ArtefactsRelPrefix.EndsWith("/")) { $ArtefactsRelPrefix += "/" }

$EnableLog = [bool](Get-ConfigValue -Config $cfg -Name "enable_log" -Default $true)
$LogDirectory = Get-ConfigValue -Config $cfg -Name "download_log_directory" -Default (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecureDownloadLogs")
$LogDirectory = [Environment]::ExpandEnvironmentVariables([string]$LogDirectory)
$script:LogFilePath = $null
$script:LocalDecrypted = $null

if ([string]::IsNullOrWhiteSpace($KmsKeyId)) {
    # Archive moves require SSE-KMS; bucket policy will deny if key is missing.
    throw "Config 'kms_key_id' is required because the bucket policy enforces SSE-KMS on archive moves."
}

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

if ($EnableClientSideDecryption -and -not (Test-AesGcmAvailable)) {
    throw "AesGcm is not usable in this runtime. Update PowerShell/.NET or disable client-side decryption."
}

function Write-Log {
    param([string]$Message)
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
    $script:LogFilePath = Join-Path -Path $LogDirectory -ChildPath ("DownloadLog_{0}.log" -f $stamp)
    Write-Log "Log started."
}

function Write-Phase {
    param([string]$Name)
    if ($script:LastPhaseStart) {
        $elapsed = (Get-Date) - $script:LastPhaseStart
        if ($script:LastPhaseName) {
            Write-Host ("  Completed: {0} in {1}" -f $script:LastPhaseName, (Format-Duration $elapsed)) -ForegroundColor DarkGray
        } else {
            Write-Host ("  Step time: {0}" -f (Format-Duration $elapsed)) -ForegroundColor DarkGray
        }
    }
    $script:LastPhaseStart = Get-Date
    $script:LastPhaseName = $Name
    $script:PhaseIndex++
    Write-Host ""
    Write-Host "====================" -ForegroundColor DarkGray
    if ($script:PhaseTotal -gt 0) {
        Write-Host ("STEP {0}/{1}: {2}" -f $script:PhaseIndex, $script:PhaseTotal, $Name) -ForegroundColor Cyan
    } else {
        Write-Host ("STEP: {0}" -f $Name) -ForegroundColor Cyan
    }
    Write-Host "====================" -ForegroundColor DarkGray
    Write-Host ""
}

function Format-Bytes {
    param([Int64]$Bytes)
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Format-Duration {
    param([TimeSpan]$ts)
    if ($ts.TotalHours -ge 1) {
        return "{0:00}h {1:00}m {2:00}s" -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds
    } elseif ($ts.TotalMinutes -ge 1) {
        return "{0:00}m {1:00}s" -f $ts.Minutes, $ts.Seconds
    } else {
        return "{0:00}s" -f $ts.Seconds
    }
}

function Format-Speed {
    param([double]$BytesPerSec)
    if ($BytesPerSec -le 0) { return "n/a" }
    if ($BytesPerSec -ge 1GB) { return ("{0:N2} GB/s" -f ($BytesPerSec / 1GB)) }
    if ($BytesPerSec -ge 1MB) { return ("{0:N2} MB/s" -f ($BytesPerSec / 1MB)) }
    if ($BytesPerSec -ge 1KB) { return ("{0:N2} KB/s" -f ($BytesPerSec / 1KB)) }
    return ("{0:N0} B/s" -f $BytesPerSec)
}

function Format-ProgressBar {
    param([double]$Percent, [int]$Width = 36)
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    $filled = [int][math]::Round(($Percent / 100) * $Width)
    if ($filled -lt 0) { $filled = 0 }
    if ($filled -gt $Width) { $filled = $Width }
    return ("[" + ("#" * $filled) + ("-" * ($Width - $filled)) + "]")
}

# Verifies the SSO session; triggers login if needed to avoid silent access failures.
function Ensure-SsoLogin {
    param([string]$Profile)

    $null = aws sts get-caller-identity --profile $Profile 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Not logged in via SSO. Opening SSO login..." -ForegroundColor Yellow
        aws sso login --profile $Profile
        if ($LASTEXITCODE -ne 0) {
            throw "SSO login failed. Please try again or contact support."
        }
    }
}

function Configure-HighSpeedTransfer {
    param([string]$Profile)

    # Apply high-speed S3 transfer settings for this profile; helps on high-latency links.
    aws configure set "profile.$Profile.s3.multipart_chunksize" $MultipartChunkSize | Out-Null
    aws configure set "profile.$Profile.s3.max_concurrent_requests" $MaxConcurrentRequests | Out-Null
    aws configure set "profile.$Profile.max_attempts" "10" | Out-Null
    aws configure set "profile.$Profile.retry_mode" "adaptive" | Out-Null
    aws configure set "profile.$Profile.s3.use_accelerate_endpoint" "true" | Out-Null
}

function Ensure-TransferAccelerationConfigured {
    param([string]$Profile,[string]$Bucket)
    if (-not $UseTransferAcceleration) { return }

    # Fail early if the bucket does not support acceleration; avoids confusing performance issues.
    $cfgJson = aws s3api get-bucket-accelerate-configuration --bucket $Bucket --profile $Profile --region $AwsRegion --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $cfgJson) {
        Write-Host "WARNING: Transfer Acceleration is required but the bucket acceleration status could not be read." -ForegroundColor Yellow
        Write-Host "WARNING: Continuing anyway; download may fail if acceleration is not enabled." -ForegroundColor Yellow
        return
    }
    $cfg = ($cfgJson | Out-String | ConvertFrom-Json)
    if ($cfg.Status -ne "Enabled") {
        Write-Host ("WARNING: Transfer Acceleration is required but the bucket is not enabled (Status={0})." -f $cfg.Status) -ForegroundColor Yellow
        Write-Host "WARNING: Continuing anyway; download may fail." -ForegroundColor Yellow
        return
    }
}

function Select-DownloadDestination {
    param([string]$DefaultPath)

    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Select where downloaded files should be saved"
    $dlg.ShowNewFolderButton = $true

    if ($DefaultPath -and (Test-Path -LiteralPath $DefaultPath)) {
        $dlg.SelectedPath = $DefaultPath
    }

    $result = $dlg.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($dlg.SelectedPath)) {
        return $null
    }

    return $dlg.SelectedPath
}

function Show-Banner {
    param([string]$DestIncoming)

    Clear-Host

    Write-Host @"
============================================================
 SECURE S3 TRANSFER — DOWNLOAD TOOL
============================================================
"@ -ForegroundColor Red

    $destText = if ($DestIncoming) { $DestIncoming } else { "<not selected>" }

    Write-Host ("Version     : {0}" -f $ToolVersion) -ForegroundColor Gray
    Write-Host ("Storage     : {0}" -f $BucketName) -ForegroundColor Gray
    Write-Host ("Folder      : {0}" -f $IncomingPrefix) -ForegroundColor Gray
    Write-Host ("Destination : {0}" -f $destText) -ForegroundColor Gray
    if ($EnableClientSideDecryption -and $script:LocalDecrypted) {
        Write-Host ("Prepared    : {0}" -f $script:LocalDecrypted) -ForegroundColor Gray
    }
    Write-Host ("Profile     : {0}" -f $AwsProfile) -ForegroundColor Gray
    Write-Host ("Started     : {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -ForegroundColor Gray
    if ($EnableLog -and $script:LogFilePath) {
        Write-Host ("Log File    : {0}" -f $script:LogFilePath) -ForegroundColor Gray
    }
    if ($EnableClientSideDecryption) {
        Write-Host ("Security    : Files are prepared on this computer") -ForegroundColor Gray
    } else {
        Write-Host ("Security    : Protected during download") -ForegroundColor Gray
    }
    Write-Host ""

    Write-Host "What happens next:" -ForegroundColor Cyan
    Write-Host "  1) You choose where files should be saved" -ForegroundColor Gray
    Write-Host "  2) We download and prepare the files" -ForegroundColor Gray
    Write-Host "  3) We verify and archive securely" -ForegroundColor Gray
    Write-Host ""
}

function Wait-ForStart {
    if ($AutoStart) { return }
    $resp = Read-Host "Press ENTER to begin download, or type Q then ENTER to quit"
    if ($resp -match '^(q|quit)$') {
        Write-Host "Exiting." -ForegroundColor Yellow
        exit 0
    }

    Write-Host ""
    Write-Host "Status: IN PROGRESS" -ForegroundColor Green
    Write-Host ""
}

function Ensure-ParentDir {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

function Convert-UnitToBytes {
    param([double]$Value,[string]$Unit)
    switch -Regex ($Unit.Trim()) {
        '^(B|Bytes?)$' { return [int64]$Value }
        '^(KB|K|KiB)$' { return [int64]($Value * 1KB) }
        '^(MB|M|MiB)$' { return [int64]($Value * 1MB) }
        '^(GB|G|GiB)$' { return [int64]($Value * 1GB) }
        '^(TB|T|TiB)$' { return [int64]($Value * 1TB) }
        default        { return [int64]$Value }
    }
}

# Parses aws-cli progress lines so we can show a global progress bar (AWS CLI output is the only reliable source).
function Try-ParseAwsProgressLine {
    param([string]$Line)
    # Example: Completed 12.3 MiB/200.0 MiB (3.1 MiB/s) ...
    $rx = [regex]'Completed\s+(?<a>[\d\.]+)\s*(?<u1>KiB|MiB|GiB|TiB|KB|MB|GB|TB|B)\s*/\s*(?<b>[\d\.]+)\s*(?<u2>KiB|MiB|GiB|TiB|KB|MB|GB|TB|B)(?:\s*\((?<speed>[^)]+)\))?'
    $m = $rx.Match($Line)
    if (-not $m.Success) { return $null }

    $uploadedBytes = Convert-UnitToBytes -Value ([double]$m.Groups["a"].Value) -Unit $m.Groups["u1"].Value
    $totalBytes    = Convert-UnitToBytes -Value ([double]$m.Groups["b"].Value) -Unit $m.Groups["u2"].Value
    if ($totalBytes -le 0) { return $null }

    $pct = [math]::Min(100, [math]::Round(($uploadedBytes / [double]$totalBytes) * 100, 1))
    return @{
        UploadedBytes = $uploadedBytes
        TotalBytes    = $totalBytes
        Percent       = $pct
        SpeedText     = $m.Groups["speed"].Value
    }
}

function Read-ExpectedSha256FromFile {
    param([string]$HashFilePath)

    if (-not (Test-Path -LiteralPath $HashFilePath)) { return $null }

    $line = (Get-Content -LiteralPath $HashFilePath -ErrorAction Stop | Select-Object -First 1)
    if (-not $line) { return $null }

    $line = $line.Trim()

    $rx = [regex]'(?i)\b(?<h>[a-f0-9]{64})\b'
    $m = $rx.Match($line)
    if ($m.Success) { return $m.Groups["h"].Value.ToLowerInvariant() }

    return $null
}

function Truncate-Text {
    param([string]$Text, [int]$Max = 55)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    if ($Text.Length -le $Max) { return $Text }
    return ($Text.Substring(0, $Max - 3) + "...")
}

function Get-Sha256WithProgress {
    param(
        [string]$FilePath,
        [string]$DisplayName
    )

    $fi = Get-Item -LiteralPath $FilePath -ErrorAction Stop
    $total = [int64]$fi.Length
    if ($total -le 0) {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath).Hash.ToLowerInvariant()
    }

    $bufferSize = 8MB
    $buffer = New-Object byte[] $bufferSize
    $hashed = [int64]0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)

    try {
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }

            [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)

            $hashed += [int64]$read
            $pct = [math]::Min(100, [math]::Round(($hashed / [double]$total) * 100, 1))

            $secs = [math]::Max(0.001, $sw.Elapsed.TotalSeconds)
            $mbps = (($hashed / 1MB) / $secs)

            Write-Progress `
                -Activity "Checking file integrity" `
                -Status ("{0}%  {1} / {2}   {3:N1} MB/s   File: {4}" -f $pct, (Format-Bytes $hashed), (Format-Bytes $total), $mbps, $DisplayName) `
                -PercentComplete $pct
        }

        [void]$sha.TransformFinalBlock($buffer, 0, 0)
        $hash = ($sha.Hash | ForEach-Object { $_.ToString("x2") }) -join ""
        return $hash.ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
        Write-Progress -Activity "Checking file integrity" -Completed -Status "Done"
    }
}

function Compare-ByteArrays {
    param([byte[]]$A, [byte[]]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    return $true
}

# Reads the CSE manifest that describes how to decrypt the file.
function Read-CseManifestJson {
    param([string]$ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "CSE manifest missing: $ManifestPath"
    }

    $json = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop
    $m = $json | ConvertFrom-Json -ErrorAction Stop

    if (-not $m -or -not $m.algorithm -or -not $m.encryptedDataKey -or -not $m.baseNonce) {
        throw "CSE manifest is missing required fields: $ManifestPath"
    }

    if ($m.algorithm -ne "AES-256-GCM") {
        throw "Unsupported CSE algorithm: $($m.algorithm)"
    }

    return $m
}

# Uses KMS to decrypt the data key stored in the manifest.
function Get-KmsPlaintextKeyFromEncryptedB64 {
    param(
        [string]$EncryptedDataKeyB64,
        [string]$Profile
    )

    $tmp = Join-Path -Path $env:TEMP -ChildPath ("kms_blob_{0}.bin" -f ([guid]::NewGuid().ToString("N")))
    try {
        $bytes = [Convert]::FromBase64String($EncryptedDataKeyB64)
        [System.IO.File]::WriteAllBytes($tmp, $bytes)

        $json = aws kms decrypt --ciphertext-blob ("fileb://$tmp") --profile $Profile --region $AwsRegion --output json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            throw "KMS decrypt failed. Check kms:Decrypt permissions."
        }

        $obj = (($json | Out-String) | ConvertFrom-Json)
        if (-not $obj.Plaintext) {
            throw "KMS decrypt returned unexpected response."
        }

        return [Convert]::FromBase64String([string]$obj.Plaintext)
    }
    finally {
        try { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } } catch {}
    }
}

# Decrypts ciphertext in chunks to avoid loading huge files into memory.
function Decrypt-FileAesGcmChunked {
    param(
        [Parameter(Mandatory=$true)][string]$InPath,
        [Parameter(Mandatory=$true)][string]$OutPath,
        [Parameter(Mandatory=$true)][byte[]]$KeyBytes,
        [Parameter(Mandatory=$true)][int]$ChunkSizeBytes,
        [Parameter(Mandatory=$true)][byte[]]$ExpectedBaseNonce12,
        [int64]$TotalPlainBytes = 0,
        [string]$DisplayName = ""
    )

    $MAGIC  = "CSECSE"
    $TAGLEN = 16

    $fsIn  = $null
    $fsOut = $null
    $aes   = $null

    try {
        $fsIn  = [System.IO.File]::Open($InPath,  [System.IO.FileMode]::Open,   [System.IO.FileAccess]::Read,  [System.IO.FileShare]::Read)
        $fsOut = [System.IO.File]::Open($OutPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

        $magicBytes = New-Object byte[] 6
        if ($fsIn.Read($magicBytes, 0, 6) -ne 6) { throw "Invalid ciphertext header (magic)." }
        $magicText = [System.Text.Encoding]::ASCII.GetString($magicBytes)
        if ($magicText -ne $MAGIC) { throw "Invalid ciphertext header (magic mismatch)." }

        $ver = $fsIn.ReadByte()
        if ($ver -ne 1) { throw "Unsupported ciphertext version: $ver" }

        $chBytes = New-Object byte[] 4
        if ($fsIn.Read($chBytes, 0, 4) -ne 4) { throw "Invalid ciphertext header (chunk size)." }
        $headerChunkSize = [int][BitConverter]::ToUInt32($chBytes, 0)
        if ($headerChunkSize -le 0) { throw "Invalid chunk size in ciphertext header." }
        if ($ChunkSizeBytes -gt 0 -and $ChunkSizeBytes -ne $headerChunkSize) {
            throw "Chunk size mismatch between manifest and ciphertext header."
        }
        $chunkSize = $headerChunkSize

        $baseNonce = New-Object byte[] 12
        if ($fsIn.Read($baseNonce, 0, 12) -ne 12) { throw "Invalid ciphertext header (nonce)." }

        if ($ExpectedBaseNonce12.Length -ne 12) { throw "Base nonce must be 12 bytes." }
        if (-not (Compare-ByteArrays -A $ExpectedBaseNonce12 -B $baseNonce)) {
            throw "Base nonce mismatch between manifest and ciphertext header."
        }

        if ($KeyBytes.Length -ne 32) { throw "AES-256-GCM requires a 32-byte key." }
        $aes = [System.Security.Cryptography.AesGcm]::new($KeyBytes)

        $done = 0L
        $chunkIndex = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        while ($fsIn.Position -lt $fsIn.Length) {
            $remaining = $fsIn.Length - $fsIn.Position
            if ($remaining -lt $TAGLEN) { throw "Ciphertext truncated (missing tag)." }

            $ctLen = [int][math]::Min([double]$chunkSize, [double]($remaining - $TAGLEN))
            if ($ctLen -le 0) { break }

            $ct = New-Object byte[] $ctLen
            if ($fsIn.Read($ct, 0, $ctLen) -ne $ctLen) { throw "Ciphertext truncated (data)." }

            $tag = New-Object byte[] $TAGLEN
            if ($fsIn.Read($tag, 0, $TAGLEN) -ne $TAGLEN) { throw "Ciphertext truncated (tag)." }

            $nonce = New-Object byte[] 12
            [Array]::Copy($baseNonce, 0, $nonce, 0, 12)
            $ctr = [BitConverter]::GetBytes([UInt32]$chunkIndex)
            [Array]::Copy($ctr, 0, $nonce, 8, 4)

            $pt = New-Object byte[] $ctLen
            $aes.Decrypt($nonce, $ct, $tag, $pt, $null)

            $fsOut.Write($pt, 0, $pt.Length)

            $done += $pt.Length
            $chunkIndex++

            if ($TotalPlainBytes -gt 0) {
                $pct = [math]::Min(100, [math]::Round(($done / [double]$TotalPlainBytes) * 100, 1))
                $elapsed = $sw.Elapsed
                $bps = if ($elapsed.TotalSeconds -gt 0) { ($done / $elapsed.TotalSeconds) } else { 0 }
                Write-Progress -Activity "Preparing files" -Status ("{0}%  {1} / {2}   {3}   Elapsed: {4}" -f $pct, (Format-Bytes $done), (Format-Bytes $TotalPlainBytes), (Format-Speed $bps), (Format-Duration $elapsed)) -PercentComplete $pct
            }
        }
    }
    finally {
        if ($aes)   { $aes.Dispose() }
        if ($fsIn)  { $fsIn.Dispose() }
        if ($fsOut) { $fsOut.Dispose() }
        Write-Progress -Activity "Preparing files" -Completed -Status "Done"
    }
}

function Write-RunSummary {
    param(
        [string]$Status,
        [string]$ErrorMessage
    )

    $endTime = Get-Date

    $totalElapsed = if ($scriptStart) { $endTime - $scriptStart } else { [TimeSpan]::Zero }
    $avgText = "n/a"
    if ($totalElapsed.TotalSeconds -gt 0 -and $bytesDone -gt 0) {
        $avgBps  = ([double]$bytesDone / [double]$totalElapsed.TotalSeconds)
        $avgText = Format-Speed -BytesPerSec $avgBps
    }

    $statusColor = if ($Status -eq "SUCCESS") { "Green" } elseif ($Status -eq "FAILED") { "Red" } else { "Yellow" }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkGray
    Write-Host ("RUN SUMMARY  [{0}]" -f $Status) -ForegroundColor $statusColor
    Write-Host "================================================================" -ForegroundColor DarkGray

    if ($scriptStart) {
        Write-Host ("Started     : {0}" -f ($scriptStart.ToString("yyyy-MM-dd HH:mm:ss"))) -ForegroundColor Gray
    }
    Write-Host ("Finished    : {0}" -f ($endTime.ToString("yyyy-MM-dd HH:mm:ss"))) -ForegroundColor Gray
    Write-Host ("Total Time  : {0}" -f (Format-Duration $totalElapsed)) -ForegroundColor Gray

    if ($totalBytes -gt 0) {
        Write-Host ("Data        : {0} / {1}" -f (Format-Bytes $bytesDone), (Format-Bytes $totalBytes)) -ForegroundColor Gray
    } else {
        Write-Host ("Data        : {0}" -f (Format-Bytes $bytesDone)) -ForegroundColor Gray
    }
    Write-Host ("Avg Speed   : {0}" -f $avgText) -ForegroundColor Gray

    if ($filesDone -ge 0 -and $totalFiles -ge 0) {
        Write-Host ("Files       : {0} / {1}" -f $filesDone, $totalFiles) -ForegroundColor Gray
    }

    if ($localIncoming) {
        Write-Host ("Destination : {0}" -f $localIncoming) -ForegroundColor Gray
    }
    Write-Host ("Source      : s3://{0}/{1}" -f $BucketName, $IncomingPrefix) -ForegroundColor Gray
    if ($EnableLog -and $script:LogFilePath) {
        Write-Host ("Log File    : {0}" -f $script:LogFilePath) -ForegroundColor Gray
    }

    if ($Status -eq "FAILED" -and $ErrorMessage) {
        Write-Host ""
        Write-Host "ERROR DETAILS:" -ForegroundColor Red
        Write-Host $ErrorMessage -ForegroundColor Red
    }

    Write-Host "================================================================" -ForegroundColor DarkGray
    Write-Host ""
}

# Make retries more resilient to brief outages
$env:AWS_RETRY_MODE   = "adaptive"
$env:AWS_MAX_ATTEMPTS = "20"
$env:AWS_PAGER        = ""

$didComplete   = $false
$localIncoming = $null
$script:PhaseIndex = 0
$script:PhaseTotal = 0
$script:LastPhaseStart = $null
$script:LastPhaseName = $null

# Summary tracking
$runStatus = "NOT_STARTED"
$runError  = $null

# Initialize counters so summary never errors if we fail early
$totalBytes   = [int64]0
$bytesDone    = [int64]0
$filesDone    = 0
$totalFiles   = 0
$archivedOk   = 0
$archivedFail = 0
$verifyFail   = 0
$hashOk       = 0
$hashFail     = 0
$hashMissing  = 0
$decryptOk    = 0
$decryptFail  = 0

# High-level flow:
# 1) Download all objects under incoming/
# 2) Decrypt locally so users can read files
# 3) Verify size/hash before archive
# 4) Move verified objects to downloaded/
try {
    $scriptStart   = Get-Date
    $downloadStart = $null
    $decryptStart  = $null
    $decryptEnd    = $null
    $archiveStart  = $null
    $runStatus     = "RUNNING"

    Initialize-Log
    Write-Log ("Version: {0}" -f $ToolVersion)
    Write-Log ("Profile: {0}" -f $AwsProfile)
    Write-Log ("Bucket: {0}" -f $BucketName)
    Write-Log ("Prefix: {0}" -f $IncomingPrefix)
    Write-Log ("Region: {0}" -f $AwsRegion)

    Initialize-ProgressUi

    Show-Banner -DestIncoming $null
    Wait-ForStart

    $script:PhaseIndex = 0
    $script:PhaseTotal = if ($EnableClientSideDecryption) { 7 } else { 6 }

    Write-Phase "Pre-flight checks"
    Ensure-SsoLogin -Profile $AwsProfile
    Configure-HighSpeedTransfer -Profile $AwsProfile
    Ensure-TransferAccelerationConfigured -Profile $AwsProfile -Bucket $BucketName
    Write-Host "Checklist:" -ForegroundColor Cyan
    Write-Host "  [OK] Signed in" -ForegroundColor Green
    Write-Host "  [OK] Ready to choose a destination folder" -ForegroundColor Green
    Write-Host "  [OK] Max speed transfer settings applied" -ForegroundColor Green
    Write-Host ""

    Write-Phase "Select a download folder"
    if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) {
        $LocalRoot = $DestinationPath
    } else {
        $defaultBase = [Environment]::GetFolderPath("Desktop")
        $LocalRoot = Select-DownloadDestination -DefaultPath $defaultBase
    }

    if (-not $LocalRoot) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        $didComplete = $true
        $runStatus   = "CANCELLED"
        return
    }

    $localIncoming = Join-Path $LocalRoot "incoming"
    New-Item -ItemType Directory -Force -Path $localIncoming | Out-Null
    $script:LocalDecrypted = $null
    if ($EnableClientSideDecryption) {
        $script:LocalDecrypted = Join-Path $LocalRoot "decrypted"
        New-Item -ItemType Directory -Force -Path $script:LocalDecrypted | Out-Null
    }
    Write-Log ("Destination: {0}" -f $localIncoming)

    $incomingUri = "s3://$BucketName/$IncomingPrefix"

    # 1) List objects in incoming/ (and total bytes)
    $downloadStart = Get-Date
    Write-Phase "Preparing download"

    $objects = New-Object System.Collections.Generic.List[object]
    $sizeByRel  = @{}
    $keyByRel   = @{}
    $totalBytes = [int64]0
    $token      = $null

    do {
        $args = @(
            "s3api", "list-objects-v2",
            "--bucket", $BucketName,
            "--prefix", $IncomingPrefix,
            "--profile", $AwsProfile,
            "--output", "json"
        )
        if ($token) { $args += @("--continuation-token", $token) }

        $json = aws @args
        if ($LASTEXITCODE -ne 0) { throw "Failed to list incoming/ objects for download sizing." }

        $obj = (($json | Out-String) | ConvertFrom-Json)

        if ($obj.Contents) {
            foreach ($c in $obj.Contents) {
                if (-not $c.Key -or $c.Key.EndsWith("/")) { continue }
                $rel  = $c.Key.Substring($IncomingPrefix.Length)
                $size = [int64]$c.Size
                $objects.Add([pscustomobject]@{ Key = $c.Key; Rel = $rel; Size = $size }) | Out-Null
                $sizeByRel[$rel] = $size
                $keyByRel[$rel]  = $c.Key
                $totalBytes += $size
            }
        }

        if ($obj.PSObject.Properties.Name -contains "NextContinuationToken") {
            $token = $obj.NextContinuationToken
        } else {
            $token = $null
        }
    } while ($token)

    if ($objects.Count -le 0) {
        Write-Host "No files found in incoming/. Nothing to download." -ForegroundColor Yellow
        $didComplete = $true
        $runStatus   = "SUCCESS"
        return
    }

    Write-Host ("Ready to download: {0} across {1} file(s)" -f (Format-Bytes $totalBytes), $objects.Count) -ForegroundColor Cyan
    Write-Log ("Total to download: {0} across {1} file(s)" -f (Format-Bytes $totalBytes), $objects.Count)
    Write-Host ""

    # Split into hash files and data files
    $hashObjs = New-Object System.Collections.Generic.List[object]
    $dataObjs = New-Object System.Collections.Generic.List[object]

    foreach ($o in $objects) {
        if ($o.Rel.ToLowerInvariant().EndsWith(".sha256")) { $hashObjs.Add($o) | Out-Null }
        else { $dataObjs.Add($o) | Out-Null }
    }

    Write-Phase "Downloading files"
    # Download order: hashes first, then data
    $downloadQueue = New-Object System.Collections.Generic.List[object]
    foreach ($h in $hashObjs) { $downloadQueue.Add($h) | Out-Null }
    foreach ($d in $dataObjs) { $downloadQueue.Add($d) | Out-Null }

    # 2) Download each object with aws s3 cp and parse "Completed X/Y" for progress
    $bytesDone  = [int64]0
    $filesDone  = 0
    $totalFiles = $downloadQueue.Count

    foreach ($o in $downloadQueue) {
        $src = "s3://$BucketName/$($o.Key)"
        $dst = Join-Path $localIncoming $o.Rel
        Ensure-ParentDir -Path $dst

        $cpArgs = @(
            "s3","cp",
            $src,
            $dst,
            "--profile", $AwsProfile,
            "--no-progress",
            "--cli-connect-timeout", "60",
            "--cli-read-timeout", "0"
        )

        # Write aws output to a temp log file, tail it, avoid Receive-Job huge output crash
        $awsCpLog = Join-Path $env:TEMP ("aws_cp_dl_{0}.log" -f ([guid]::NewGuid().ToString("N")))

        $job = Start-Job -ScriptBlock {
            param($ArgsArray, $OutFile)
            try {
                & aws @ArgsArray 2>&1 | Out-File -FilePath $OutFile -Encoding UTF8
                return $LASTEXITCODE
            } catch {
                ($_ | Out-String) | Out-File -FilePath $OutFile -Append -Encoding UTF8
                return 1
            }
        } -ArgumentList (,$cpArgs), $awsCpLog

        $lastProgress  = $null
        $lastLineCount = 0

        while ($true) {
            if (Test-Path -LiteralPath $awsCpLog) {
                $lines = @(Get-Content -LiteralPath $awsCpLog -ErrorAction SilentlyContinue)
                $lineCount = $lines.Count
                if ($lineCount -gt $lastLineCount) {
                    $newLines = $lines[$lastLineCount..($lineCount - 1)]
                    $lastLineCount = $lineCount

                    foreach ($ln in $newLines) {
                        $p = Try-ParseAwsProgressLine -Line ([string]$ln)
                        if ($p) { $lastProgress = $p }
                    }
                }
            }

            $state   = (Get-Job -Id $job.Id).State
            $elapsed = (Get-Date) - $downloadStart

            $currentUploaded = [int64]0
            $currentTotal    = [int64]$o.Size
            $speedText       = ""

            if ($lastProgress) {
                $currentUploaded = [int64]([math]::Min([double]$lastProgress.UploadedBytes, [double]$currentTotal))
                $speedText = $lastProgress.SpeedText
            }

            $globalBytes = [int64]([math]::Min([double]($bytesDone + $currentUploaded), [double]$totalBytes))
            $pct = [math]::Min(100, [math]::Round(($globalBytes / [double]$totalBytes) * 100, 1))

            $avgBps = 0.0
            if ($elapsed.TotalSeconds -gt 0) {
                $avgBps = ([double]$globalBytes / [double]$elapsed.TotalSeconds)
            }
            $avgText = (Format-Speed -BytesPerSec $avgBps).Trim()
            if (-not $avgText) { $avgText = "n/a" }

            $etaText = "n/a"
            $remaining = [double]($totalBytes - $globalBytes)
            if ($avgBps -gt 0 -and $remaining -gt 0) {
                $eta = [TimeSpan]::FromSeconds($remaining / $avgBps)
                $etaText = (Format-Duration $eta).Trim()
            } elseif ($remaining -le 0) {
                $etaText = "00s"
            }

            $currentText = if ($speedText) { $speedText.Trim() } else { "n/a" }
            $nowText = Truncate-Text -Text $o.Rel -Max 55

            $bar = Format-ProgressBar -Percent $pct
            $status = ("{0} {1}%  {2} / {3}   Files: {4}/{5}   Now: {6}   Current: {7} | Avg: {8} | ETA: {9}   Elapsed: {10}" -f `
                $bar, $pct, (Format-Bytes $globalBytes), (Format-Bytes $totalBytes),
                $filesDone, $totalFiles, $nowText, $currentText, $avgText, $etaText, (Format-Duration $elapsed))

            Write-StatusLine $status
            Write-Progress -Activity "Downloading files" -Status $status -PercentComplete $pct

            if ($state -eq "Completed" -or $state -eq "Failed" -or $state -eq "Stopped") { break }
            Start-Sleep -Milliseconds 750
        }

        $jobExit = Receive-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

        $text = ""
        if (Test-Path -LiteralPath $awsCpLog) {
            $text = (Get-Content -LiteralPath $awsCpLog -ErrorAction SilentlyContinue | Out-String)
            Remove-Item -LiteralPath $awsCpLog -Force -ErrorAction SilentlyContinue
        }

        if ($text -match '(?m)^(fatal error:|ERROR:)\b') {
            throw "Download failed for $($o.Rel):`n$text"
        }
        if ($jobExit -ne $null -and [int]$jobExit -ne 0) {
            throw "Download command failed for $($o.Rel) (exit code $jobExit).`n$text"
        }

        if (-not (Test-Path -LiteralPath $dst)) {
            throw "Download finished but local file missing: $dst"
        }

        $localSize = (Get-Item -LiteralPath $dst).Length
        if ($localSize -ne $o.Size) {
            throw "Download finished but size mismatch for $($o.Rel). Local=$localSize bytes, S3=$($o.Size) bytes"
        }

        $bytesDone += [int64]$o.Size
        $filesDone++

        Write-Host ("Saved: {0} ({1})" -f $o.Rel, (Format-Bytes $o.Size)) -ForegroundColor Gray
    }

    Write-Progress -Activity "Downloading files" -Completed -Status "Done"
    Clear-StatusLine

    $downloadElapsed = (Get-Date) - $downloadStart
    Write-Host ("Download finished in {0}." -f (Format-Duration $downloadElapsed)) -ForegroundColor Green
    Write-Log ("Download complete in {0}." -f (Format-Duration $downloadElapsed))

    # 2.5) Decrypt encrypted files (if present)
    if ($EnableClientSideDecryption) {
        Write-Phase "Preparing your files"
        $decryptStart = Get-Date

        $encList = @($dataObjs | Where-Object { $_.Rel.ToLowerInvariant().EndsWith($CiphertextExtension) })
        if ($encList.Count -le 0) {
            Write-Host "No secured files were found. Continuing." -ForegroundColor Yellow
        } else {
            $i = 0
            foreach ($o in $encList) {
                $i++
                $rel = $o.Rel
                $baseRel = $rel.Substring(0, $rel.Length - $CiphertextExtension.Length)
                $manifestRel = "$ArtefactsRelPrefix$baseRel$CseManifestSuffix"

                $encPath = Join-Path $localIncoming $rel
                $manifestPath = Join-Path $localIncoming $manifestRel
                $outPath = Join-Path $script:LocalDecrypted $baseRel

                $pct = [math]::Min(100, [math]::Round(($i / [double]$encList.Count) * 100, 1))
                Write-Progress -Activity "Preparing files" -Status ("{0}% ({1}/{2})  Current: {3}" -f $pct, $i, $encList.Count, $baseRel) -PercentComplete $pct

                if (-not (Test-Path -LiteralPath $manifestPath)) {
                    $decryptFail++
                    Write-Host "WARNING: A required security file is missing for $rel. This file will be skipped." -ForegroundColor Yellow
                    Write-Log ("Decrypt skip (manifest missing): {0}" -f $rel)
                    continue
                }
                if (-not (Test-Path -LiteralPath $encPath)) {
                    $decryptFail++
                    Write-Host "WARNING: The secured file is missing: $rel. This file will be skipped." -ForegroundColor Yellow
                    Write-Log ("Decrypt skip (ciphertext missing): {0}" -f $rel)
                    continue
                }

                $manifest = Read-CseManifestJson -ManifestPath $manifestPath

                $keyBytes = $null
                try {
                    $keyBytes = Get-KmsPlaintextKeyFromEncryptedB64 -EncryptedDataKeyB64 $manifest.encryptedDataKey -Profile $AwsProfile
                    $baseNonce = [Convert]::FromBase64String([string]$manifest.baseNonce)
                    $chunkSize = [int]$manifest.chunkSizeBytes
                    $origSize  = [int64]$manifest.originalSizeBytes

                    Decrypt-FileAesGcmChunked -InPath $encPath -OutPath $outPath -KeyBytes $keyBytes -ChunkSizeBytes $chunkSize -ExpectedBaseNonce12 $baseNonce -TotalPlainBytes $origSize -DisplayName $baseRel
                    $decryptOk++
                    Write-Host ("Prepared: {0}" -f $baseRel) -ForegroundColor Green
                    Write-Log ("Decrypt OK: {0}" -f $baseRel)
                }
                catch {
                    $decryptFail++
                    Write-Host ("WARNING: We could not prepare {0}. It will be skipped." -f $baseRel) -ForegroundColor Yellow
                    Write-Log ("Decrypt failed: {0} ({1})" -f $rel, $_.Exception.Message)
                    try { if (Test-Path -LiteralPath $outPath) { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } } catch {}
                }
                finally {
                    if ($keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
                }
            }
        }

        Write-Progress -Activity "Preparing files" -Completed -Status "Done"
        $decryptEnd = Get-Date
        Write-Log ("Decryption complete. OK={0} Fail={1}" -f $decryptOk, $decryptFail)
    }

    # 3) Verify -> Build list of verified items (NO MOVES HERE)
    # We verify size + hash before any delete to avoid data loss.
    Write-Phase "Checking files before archiving"
    $archiveStart   = Get-Date

    $processed      = 0
    $verifyFail     = 0
    $hashOk         = 0
    $hashMissing    = 0
    $hashFail       = 0

    $totalToVerify  = $dataObjs.Count

    $verifiedForArchive = New-Object System.Collections.Generic.List[object]

    foreach ($o in $dataObjs) {
        $processed++

        $key = $o.Key
        $rel = $o.Rel
        $localPath = Join-Path $localIncoming $rel
        Ensure-ParentDir -Path $localPath

        $isEncrypted = $rel.ToLowerInvariant().EndsWith($CiphertextExtension)
        if ($isEncrypted) {
            $baseRel = $rel.Substring(0, $rel.Length - $CiphertextExtension.Length)
            $plainPath = Join-Path $script:LocalDecrypted $baseRel
            $manifestRel = "$ArtefactsRelPrefix$baseRel$CseManifestSuffix"
            $manifestPath = Join-Path $localIncoming $manifestRel
        } else {
            $baseRel = $rel
            $plainPath = $localPath
            $manifestRel = $null
            $manifestPath = $null
        }

        $pct = [math]::Min(100, [math]::Round(($processed / [double]$totalToVerify) * 100, 1))
        Write-Progress `
            -Activity "Checking files" `
            -Status ("{0}% ({1}/{2})  Skipped:{3}  Checks OK:{4}  Checks Failed:{5}  Missing Hash:{6}  Current: {7}" -f `
                $pct, $processed, $totalToVerify, $verifyFail, $hashOk, $hashFail, $hashMissing, $rel) `
            -PercentComplete $pct

        $s3SizeText = aws s3api head-object `
            --bucket $BucketName `
            --key $key `
            --profile $AwsProfile `
            --query "ContentLength" `
            --output text

        if ($LASTEXITCODE -ne 0 -or -not $s3SizeText) {
            $verifyFail++
            Write-Host "WARNING: We could not verify $rel. It will be skipped." -ForegroundColor Yellow
            continue
        }

        $s3Size = [int64]$s3SizeText

        if (-not (Test-Path -LiteralPath $localPath)) {
            $verifyFail++
            Write-Host "WARNING: The downloaded file is missing for $rel. It will be skipped." -ForegroundColor Yellow
            continue
        }

        $localSize = (Get-Item -LiteralPath $localPath).Length
        if ($localSize -ne $s3Size) {
            $verifyFail++
            Write-Host ("WARNING: The file size for {0} does not match. It will be skipped." -f $rel) -ForegroundColor Yellow
            continue
        }

        $hashRel = "$ArtefactsRelPrefix$baseRel.sha256"
        $hashKey = $null
        if ($keyByRel.ContainsKey($hashRel)) { $hashKey = $keyByRel[$hashRel] }

        if ($isEncrypted) {
            if (-not $EnableClientSideDecryption) {
                $verifyFail++
                Write-Host "WARNING: A secured file was found but local preparation is disabled. It will be skipped." -ForegroundColor Yellow
                continue
            }
            if (-not (Test-Path -LiteralPath $manifestPath)) {
                $verifyFail++
                Write-Host "WARNING: A required security file is missing for $rel. It will be skipped." -ForegroundColor Yellow
                continue
            }
            if (-not (Test-Path -LiteralPath $plainPath)) {
                $verifyFail++
                Write-Host "WARNING: Prepared file missing for $baseRel. It will be skipped." -ForegroundColor Yellow
                continue
            }

            try {
                $m = Read-CseManifestJson -ManifestPath $manifestPath
                $expectedSize = [int64]$m.originalSizeBytes
                if ($expectedSize -gt 0) {
                    $plainSize = (Get-Item -LiteralPath $plainPath).Length
                    if ($plainSize -ne $expectedSize) {
                        $verifyFail++
                        Write-Host ("WARNING: Prepared file size mismatch for {0}. It will be skipped." -f $baseRel) -ForegroundColor Yellow
                        continue
                    }
                }
            } catch {
                $verifyFail++
                Write-Host ("WARNING: We could not read the security file for {0}. It will be skipped." -f $rel) -ForegroundColor Yellow
                continue
            }
        }

        if ($hashKey) {
            $hashLocalPath = Join-Path $localIncoming $hashRel
            if (-not (Test-Path -LiteralPath $hashLocalPath)) {
                $hashFail++
                $verifyFail++
                Write-Host "WARNING: The check file for $baseRel is missing. It will be skipped." -ForegroundColor Yellow
                continue
            }

            $expectedHash = Read-ExpectedSha256FromFile -HashFilePath $hashLocalPath
            if (-not $expectedHash) {
                $hashFail++
                $verifyFail++
                Write-Host "WARNING: The check file for $baseRel is not readable. It will be skipped." -ForegroundColor Yellow
                continue
            }

            Write-Host ("Checking file integrity for {0}..." -f $baseRel) -ForegroundColor Cyan
            $actualHash = Get-Sha256WithProgress -FilePath $plainPath -DisplayName $baseRel

            if ($actualHash -ne $expectedHash) {
                $hashFail++
                $verifyFail++
                Write-Host "WARNING: The integrity check failed for $baseRel. It will be skipped." -ForegroundColor Yellow
                continue
            } else {
                $hashOk++
                Write-Host "Integrity check OK" -ForegroundColor Green
            }
        } else {
            $hashMissing++
        }

        $verifiedForArchive.Add($o) | Out-Null
    }

    Write-Progress -Activity "Verifying files" -Completed -Status "Done"

    Write-Host ""
    Write-Host ("Verification complete. Verified {0}/{1} file(s)." -f $verifiedForArchive.Count, $dataObjs.Count) -ForegroundColor Green
    Write-Host "Archiving will now move verified files to the archive." -ForegroundColor Cyan
    Write-Host ""

    # 4) ARCHIVE step (separate progress bar that shows active work)
    # Archive uses s3 mv (copy + delete). If delete is denied, the file remains in incoming/.
    Write-Phase "Archiving files"
    $archivedOk     = 0
    $archivedFail   = 0

    $toArchiveCount = $verifiedForArchive.Count
    if ($toArchiveCount -gt 0) {
        $i = 0
        foreach ($o in $verifiedForArchive) {
            $i++

            $key = $o.Key
            $rel = $o.Rel
            $isEncrypted = $rel.ToLowerInvariant().EndsWith($CiphertextExtension)
            if ($isEncrypted) {
                $baseRel = $rel.Substring(0, $rel.Length - $CiphertextExtension.Length)
                $hashRel = "$ArtefactsRelPrefix$baseRel.sha256"
                $manifestRel = "$ArtefactsRelPrefix$baseRel$CseManifestSuffix"
            } else {
                $baseRel = $rel
                $hashRel = "$ArtefactsRelPrefix$rel.sha256"
                $manifestRel = $null
            }

            $src = "s3://$BucketName/$key"
            $dst = "s3://$BucketName/$DonePrefix$rel"

            $pct = [math]::Min(100, [math]::Round(($i / [double]$toArchiveCount) * 100, 1))

            Write-Progress `
                -Activity "Archiving files" `
                -Status ("{0}% ({1}/{2})  OK:{3}  Fail:{4}  Moving: {5}" -f $pct, $i, $toArchiveCount, $archivedOk, $archivedFail, $rel) `
                -PercentComplete $pct

            Write-Host ("Archiving: {0}" -f $rel) -ForegroundColor Cyan

            aws s3 mv "$src" "$dst" `
                --profile $AwsProfile `
                --only-show-errors `
                --sse aws:kms `
                --sse-kms-key-id $KmsKeyId `
                --cli-connect-timeout 60 `
                --cli-read-timeout 0

            if ($LASTEXITCODE -ne 0) {
                $archivedFail++
                Write-Host "WARNING: We could not archive $rel. It will remain for retry." -ForegroundColor Yellow
                continue
            }

            $hashKey = $null
            if ($keyByRel.ContainsKey($hashRel)) { $hashKey = $keyByRel[$hashRel] }

            if ($hashKey) {
                $hashSrc = "s3://$BucketName/$hashKey"
                $hashDst = "s3://$BucketName/$DonePrefix$hashRel"

                aws s3 mv "$hashSrc" "$hashDst" `
                    --profile $AwsProfile `
                    --only-show-errors `
                    --sse aws:kms `
                    --sse-kms-key-id $KmsKeyId `
                    --cli-connect-timeout 60 `
                    --cli-read-timeout 0

                if ($LASTEXITCODE -ne 0) {
                Write-Host "WARNING: The check file for $baseRel could not be archived. It will remain for retry." -ForegroundColor Yellow
                }
            }

            if ($isEncrypted -and $manifestRel) {
                $manifestKey = $null
                if ($keyByRel.ContainsKey($manifestRel)) { $manifestKey = $keyByRel[$manifestRel] }
                if ($manifestKey) {
                    $mSrc = "s3://$BucketName/$manifestKey"
                    $mDst = "s3://$BucketName/$DonePrefix$manifestRel"

                    aws s3 mv "$mSrc" "$mDst" `
                        --profile $AwsProfile `
                        --only-show-errors `
                        --sse aws:kms `
                        --sse-kms-key-id $KmsKeyId `
                        --cli-connect-timeout 60 `
                        --cli-read-timeout 0

                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "WARNING: The security file for $baseRel could not be archived. It will remain for retry." -ForegroundColor Yellow
                    }
                }
            }

            $archivedOk++
        }
    } else {
        Write-Host "No files were ready to archive." -ForegroundColor Yellow
    }

    Write-Progress -Activity "Archiving files" -Completed -Status "Done"

    $archiveElapsed = (Get-Date) - $archiveStart
    Write-Host ("Archiving complete in {0}. OK:{1}  Failed:{2}  Skipped:{3}" -f (Format-Duration $archiveElapsed), $archivedOk, $archivedFail, $verifyFail) -ForegroundColor Green
    Write-Host ("Integrity checks: OK:{0}  Failed:{1}  Missing:{2}" -f $hashOk, $hashFail, $hashMissing) -ForegroundColor Cyan

    # CLEANUP: Remove local encrypted files and manifests, keeping only decrypted files and their hashes
    # Note: S3 files were already archived to downloaded/ prefix in the previous phase
    Write-Phase "Cleaning up temporary files"
    $cleanupStart = Get-Date
    $cleanedCount = 0
    
    if ($toArchiveCount -gt 0) {
        $i = 0
        foreach ($o in $verifiedForArchive) {
            $i++
            
            $key = $o.Key
            $rel = $o.Rel
            $isEncrypted = $rel.ToLowerInvariant().EndsWith($CiphertextExtension)
            
            if ($isEncrypted) {
                Write-Progress `
                    -Activity "Cleaning up temporary files" `
                    -Status ("{0}% ({1}/{2})  Cleaned: {3}" -f [math]::Round(($i / [double]$toArchiveCount) * 100), $i, $toArchiveCount, $cleanedCount) `
                    -PercentComplete ([math]::Round(($i / [double]$toArchiveCount) * 100))
                
                # Delete the local encrypted file
                $localEncryptedPath = Join-Path $localIncoming $rel
                if (Test-Path -LiteralPath $localEncryptedPath) {
                    Write-Host ("Removing local encrypted file: {0}" -f $rel) -ForegroundColor DarkGray
                    Remove-Item -LiteralPath $localEncryptedPath -Force -ErrorAction SilentlyContinue
                    $cleanedCount++
                }
                
                # Delete the local manifest file
                $baseRel = $rel.Substring(0, $rel.Length - $CiphertextExtension.Length)
                $manifestRel = "$ArtefactsRelPrefix$baseRel$CseManifestSuffix"
                
                $localManifestPath = Join-Path $localIncoming $manifestRel
                if (Test-Path -LiteralPath $localManifestPath) {
                    Write-Host ("Removing local manifest: {0}" -f $manifestRel) -ForegroundColor DarkGray
                    Remove-Item -LiteralPath $localManifestPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    
    Write-Progress -Activity "Cleaning up temporary files" -Completed -Status "Done"
    $cleanupElapsed = (Get-Date) - $cleanupStart
    Write-Host ("Cleanup complete in {0}. Removed {1} local encrypted file(s) and manifests." -f (Format-Duration $cleanupElapsed), $cleanedCount) -ForegroundColor Green

    $totalElapsed = (Get-Date) - $scriptStart
    Write-Host ("Total runtime: {0}" -f (Format-Duration $totalElapsed)) -ForegroundColor Cyan

    Write-Host ""
    if ($verifyFail -gt 0) {
        Write-Host "NOTE: Some files were skipped because checks did not pass. They remain for review." -ForegroundColor Yellow
    }
    Write-Host "All done. Your files are downloaded and ready." -ForegroundColor Green

    $didComplete = $true
    $runStatus   = "SUCCESS"
}
catch {
    $runStatus = "FAILED"
    $runError  = $_.Exception.Message

    Write-Log ("Run failed: {0}" -f $runError)
    Write-Host ""
    Write-Host "ERROR: $($runError)" -ForegroundColor Red
    if ($EnableLog -and $script:LogFilePath) {
        Write-Host ("Support log saved to: {0}" -f $script:LogFilePath) -ForegroundColor DarkGray
    }
}
finally {
    Write-RunSummary -Status $runStatus -ErrorMessage $runError
    Write-Log ("Run status: {0}" -f $runStatus)

    if (-not $AutoStart) {
        if ($didComplete) {
            # Open decrypted folder if CSE is enabled, otherwise incoming folder
            $folderToOpen = if ($EnableClientSideDecryption -and $script:LocalDecrypted -and (Test-Path -LiteralPath $script:LocalDecrypted)) {
                $script:LocalDecrypted
            } elseif ($localIncoming -and (Test-Path -LiteralPath $localIncoming)) {
                $localIncoming
            } else {
                $null
            }

            if ($folderToOpen) {
                Write-Host ""
                Write-Host "Open destination folder?" -ForegroundColor Cyan

                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Download and archive complete.`n`nOpen the destination folder now?`n`n$folderToOpen",
                    "Download Complete",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )

                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    Start-Process explorer.exe $folderToOpen
                }
            }
        }

        Write-Host ""
        Write-Host "Press Enter to close..."
        [void][System.Console]::ReadLine()
    }
}
