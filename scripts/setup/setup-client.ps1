<#
Purpose:
  Guided client onboarding for Secure S3 Transfer. Creates/updates an AWS SSO profile,
  writes a local JSON config for upload/download, applies safe transfer settings, and
  creates a desktop shortcut. Optional post-setup validation is supported.

When to use:
  - New laptop onboarding (uploader or downloader)
  - Rebuild a profile/config after environment changes
  - Validate access after role updates

Prerequisites:
  - Windows 10/11
  - PowerShell 7 (this script can auto-install)
  - AWS CLI v2 (this script can auto-install)
  - SSO access to the correct AWS account and permission set
  - A populated .env file (see .env.example)

Inputs:
  - .env file with SSO + bucket + KMS information
  - Mode (upload/download)

Outputs / changes:
  - AWS CLI SSO profile entries in ~/.aws/config
  - config.upload.json or config.download.json under scripts/config/
  - Desktop shortcut to the relevant upload/download script
  - Optional test file in %TEMP% when -RunTest is used

Logs:
  - Upload: %USERPROFILE%\Documents\SecureUploadLogs
  - Download: %USERPROFILE%\Documents\SecureDownloadLogs

Common failure causes:
  - Missing/incorrect .env values (bucket/KMS/SSO info)
  - SSO role not assigned to the user
  - KMS policy missing the role principal
  - AWS CLI or PowerShell 7 install blocked by policy

Usage:
  pwsh -File scripts\setup\setup-client.ps1 -Gui -RunTest

Maintainer notes:
  - The JSON config format must remain aligned with Upload_To_S3.ps1 and Download_From_S3.ps1.
  - KMS key IDs must match bucket policy enforcement; changing key requires updating .env and Terraform outputs.
  - The SSO role names must align with Identity Center permission sets.
#>
[CmdletBinding()]
param(
    [ValidateSet("upload","download")][string]$Mode,
    [string]$ProfileName,
    [string]$EnvFile = (Join-Path $PSScriptRoot "..\\..\\.env"),
    [switch]$Force,
    [switch]$SkipTransferSettings,
    [switch]$SkipShortcut,
    [switch]$Gui,
    [switch]$RunTest,
    [switch]$Login
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        # Fail fast so we don't create a half-configured client.
        throw "Required command not found: $Name"
    }
}

function Install-WithWinget {
    param([string]$Id,[string]$Name)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host ("Installing {0} via winget..." -f $Name) -ForegroundColor Cyan
        $null = Start-Process -FilePath winget -ArgumentList "install --id $Id --accept-package-agreements --accept-source-agreements -e" -Wait -PassThru
        return $true
    }
    return $false
}

function Install-AwsCli {
    if (Install-WithWinget -Id "Amazon.AWSCLI" -Name "AWS CLI v2") { return }
    # MSI fallback supports environments without winget.
    Write-Host "Installing AWS CLI v2 via MSI..." -ForegroundColor Cyan
    $msiPath = Join-Path $env:TEMP "AWSCLIV2.msi"
    Invoke-WebRequest -Uri "https://awscli.amazonaws.com/AWSCLIV2.msi" -OutFile $msiPath
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn" -Wait
}

function Install-PowerShell7 {
    if (Install-WithWinget -Id "Microsoft.PowerShell" -Name "PowerShell 7") { return }
    # MSI fallback keeps installs compatible with locked-down endpoints.
    Write-Host "Installing PowerShell 7 via MSI..." -ForegroundColor Cyan
    $msiPath = Join-Path $env:TEMP "PowerShell-7.msi"
    Invoke-WebRequest -Uri "https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.4.6-win-x64.msi" -OutFile $msiPath
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn" -Wait
}

function Ensure-PowerShell7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }
    Install-PowerShell7
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        # Crypto + JSON behaviors are standardized on PS7; PS5 can break assumptions.
        throw "PowerShell 7 installation failed. Please install manually."
    }
    # Relaunch under PS7 to keep consistent behavior end-to-end.
    $boundArgs = @()
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) {
            if ($kv.Value) { $boundArgs += "-$($kv.Key)" }
        } else {
            $boundArgs += "-$($kv.Key) `"$($kv.Value)`""
        }
    }
    $allArgs = @($boundArgs + $args) -join " "
    Write-Host "Restarting in PowerShell 7..." -ForegroundColor Cyan
    Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList "-File `"$PSCommandPath`" $allArgs" -Wait
    exit 0
}

function Ensure-AwsCli {
    if (Get-Command aws -ErrorAction SilentlyContinue) { return }
    Install-AwsCli
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
        # No AWS CLI means no SSO profile and no data transfer.
        throw "AWS CLI installation failed. Please install manually."
    }
}

function Read-EnvFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        # .env is the authoritative source of local client settings.
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
        # Missing values here cause wrong bucket/KMS usage and access denials.
        throw "Missing $Key in env file."
    }
    return $Map[$Key]
}

function Prompt-Mode {
    while ($true) {
        $choice = (Read-Host "Select mode (upload/download)").Trim().ToLower()
        switch ($choice) {
            "upload" { return "upload" }
            "download" { return "download" }
            "u" { return "upload" }
            "d" { return "download" }
        }
        Write-Host "Please enter 'upload' or 'download'." -ForegroundColor Yellow
    }
}

function Prompt-ModeGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Secure S3 Transfer Setup"
    $form.Size = New-Object System.Drawing.Size(360,180)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Configure this laptop as:"
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(20,20)
    $form.Controls.Add($label)

    $btnUpload = New-Object System.Windows.Forms.Button
    $btnUpload.Text = "Uploader"
    $btnUpload.Size = New-Object System.Drawing.Size(120,35)
    $btnUpload.Location = New-Object System.Drawing.Point(40,70)
    $btnUpload.Add_Click({ $form.Tag = "upload"; $form.Close() })
    $form.Controls.Add($btnUpload)

    $btnDownload = New-Object System.Windows.Forms.Button
    $btnDownload.Text = "Downloader"
    $btnDownload.Size = New-Object System.Drawing.Size(120,35)
    $btnDownload.Location = New-Object System.Drawing.Point(180,70)
    $btnDownload.Add_Click({ $form.Tag = "download"; $form.Close() })
    $form.Controls.Add($btnDownload)

    $form.Topmost = $true
    [void]$form.ShowDialog()

    if (-not $form.Tag) {
        throw "Selection cancelled. Exiting."
    }
    return $form.Tag
}

function Prompt-RunScriptGui {
    Add-Type -AssemblyName System.Windows.Forms
    $result = [System.Windows.Forms.MessageBox]::Show(
        "Run the $Mode script now?",
        "Secure S3 Transfer",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Show-ErrorGui {
    param([string]$Message)
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        "Secure S3 Transfer - Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Set-ProfileSetting {
    param([string]$Profile,[string]$Key,[string]$Value)
    aws configure set "profile.$Profile.$Key" $Value | Out-Null
}

function Apply-TransferSettings {
    param([string]$Profile,[string]$UseAccel)
    # These settings are tuned for large, reliable transfers (fewer retries, stable chunk sizes).
    Set-ProfileSetting -Profile $Profile -Key "s3.multipart_chunksize" -Value "256MB"
    Set-ProfileSetting -Profile $Profile -Key "s3.max_concurrent_requests" -Value "10"
    Set-ProfileSetting -Profile $Profile -Key "max_attempts" -Value "10"
    Set-ProfileSetting -Profile $Profile -Key "retry_mode" -Value "adaptive"
    if ($UseAccel) {
        # Acceleration is opt-in and only works if enabled on the bucket.
        Set-ProfileSetting -Profile $Profile -Key "s3.use_accelerate_endpoint" -Value "true"
    }
}

function Write-JsonFile {
    param([string]$Path,[object]$Obj,[switch]$Force)
    if (-not $Force -and (Test-Path -LiteralPath $Path)) {
        Write-Host ("Config file already exists: {0}" -f $Path) -ForegroundColor Yellow
        Write-Host "Nothing was changed. Re-run with -Force to overwrite." -ForegroundColor Yellow
        return $false
    }
    $json = $Obj | ConvertTo-Json -Depth 6
    $json | Set-Content -LiteralPath $Path -Encoding UTF8
    return $true
}

function Create-DesktopShortcut {
    param(
        [string]$ShortcutName,
        [string]$TargetPath,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$IconPath
    )
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktop $ShortcutName
    $shell = New-Object -ComObject WScript.Shell
    $exists = Test-Path -LiteralPath $shortcutPath
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $WorkingDirectory
    if ($IconPath -and (Test-Path -LiteralPath $IconPath)) {
        $shortcut.IconLocation = $IconPath
    }
    $shortcut.Save()
    return (-not $exists)
}

Ensure-PowerShell7
Ensure-AwsCli

if (-not $Mode) {
    if ($Gui -or $Host.Name -eq "ConsoleHost") {
        try {
            $Mode = Prompt-ModeGui
        } catch {
            $Mode = Prompt-Mode
        }
    } else {
        $Mode = Prompt-Mode
    }
}

$envMap = Read-EnvFile -Path $EnvFile
$region = Require-EnvValue -Map $envMap -Key "AWS_REGION"

if (-not $ProfileName) {
    $ProfileName = if ($Mode -eq "upload") { "SecureUpload" } else { "SecureDownload" }
}

Write-Host ("Configuring SSO profile '{0}' ({1})..." -f $ProfileName,$Mode) -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "configure-sso.ps1") -ProfileName $ProfileName -Mode $Mode -EnvFile $EnvFile
if ($LASTEXITCODE -ne 0) { throw "SSO profile configuration failed." } # Likely missing SSO assignment or invalid Start URL.

if (-not $SkipTransferSettings) {
    $useAccel = $false
    if ($envMap.ContainsKey("ENABLE_TRANSFER_ACCELERATION")) {
        $useAccel = $envMap["ENABLE_TRANSFER_ACCELERATION"].ToLower() -eq "true"
    } else {
        # Default to acceleration on for better long-haul performance.
        $useAccel = $true
    }
    Write-Host "Applying transfer settings..." -ForegroundColor Cyan
    Apply-TransferSettings -Profile $ProfileName -UseAccel:$useAccel
}

$bucket    = Require-EnvValue -Map $envMap -Key "BUCKET_NAME"
$kmsKeyArn = Require-EnvValue -Map $envMap -Key "KMS_KEY_ID"
$incoming  = $envMap["INCOMING_PREFIX"]
$artefacts = $envMap["ARTEFACTS_PREFIX"]
$downloaded = $envMap["DOWNLOADED_PREFIX"]
if (-not $incoming) { $incoming = "incoming/" }
if (-not $artefacts) { $artefacts = "incoming/artefacts/" }
if (-not $downloaded) { $downloaded = "downloaded/" }

$outDir = Join-Path $PSScriptRoot "..\\config"
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

if ($Mode -eq "upload") {
    $configPath = Join-Path $outDir "config.upload.json"
    $config = [ordered]@{
        aws_profile                         = $ProfileName
        aws_region                          = $region
        bucket_name                         = $bucket
        incoming_prefix                     = $incoming
        artefacts_prefix                    = $artefacts
        kms_key_id                          = $kmsKeyArn
        # Client-side encryption protects plaintext before it leaves the device.
        enable_client_side_encryption       = $true
        cse_chunk_size_mb                   = 4
        cse_manifest_suffix                 = ".cse.manifest.json"
        ciphertext_extension                = ".enc"
        use_transfer_acceleration           = $true
        enable_upload_checksum              = $true
        upload_checksum_algorithm           = "SHA256"
        store_ciphertext_with_enc_extension = $true
        upload_progress_sample_ms           = 250
        # Defender scan runs before encryption to prevent storing malware in S3.
        enable_defender_scan                = $true
        defender_scan_poll_ms               = 500
        enable_log                          = $true
        upload_log_directory                = "%USERPROFILE%\\Documents\\SecureUploadLogs"
    }
} else {
    $configPath = Join-Path $outDir "config.download.json"
    $config = [ordered]@{
        aws_profile            = $ProfileName
        aws_region             = $region
        bucket_name            = $bucket
        incoming_prefix        = $incoming
        artefacts_prefix       = $artefacts
        downloaded_prefix      = $downloaded
        kms_key_id             = $kmsKeyArn
        cse_manifest_suffix    = ".cse.manifest.json"
        ciphertext_extension   = ".enc"
        enable_log             = $true
        download_log_directory = "%USERPROFILE%\\Documents\\SecureDownloadLogs"
    }
}

$wrote = Write-JsonFile -Path $configPath -Obj $config -Force:$Force
if ($wrote) {
    Write-Host "Wrote config: $configPath" -ForegroundColor Green
}

if (-not $SkipShortcut) {
    $pwshPath = (Get-Command pwsh).Source
    $scriptPath = if ($Mode -eq "upload") {
        Join-Path $PSScriptRoot "..\\..\\scripts\\upload\\Upload_To_S3.ps1"
    } else {
        Join-Path $PSScriptRoot "..\\..\\scripts\\download\\Download_From_S3.ps1"
    }
    $iconPath = Join-Path $PSScriptRoot "..\\assets\\secure-s3-transfer.ico"
    $shortcutName = if ($Mode -eq "upload") { "Secure Upload.lnk" } else { "Secure Download.lnk" }
    $args = "-ExecutionPolicy Bypass -File `"$scriptPath`""
    $created = Create-DesktopShortcut -ShortcutName $shortcutName -TargetPath $pwshPath -Arguments $args -WorkingDirectory (Split-Path $scriptPath -Parent) -IconPath $iconPath
    if ($created) {
        Write-Host ("Created desktop shortcut: {0}" -f $shortcutName) -ForegroundColor Green
    } else {
        # Always refresh shortcut in case script paths moved.
        Write-Host ("Desktop shortcut updated: {0}" -f $shortcutName) -ForegroundColor Green
    }
}

if ($Login) {
    Write-Host "Starting SSO login..." -ForegroundColor Cyan
    & aws sso login --profile $ProfileName
}

if ($RunTest) {
    Write-Host "Running client test..." -ForegroundColor Cyan
    $testMode = $Mode
    try {
        & (Join-Path $PSScriptRoot "test-client.ps1") -Mode $testMode
    } catch {
        try {
            Show-ErrorGui -Message $_.Exception.Message
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }

    $runScript = $false
    try {
        $runScript = Prompt-RunScriptGui
    } catch {
        $choice = (Read-Host "Run the $Mode script now? (y/n)").Trim().ToLower()
        $runScript = ($choice -eq "y" -or $choice -eq "yes")
    }
    if ($runScript) {
        if ($Mode -eq "upload") {
            $testFile = Join-Path $env:TEMP "secure-upload-test.txt"
            "test $(Get-Date -Format s)" | Set-Content -LiteralPath $testFile -Encoding UTF8
            # Run the same upload script operators will use in production.
            pwsh -File (Join-Path $PSScriptRoot "..\\upload\\Upload_To_S3.ps1") -InputFilePath $testFile -AutoStart
        } else {
            $dest = Join-Path $env:TEMP "secure-download-test"
            if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest | Out-Null }
            # Run the same download script operators will use in production.
            pwsh -File (Join-Path $PSScriptRoot "..\\download\\Download_From_S3.ps1") -DestinationPath $dest -AutoStart
        }
    }
}

Write-Host ("Setup complete for {0} mode." -f $Mode) -ForegroundColor Green
Write-Host ("Run: pwsh -File scripts\\{0}\\{1}" -f $Mode, $(if ($Mode -eq "upload") { "Upload_To_S3.ps1" } else { "Download_From_S3.ps1" })) -ForegroundColor Yellow
