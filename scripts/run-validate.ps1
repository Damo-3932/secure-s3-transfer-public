<#
Purpose:
  Validate that the deployed environment matches expected security controls.
  This is a governance-friendly check for S3/KMS/CloudTrail/Alerting posture.

When to use:
  - After Terraform apply
  - Before audits or demos
  - In CI for continuous validation

Prerequisites:
  - AWS CLI v2
  - Terraform access to environment state
  - BaseProfile with read permissions for audit checks

Inputs:
  - EnvDir (Terraform environment directory)
  - BaseProfile (used for AWS CLI checks)
  - Upload/Download profiles (optional smoke test)

Outputs:
  - PASS/FAIL report and non-zero exit code if findings exist

Common failure causes:
  - Backend not configured (missing TF_BACKEND_BUCKET/backend.hcl)
  - Missing permissions for CloudTrail/KMS/SNS checks
  - Drift from manual console changes

Usage:
  pwsh -File scripts\run-validate.ps1 -EnvDir infra\envs\prod -BaseProfile Developer -SkipClientValidation
#>
[CmdletBinding()]
param(
    [string]$EnvDir = (Join-Path $PSScriptRoot "..\infra\envs\prod"),
    [string]$BaseProfile = "",
    [string]$UploadProfile = "SecureUpload",
    [string]$DownloadProfile = "SecureDownload",
    [switch]$SkipClientValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Failures = @()

function Write-Pass {
    param([string]$Message)
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    $script:Failures += $Message
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        # Validation can't continue without required tooling.
        Write-Fail "Required command not found: $Name"
    }
}

function Invoke-Aws {
    param(
        [string[]]$CliArgs,
        [string]$Region,
        [string]$Profile
    )
    $args = @()
    if ($Region) { $args += @("--region", $Region) }
    if ($Profile) { $args += @("--profile", $Profile) }
    $out = & aws @CliArgs @args 2>&1
    return @{
        ExitCode = $LASTEXITCODE
        Output   = ($out | Out-String).Trim()
    }
}

function Get-TerraformOutputs {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { throw "EnvDir not found: $Dir" }
    Push-Location -LiteralPath $Dir
    try {
        $json = & terraform output -json
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            # Terraform outputs are the source of truth for expected resource names.
            throw "terraform output failed in $Dir. Ensure you ran terraform init/apply."
        }
        return ($json | ConvertFrom-Json)
    }
    finally {
        Pop-Location
    }
}

function Get-OutputValue {
    param(
        [object]$Outputs,
        [string]$Name
    )
    if (-not ($Outputs.PSObject.Properties.Name -contains $Name)) {
        Write-Fail "Missing terraform output: $Name"
        return ""
    }
    return $Outputs.$Name.value
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$PassMessage,
        [string]$FailMessage
    )
    if ($Condition) {
        Write-Pass $PassMessage
    } else {
        Write-Fail $FailMessage
    }
}

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Needle,
        [string]$FailMessage
    )
    if ($Text -like "*$Needle*") {
        Write-Pass $Needle
    } else {
        Write-Fail $FailMessage
    }
}

function Get-BackendBucketName {
    param([string]$Dir)
    if ($env:TF_BACKEND_BUCKET) { return $env:TF_BACKEND_BUCKET }
    $backendFile = Join-Path $Dir "backend.hcl"
    if (-not (Test-Path -LiteralPath $backendFile)) { return "" }
    $text = Get-Content -LiteralPath $backendFile -Raw
    if ($text -match 'bucket\s*=\s*"([^"]+)"') {
        return $Matches[1]
    }
    return ""
}

Write-Host "== Secure S3 Transfer Validation (prod) ==" -ForegroundColor Cyan

Require-Command "aws"
Require-Command "terraform"

if ($script:Failures.Count -gt 0) { exit 1 }

if ($BaseProfile) {
    Write-Host "Logging in to SSO ($BaseProfile)..." -ForegroundColor Gray
    $login = Invoke-Aws -CliArgs @("sso","login") -Region "" -Profile $BaseProfile
    if ($login.ExitCode -ne 0) {
        Write-Fail "SSO login failed: $($login.Output)"
    } else {
        Write-Pass "SSO login succeeded"
    }
}

$tf = Get-TerraformOutputs -Dir $EnvDir

$bucket = Get-OutputValue -Outputs $tf -Name "bucket_name"
$bucketArn = Get-OutputValue -Outputs $tf -Name "bucket_arn"
$region = Get-OutputValue -Outputs $tf -Name "aws_region"
$kmsKeyArn = Get-OutputValue -Outputs $tf -Name "kms_key_arn"
$kmsAliasName = Get-OutputValue -Outputs $tf -Name "kms_alias_name"
$incomingPrefix = Get-OutputValue -Outputs $tf -Name "incoming_prefix"
$auditBucket = Get-OutputValue -Outputs $tf -Name "audit_log_bucket_name"
$cloudtrailName = Get-OutputValue -Outputs $tf -Name "cloudtrail_name"
$logGroupName = Get-OutputValue -Outputs $tf -Name "cloudwatch_log_group_name"
$uploaderRoleArn = Get-OutputValue -Outputs $tf -Name "uploader_role_arn"
$downloaderRoleArn = Get-OutputValue -Outputs $tf -Name "downloader_role_arn"
$alertingEnabled = Get-OutputValue -Outputs $tf -Name "alerting_enabled"
$alertEmail = Get-OutputValue -Outputs $tf -Name "alert_email"
$alertingNamePrefix = Get-OutputValue -Outputs $tf -Name "alerting_name_prefix"
$alertingTopicArn = Get-OutputValue -Outputs $tf -Name "alerting_sns_topic_arn"
$alertingIamTopicArn = Get-OutputValue -Outputs $tf -Name "alerting_iam_sns_topic_arn"

Write-Host "Checking transfer bucket guardrails..." -ForegroundColor Cyan

$publicAccess = Invoke-Aws -CliArgs @("s3api","get-public-access-block","--bucket",$bucket) -Region $region -Profile $BaseProfile
if ($publicAccess.ExitCode -ne 0) {
    Write-Fail "Public access block missing for ${bucket}: $($publicAccess.Output)"
} else {
    $block = $publicAccess.Output | ConvertFrom-Json
    Assert-True ($block.PublicAccessBlockConfiguration.BlockPublicAcls -eq $true) "BlockPublicAcls enabled" "BlockPublicAcls not enabled"
    Assert-True ($block.PublicAccessBlockConfiguration.BlockPublicPolicy -eq $true) "BlockPublicPolicy enabled" "BlockPublicPolicy not enabled"
    Assert-True ($block.PublicAccessBlockConfiguration.IgnorePublicAcls -eq $true) "IgnorePublicAcls enabled" "IgnorePublicAcls not enabled"
    Assert-True ($block.PublicAccessBlockConfiguration.RestrictPublicBuckets -eq $true) "RestrictPublicBuckets enabled" "RestrictPublicBuckets not enabled"
}

$versioning = Invoke-Aws -CliArgs @("s3api","get-bucket-versioning","--bucket",$bucket) -Region $region -Profile $BaseProfile
if ($versioning.ExitCode -ne 0) {
    Write-Fail "Versioning check failed for ${bucket}: $($versioning.Output)"
} else {
    $versioningJson = $versioning.Output | ConvertFrom-Json
    Assert-True ($versioningJson.Status -eq "Enabled") "Versioning enabled" "Versioning not enabled"
}

$ownership = Invoke-Aws -CliArgs @("s3api","get-bucket-ownership-controls","--bucket",$bucket) -Region $region -Profile $BaseProfile
if ($ownership.ExitCode -ne 0) {
    Write-Fail "Ownership controls missing for ${bucket}: $($ownership.Output)"
} else {
    $ownershipJson = $ownership.Output | ConvertFrom-Json
    $ownershipMode = $ownershipJson.OwnershipControls.Rules[0].ObjectOwnership
    Assert-True ($ownershipMode -eq "BucketOwnerEnforced") "Object Ownership enforced" "Object Ownership not enforced"
}

$encryption = Invoke-Aws -CliArgs @("s3api","get-bucket-encryption","--bucket",$bucket) -Region $region -Profile $BaseProfile
if ($encryption.ExitCode -ne 0) {
    Write-Fail "Encryption not enabled for ${bucket}: $($encryption.Output)"
} else {
    $enc = $encryption.Output | ConvertFrom-Json
    $rule = $enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
    Assert-True ($rule.SSEAlgorithm -eq "aws:kms") "SSE-KMS enabled" "SSE-KMS not enabled"
    Assert-True ($rule.KMSMasterKeyID -eq $kmsKeyArn) "Bucket CMK matches expected key" "Bucket CMK does not match expected key"
}

$policy = Invoke-Aws -CliArgs @("s3api","get-bucket-policy","--bucket",$bucket) -Region $region -Profile $BaseProfile
if ($policy.ExitCode -ne 0) {
    Write-Fail "Bucket policy missing for ${bucket}: $($policy.Output)"
} else {
    $policyJson = ($policy.Output | ConvertFrom-Json).Policy
    # These denies enforce TLS + SSE-KMS + key pinning.
    Assert-Contains $policyJson "aws:SecureTransport" "TLS-only policy missing"
    Assert-Contains $policyJson "s3:x-amz-server-side-encryption" "SSE-KMS enforcement missing"
    Assert-Contains $policyJson "s3:x-amz-server-side-encryption-aws-kms-key-id" "KMS key pin policy missing"
    Assert-Contains $policyJson $kmsKeyArn "Bucket policy does not pin to expected CMK"
}

$logging = Invoke-Aws -CliArgs @("s3api","get-bucket-logging","--bucket",$bucket) -Region $region -Profile $BaseProfile
if ($logging.ExitCode -ne 0) {
    Write-Fail "Bucket logging check failed for ${bucket}: $($logging.Output)"
} else {
    $loggingJson = $logging.Output | ConvertFrom-Json
    $targetBucket = $loggingJson.LoggingEnabled.TargetBucket
    Assert-True ([string]::IsNullOrWhiteSpace($targetBucket) -eq $false) "Server access logging enabled" "Server access logging not enabled"
}

$logBucket = "$bucket-logs"
Write-Host "Checking transfer log bucket ($logBucket)..." -ForegroundColor Cyan

$logBucketAccess = Invoke-Aws -CliArgs @("s3api","get-public-access-block","--bucket",$logBucket) -Region $region -Profile $BaseProfile
if ($logBucketAccess.ExitCode -ne 0) {
    Write-Fail "Public access block missing for ${logBucket}: $($logBucketAccess.Output)"
}

$logBucketEnc = Invoke-Aws -CliArgs @("s3api","get-bucket-encryption","--bucket",$logBucket) -Region $region -Profile $BaseProfile
if ($logBucketEnc.ExitCode -ne 0) {
    Write-Fail "Encryption not enabled for ${logBucket}: $($logBucketEnc.Output)"
} else {
    $logEnc = $logBucketEnc.Output | ConvertFrom-Json
    $logRule = $logEnc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
    Assert-True ($logRule.SSEAlgorithm -eq "aws:kms") "Log bucket SSE-KMS enabled" "Log bucket SSE-KMS not enabled"
}

$logBucketVersioning = Invoke-Aws -CliArgs @("s3api","get-bucket-versioning","--bucket",$logBucket) -Region $region -Profile $BaseProfile
if ($logBucketVersioning.ExitCode -ne 0) {
    Write-Fail "Versioning check failed for ${logBucket}: $($logBucketVersioning.Output)"
} else {
    $logVer = $logBucketVersioning.Output | ConvertFrom-Json
    Assert-True ($logVer.Status -eq "Enabled") "Log bucket versioning enabled" "Log bucket versioning not enabled"
}

$logBucketPolicy = Invoke-Aws -CliArgs @("s3api","get-bucket-policy","--bucket",$logBucket) -Region $region -Profile $BaseProfile
if ($logBucketPolicy.ExitCode -ne 0) {
    Write-Fail "Log bucket policy missing for ${logBucket}: $($logBucketPolicy.Output)"
} else {
    $logPolicyJson = ($logBucketPolicy.Output | ConvertFrom-Json).Policy
    Assert-Contains $logPolicyJson "logging.s3.amazonaws.com" "Log bucket policy missing S3 log delivery principal"
}

Write-Host "Checking KMS controls..." -ForegroundColor Cyan

$rotation = Invoke-Aws -CliArgs @("kms","get-key-rotation-status","--key-id",$kmsKeyArn) -Region $region -Profile $BaseProfile
if ($rotation.ExitCode -ne 0) {
    Write-Fail "KMS rotation check failed: $($rotation.Output)"
} else {
    $rotationJson = $rotation.Output | ConvertFrom-Json
    Assert-True ($rotationJson.KeyRotationEnabled -eq $true) "KMS rotation enabled" "KMS rotation not enabled"
}

$aliases = Invoke-Aws -CliArgs @("kms","list-aliases","--key-id",$kmsKeyArn) -Region $region -Profile $BaseProfile
if ($aliases.ExitCode -ne 0) {
    Write-Fail "KMS alias check failed: $($aliases.Output)"
} else {
    $aliasesJson = $aliases.Output | ConvertFrom-Json
    $aliasNames = $aliasesJson.Aliases.AliasName
    Assert-True ($aliasNames -contains $kmsAliasName) "KMS alias exists" "KMS alias missing: $kmsAliasName"
}

$policyDoc = Invoke-Aws -CliArgs @("kms","get-key-policy","--key-id",$kmsKeyArn,"--policy-name","default") -Region $region -Profile $BaseProfile
if ($policyDoc.ExitCode -ne 0) {
    Write-Fail "KMS key policy check failed: $($policyDoc.Output)"
} else {
    $policyJson = ($policyDoc.Output | ConvertFrom-Json).Policy
    Assert-Contains $policyJson $uploaderRoleArn "KMS policy missing uploader role"
    Assert-Contains $policyJson $downloaderRoleArn "KMS policy missing downloader role"
}

Write-Host "Checking audit logging..." -ForegroundColor Cyan

$trail = Invoke-Aws -CliArgs @("cloudtrail","get-trail","--name",$cloudtrailName) -Region $region -Profile $BaseProfile
if ($trail.ExitCode -ne 0) {
    Write-Fail "CloudTrail lookup failed: $($trail.Output)"
} else {
    $trailJson = $trail.Output | ConvertFrom-Json
    $trailInfo = $trailJson.Trail
    Assert-True ($trailInfo.IsMultiRegionTrail -eq $true) "CloudTrail multi-region enabled" "CloudTrail multi-region disabled"
    Assert-True ($trailInfo.IncludeGlobalServiceEvents -eq $true) "CloudTrail global events enabled" "CloudTrail global events disabled"
    Assert-True ($trailInfo.LogFileValidationEnabled -eq $true) "CloudTrail log validation enabled" "CloudTrail log validation disabled"
    Assert-True ([string]::IsNullOrWhiteSpace($trailInfo.KmsKeyId) -eq $false) "CloudTrail KMS key configured" "CloudTrail KMS key not configured"
    Assert-True ($trailInfo.S3BucketName -eq $auditBucket) "CloudTrail logs to audit bucket" "CloudTrail audit bucket mismatch"
}

$logGroup = Invoke-Aws -CliArgs @("logs","describe-log-groups","--log-group-name-prefix",$logGroupName) -Region $region -Profile $BaseProfile
if ($logGroup.ExitCode -ne 0) {
    Write-Fail "CloudWatch log group lookup failed: $($logGroup.Output)"
} else {
    $logGroupJson = $logGroup.Output | ConvertFrom-Json
    $exact = $logGroupJson.logGroups | Where-Object { $_.logGroupName -eq $logGroupName } | Select-Object -First 1
    if (-not $exact) {
        Write-Fail "CloudWatch log group not found: $logGroupName"
    } else {
        Assert-True ([string]::IsNullOrWhiteSpace($exact.kmsKeyId) -eq $false) "Log group encrypted with CMK" "Log group not encrypted with CMK"
    }
}

$auditLogging = Invoke-Aws -CliArgs @("s3api","get-bucket-logging","--bucket",$auditBucket) -Region $region -Profile $BaseProfile
if ($auditLogging.ExitCode -ne 0) {
    Write-Fail "Audit bucket logging check failed: $($auditLogging.Output)"
} else {
    $auditLogJson = $auditLogging.Output | ConvertFrom-Json
    $auditTarget = $auditLogJson.LoggingEnabled.TargetBucket
    Assert-True ([string]::IsNullOrWhiteSpace($auditTarget) -eq $false) "Audit bucket access logging enabled" "Audit bucket access logging not enabled"
}

Write-Host "Checking alerting (mandatory)..." -ForegroundColor Cyan

Assert-True ($alertingEnabled -eq $true) "Alerting enabled" "Alerting is disabled (must be enabled in prod)"
Assert-True ([string]::IsNullOrWhiteSpace($alertEmail) -eq $false) "Alert email configured" "Alert email missing"

if ($alertingEnabled -eq $true) {
    $sns = Invoke-Aws -CliArgs @("sns","get-topic-attributes","--topic-arn",$alertingTopicArn) -Region $region -Profile $BaseProfile
    if ($sns.ExitCode -ne 0) {
        Write-Fail "SNS topic not found: $($sns.Output)"
    } else {
        $snsJson = $sns.Output | ConvertFrom-Json
        $kmsKey = $snsJson.Attributes.KmsMasterKeyId
        Assert-True ([string]::IsNullOrWhiteSpace($kmsKey) -eq $false) "SNS topic encrypted" "SNS topic not encrypted"
    }

    $subs = Invoke-Aws -CliArgs @("sns","list-subscriptions-by-topic","--topic-arn",$alertingTopicArn) -Region $region -Profile $BaseProfile
    if ($subs.ExitCode -ne 0) {
        Write-Fail "SNS subscriptions lookup failed: $($subs.Output)"
    } else {
        $subsJson = $subs.Output | ConvertFrom-Json
        # Subscription must be confirmed or alerts won't deliver.
        $match = $subsJson.Subscriptions | Where-Object { $_.Endpoint -eq $alertEmail } | Select-Object -First 1
        if (-not $match) {
            Write-Fail "SNS subscription missing for $alertEmail"
        } else {
            Assert-True ($match.SubscriptionArn -ne "PendingConfirmation") "SNS subscription confirmed" "SNS subscription pending confirmation"
        }
    }

    $regionalRules = @(
        "${alertingNamePrefix}-s3-bucket-policy-changes",
        "${alertingNamePrefix}-s3-public-access-changes",
        "${alertingNamePrefix}-kms-policy-changes",
        "${alertingNamePrefix}-kms-deletion"
    )

    foreach ($ruleName in $regionalRules) {
        $rule = Invoke-Aws -CliArgs @("events","describe-rule","--name",$ruleName) -Region $region -Profile $BaseProfile
        if ($rule.ExitCode -ne 0) {
            Write-Fail "EventBridge rule missing: $ruleName"
        } else {
            Write-Pass "EventBridge rule present: $ruleName"
        }

        $targets = Invoke-Aws -CliArgs @("events","list-targets-by-rule","--rule",$ruleName) -Region $region -Profile $BaseProfile
        if ($targets.ExitCode -ne 0) {
            Write-Fail "EventBridge targets lookup failed for ${ruleName}: $($targets.Output)"
        } else {
            $targetsJson = $targets.Output | ConvertFrom-Json
            $match = $targetsJson.Targets | Where-Object { $_.Arn -eq $alertingTopicArn } | Select-Object -First 1
            Assert-True ($null -ne $match) "SNS target wired for $ruleName" "SNS target missing for $ruleName"
        }
    }

    $iamRuleName = "${alertingNamePrefix}-iam-role-policy-changes"
    $iamRule = Invoke-Aws -CliArgs @("events","describe-rule","--name",$iamRuleName) -Region "us-east-1" -Profile $BaseProfile
    if ($iamRule.ExitCode -ne 0) {
        Write-Fail "IAM EventBridge rule missing (us-east-1): $iamRuleName"
    } else {
        Write-Pass "IAM EventBridge rule present (us-east-1)"
    }

    $iamTargets = Invoke-Aws -CliArgs @("events","list-targets-by-rule","--rule",$iamRuleName) -Region "us-east-1" -Profile $BaseProfile
    if ($iamTargets.ExitCode -ne 0) {
        Write-Fail "IAM EventBridge targets lookup failed: $($iamTargets.Output)"
    } else {
        $iamTargetsJson = $iamTargets.Output | ConvertFrom-Json
        $iamMatch = $iamTargetsJson.Targets | Where-Object { $_.Arn -eq $alertingIamTopicArn } | Select-Object -First 1
        Assert-True ($null -ne $iamMatch) "IAM SNS target wired" "IAM SNS target missing"
    }
}

Write-Host "Checking Terraform backend bucket..." -ForegroundColor Cyan

$backendBucket = Get-BackendBucketName -Dir $EnvDir
if ([string]::IsNullOrWhiteSpace($backendBucket)) {
    Write-Fail "Backend bucket name not found (set TF_BACKEND_BUCKET or create backend.hcl)."
} else {
    $backendAccess = Invoke-Aws -CliArgs @("s3api","get-public-access-block","--bucket",$backendBucket) -Region $region -Profile $BaseProfile
    if ($backendAccess.ExitCode -ne 0) {
        Write-Fail "Backend public access block missing: $($backendAccess.Output)"
    }

    $backendEnc = Invoke-Aws -CliArgs @("s3api","get-bucket-encryption","--bucket",$backendBucket) -Region $region -Profile $BaseProfile
    if ($backendEnc.ExitCode -ne 0) {
        Write-Fail "Backend encryption missing: $($backendEnc.Output)"
    } else {
        $backendEncJson = $backendEnc.Output | ConvertFrom-Json
        $backendRule = $backendEncJson.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
        Assert-True ($backendRule.SSEAlgorithm -eq "aws:kms") "Backend SSE-KMS enabled" "Backend SSE-KMS not enabled"
    }

    $backendVer = Invoke-Aws -CliArgs @("s3api","get-bucket-versioning","--bucket",$backendBucket) -Region $region -Profile $BaseProfile
    if ($backendVer.ExitCode -ne 0) {
        Write-Fail "Backend versioning check failed: $($backendVer.Output)"
    } else {
        $backendVerJson = $backendVer.Output | ConvertFrom-Json
        Assert-True ($backendVerJson.Status -eq "Enabled") "Backend versioning enabled" "Backend versioning not enabled"
    }

    $backendPolicy = Invoke-Aws -CliArgs @("s3api","get-bucket-policy","--bucket",$backendBucket) -Region $region -Profile $BaseProfile
    if ($backendPolicy.ExitCode -ne 0) {
        Write-Fail "Backend bucket policy missing: $($backendPolicy.Output)"
    } else {
        $backendPolicyJson = ($backendPolicy.Output | ConvertFrom-Json).Policy
        Assert-Contains $backendPolicyJson "aws:SecureTransport" "Backend TLS-only policy missing"
    }
}

if (-not $SkipClientValidation) {
    if (-not $BaseProfile) {
        Write-Fail "BaseProfile is required for client validation. Use -SkipClientValidation to bypass."
    } else {
        Write-Host "Running client smoke test..." -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot "run-smoke-test.ps1") `
            -EnvDir $EnvDir `
            -BaseProfile $BaseProfile `
            -UploadProfile $UploadProfile `
            -DownloadProfile $DownloadProfile `
            -Cleanup
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Client smoke test failed."
        } else {
            Write-Pass "Client smoke test succeeded"
        }
    }
}

if ($script:Failures.Count -gt 0) {
    Write-Host "Validation failed: $($script:Failures.Count) issue(s)." -ForegroundColor Red
    exit 1
}

Write-Host "Validation succeeded with no findings." -ForegroundColor Cyan
exit 0
