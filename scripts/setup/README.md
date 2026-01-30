# Setup Automation Scripts

These scripts automate first-time cloud deployment and per-user laptop setup.

## 1) Full cloud deployment (first time)
Deploys the remote state backend and the environment stack.

```powershell
pwsh -File scripts\setup\deploy-cloud.ps1 -AutoApprove -GenerateConfigs `
  -UploadProfile YOUR_UPLOAD_PROFILE -DownloadProfile YOUR_DOWNLOAD_PROFILE
```

Notes:
- If `backend.hcl` or `terraform.tfvars` do not exist, the script copies the example files and stops so you can edit them.
- Use `-SkipBootstrap` if the state backend already exists.
- Use `-SkipBackendInit` if the backend is already initialized.
- Use `-PlanOnly` or `-ValidateOnly` to test without applying.
- Use `-AwsProfile` to preflight-check that a local AWS CLI profile exists.
- `-ValidateOnly` disables backend init for the env to allow offline validation.

## 2) Configure a user laptop (upload OR download)
Creates a least-privilege profile and a single config file for that mode.

Upload user:
```powershell
pwsh -File scripts\setup\configure-user.ps1 -Mode upload `
  -ProfileName upload-user `
  -SourceProfile YOUR_SSO_PROFILE
```

Download user:
```powershell
pwsh -File scripts\setup\configure-user.ps1 -Mode download `
  -ProfileName download-user `
  -SourceProfile YOUR_SSO_PROFILE
```

Options:
- `-Force` overwrites config files.
- `-SkipProfileSettings` only writes the JSON config file.
- `-SkipConfigFile` only configures the AWS CLI profile.

## 3) One-step client setup (guided)
Interactive setup that asks whether this laptop is upload or download, then:
- configures the SSO profile from `.env`
- applies transfer settings
- writes the matching config file
- creates/repairs a desktop shortcut
- auto-installs PowerShell 7 and AWS CLI v2 if missing

```powershell
copy .env.example .env
pwsh -File scripts\setup\setup-client.ps1 -Gui
```

Run validation after setup and prompt to launch the client script:
```powershell
pwsh -File scripts\setup\setup-client.ps1 -Gui -RunTest
```

Non-interactive:
```powershell
pwsh -File scripts\setup\setup-client.ps1 -Mode upload -ProfileName SecureUpload
pwsh -File scripts\setup\setup-client.ps1 -Mode download -ProfileName SecureDownload
```

Options:
- `-Login` launches SSO login automatically at the end.
- `-RunTest` runs the client test first, then prompts to launch the script.
- `-SkipShortcut` skips desktop shortcut creation/repair.
