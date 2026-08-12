[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentId,

    [Parameter(Mandatory = $true)]
    [string]$EyeMoleSoarUrl,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$SyftPath = "C:\Program Files\EyeMoleAgent\syft.exe",
    [string]$CaCertPath = "",
    [string[]]$ScanTargets = @("C:\Program Files", "C:\Program Files (x86)")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$programDir = "C:\Program Files\EyeMoleAgent"
$dataDir = "C:\ProgramData\EyeMoleAgent"
$scriptSource = Join-Path $PSScriptRoot "Generate-And-Upload-Sbom.ps1"
$scriptTarget = Join-Path $programDir "Generate-And-Upload-Sbom.ps1"
$configPath = Join-Path $dataDir "agent.json"
$tokenPath = Join-Path $dataDir "token.txt"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell session."
}

if (-not (Test-Path -LiteralPath $scriptSource)) {
    throw "Cannot find script source: $scriptSource"
}

New-Item -ItemType Directory -Force -Path $programDir, $dataDir | Out-Null
Copy-Item -LiteralPath $scriptSource -Destination $scriptTarget -Force

Set-Content -LiteralPath $tokenPath -Value $Token -NoNewline -Encoding ASCII

$acl = Get-Acl -LiteralPath $tokenPath
$acl.SetAccessRuleProtection($true, $false)
@($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")))
Set-Acl -LiteralPath $tokenPath -AclObject $acl

$config = [ordered]@{
    AgentId = $AgentId
    EyeMoleSoarUrl = $EyeMoleSoarUrl
    TokenPath = $tokenPath
    SyftPath = $SyftPath
    CaCertPath = $CaCertPath
    ScanTargets = $ScanTargets
}

$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding UTF8

& curl.exe --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "curl.exe is required. Windows Server 2019 includes curl.exe by default; verify it is available in PATH."
}

if (-not (Test-Path -LiteralPath $SyftPath)) {
    Write-Warning "Syft was not found at $SyftPath. Install syft.exe before the scheduled task runs."
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptTarget`" -ConfigPath `"$configPath`""

$trigger = New-ScheduledTaskTrigger -Daily -At 2:15am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask `
    -TaskName "EyeMole SBOM Upload" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Generate a CycloneDX SBOM with Syft and upload it to EyeMole SOAR." `
    -Force | Out-Null

Write-Host "EyeMole SBOM scheduled task installed. Check with: Get-ScheduledTask -TaskName 'EyeMole SBOM Upload'"
