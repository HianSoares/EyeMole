[CmdletBinding()]
param(
    [string]$ConfigPath = "C:\ProgramData\EyeMoleAgent\agent.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-AgentLog {
    param(
        [string]$Level,
        [string]$Message,
        [string]$LogPath
    )

    $line = "{0:o} [{1}] {2}" -f (Get-Date), $Level, $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Read-AgentConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }

    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Assert-AgentConfig {
    param($Config)

    foreach ($property in @("AgentId", "EyeMoleSoarUrl", "TokenPath", "SyftPath", "ScanTargets")) {
        if (-not $Config.PSObject.Properties.Name.Contains($property)) {
            throw "Missing required config property: $property"
        }
    }

    if (-not $Config.AgentId) {
        throw "AgentId cannot be empty"
    }

    if (-not $Config.EyeMoleSoarUrl) {
        throw "EyeMoleSoarUrl cannot be empty"
    }

    if (-not (Test-Path -LiteralPath $Config.TokenPath)) {
        throw "Token file not found: $($Config.TokenPath)"
    }

    if (-not (Test-Path -LiteralPath $Config.SyftPath)) {
        throw "Syft executable not found: $($Config.SyftPath)"
    }

    if (-not $Config.ScanTargets -or $Config.ScanTargets.Count -eq 0) {
        throw "ScanTargets must contain at least one directory"
    }

    if ($Config.PSObject.Properties.Name.Contains("CaCertPath") -and $Config.CaCertPath) {
        if (-not (Test-Path -LiteralPath $Config.CaCertPath)) {
            throw "CaCertPath is set but not readable: $($Config.CaCertPath)"
        }
    }
}

function New-Sbom {
    param(
        $Config,
        [string]$OutputPath,
        [string]$LogPath
    )

    $parts = @()
    $index = 0

    foreach ($target in $Config.ScanTargets) {
        $partPath = Join-Path ([System.IO.Path]::GetDirectoryName($OutputPath)) ("part-{0}.json" -f $index)
        Write-AgentLog -Level "INFO" -Message "Generating CycloneDX SBOM for $target" -LogPath $LogPath
        & $Config.SyftPath scan $target --from dir -o cyclonedx-json | Out-File -FilePath $partPath -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            throw "Syft failed for target $target with exit code $LASTEXITCODE"
        }
        $parts += $partPath
        $index++
    }

    if ($parts.Count -eq 1) {
        Move-Item -LiteralPath $parts[0] -Destination $OutputPath -Force
        return
    }

    $seen = @{}
    $components = New-Object System.Collections.Generic.List[object]

    foreach ($part in $parts) {
        $json = Get-Content -LiteralPath $part -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($component in @($json.components)) {
            $key = "{0}|{1}|{2}|{3}|{4}" -f $component.'bom-ref', $component.name, $component.version, $component.type, $component.purl
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $components.Add($component)
            }
        }
    }

    $merged = [ordered]@{
        bomFormat = "CycloneDX"
        specVersion = "1.5"
        version = 1
        metadata = [ordered]@{
            component = [ordered]@{
                type = "application"
                name = "eyemole-agent-scan"
            }
        }
        components = $components
    }

    $merged | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputPath -Encoding utf8

    foreach ($part in $parts) {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    }
}

function Send-Sbom {
    param(
        $Config,
        [string]$SbomPath,
        [string]$LogPath
    )

    $token = (Get-Content -LiteralPath $Config.TokenPath -Raw -Encoding UTF8).Trim()
    if (-not $token) {
        throw "Token file is empty: $($Config.TokenPath)"
    }

    $baseUrl = $Config.EyeMoleSoarUrl.TrimEnd("/")
    $uploadUrl = "$baseUrl/soar-api/sbom/$($Config.AgentId)"

    $curlArgs = @(
        "--fail",
        "--silent",
        "--show-error",
        "--connect-timeout", "10",
        "--max-time", "180",
        "--retry", "2",
        "--request", "POST",
        "--header", "Authorization: Bearer $token",
        "--header", "Content-Type: application/json",
        "--data-binary", "@$SbomPath"
    )

    if ($Config.PSObject.Properties.Name.Contains("CaCertPath") -and $Config.CaCertPath) {
        $curlArgs += @("--cacert", $Config.CaCertPath)
    }

    $curlArgs += $uploadUrl

    Write-AgentLog -Level "INFO" -Message "Uploading SBOM to $uploadUrl" -LogPath $LogPath
    & curl.exe @curlArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe failed with exit code $LASTEXITCODE"
    }
    Write-AgentLog -Level "INFO" -Message "SBOM upload accepted for agent $($Config.AgentId)" -LogPath $LogPath
}

$config = Read-AgentConfig -Path $ConfigPath
Assert-AgentConfig -Config $config

$rootDir = Split-Path -Parent $ConfigPath
$logDir = Join-Path $rootDir "logs"
$workDir = Join-Path $rootDir "work"
New-Item -ItemType Directory -Force -Path $logDir, $workDir | Out-Null

$logPath = Join-Path $logDir "sbom-upload.log"
$sbomPath = Join-Path $workDir ("sbom-{0}.json" -f ([guid]::NewGuid()))

try {
    New-Sbom -Config $config -OutputPath $sbomPath -LogPath $logPath
    Send-Sbom -Config $config -SbomPath $sbomPath -LogPath $logPath
}
catch {
    Write-AgentLog -Level "ERROR" -Message $_.Exception.Message -LogPath $logPath
    exit 1
}
finally {
    if (Test-Path -LiteralPath $sbomPath) {
        Remove-Item -LiteralPath $sbomPath -Force
    }
}
