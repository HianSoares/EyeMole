<#
.SYNOPSIS
  Wazuh 4.x Windows Active Response receiver: fixed READ-ONLY collection for EyeMole.

.DESCRIPTION
  Install/configure explicitly (see docs/AUTOMATIC_REMEDIATION.md); called by
  eyemole-collect.cmd. No free commands: the request is HMAC-SHA256 signed by
  the EyeMole worker over the exact payload text, bound to this agent,
  short-lived and single-use. Only these actions run, with validated
  parameters: windows_build (registry CurrentVersion), windows_hotfixes
  (Get-HotFix), wu_search (Windows Update Agent search, read-only),
  windows_feature (Get-WindowsFeature / Get-WindowsOptionalFeature).
  Outputs are uploaded with this agent's token to the URL configured locally.
  Nothing is installed or changed.
#>
$ErrorActionPreference = 'Stop'
$PolicyPath = Join-Path $env:ProgramData 'EyeMole\collector.json'
$StateDir = Join-Path $env:ProgramData 'EyeMole\collector-state'

function ConvertFrom-B64Url([string]$Text) {
    if ($Text -notmatch '^[A-Za-z0-9_-]{1,16000}$') { throw 'encoding' }
    $t = $Text.Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return [Convert]::FromBase64String($t)
}

function Test-Equal([string]$A, [string]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ([int][char]$A[$i] -bxor [int][char]$B[$i]) }
    return $diff -eq 0
}

function Confirm-Request([string]$Argument, $Policy) {
    $packet = [Text.Encoding]::UTF8.GetString((ConvertFrom-B64Url $Argument)) | ConvertFrom-Json
    if (-not $packet.p -or -not $packet.s) { throw 'packet_schema' }
    if ([string]$Policy.hmac_key -eq '' -or ([string]$Policy.hmac_key).Length -lt 32) { throw 'key' }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes([string]$Policy.hmac_key))
    $signature = -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$packet.p)) | ForEach-Object { $_.ToString('x2') })
    if (-not (Test-Equal $signature ([string]$packet.s))) { throw 'signature' }
    $payload = [Text.Encoding]::UTF8.GetString((ConvertFrom-B64Url ([string]$packet.p))) | ConvertFrom-Json
    if (-not $Policy.enabled -or [string]$payload.agent_id -ne [string]$Policy.agent_id -or [string]$payload.agent_id -eq '000') { throw 'agent_or_disabled' }
    if ([string]$payload.id -notmatch '^[a-f0-9]{32}$' -or [string]$payload.finding_id -notmatch '^[a-f0-9]{64}$') { throw 'id' }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($payload.issued_at -lt ($now - 300) -or $payload.issued_at -gt ($now + 30) -or $payload.expires_at -le $now -or $payload.expires_at -gt ($payload.issued_at + 3600)) { throw 'expired' }
    $actions = @($payload.actions)
    if ($actions.Count -lt 1 -or $actions.Count -gt 10) { throw 'actions' }
    foreach ($item in $actions) {
        switch ([string]$item.action) {
            'windows_build' { }
            'windows_hotfixes' { }
            'wu_search' { if ([string]$item.kb -notmatch '^KB\d{6,8}$') { throw 'parameters' } }
            'windows_feature' { if ([string]$item.name -notmatch '^[A-Za-z0-9-]{1,64}$') { throw 'parameters' } }
            default { throw 'action' }
        }
    }
    return $payload
}

function Invoke-ReadOnlyAction($Item) {
    switch ([string]$Item.action) {
        'windows_build' {
            $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            return (@{ ProductName = [string]$cv.ProductName; EditionID = [string]$cv.EditionID;
                       InstallationType = [string]$cv.InstallationType; CurrentBuild = [string]$cv.CurrentBuild;
                       UBR = [int]$cv.UBR; Architecture = [string]$env:PROCESSOR_ARCHITECTURE } | ConvertTo-Json -Compress)
        }
        'windows_hotfixes' {
            return (ConvertTo-Json -Compress -InputObject @(Get-HotFix | ForEach-Object { [string]$_.HotFixID }))
        }
        'wu_search' {
            $number = ([string]$Item.kb).Substring(2)
            $updates = @((New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'").Updates |
                         Where-Object { $_.KBArticleIDs -contains $number })
            return (@{ kb = [string]$Item.kb; offered = ($updates.Count -gt 0) } | ConvertTo-Json -Compress)
        }
        'windows_feature' {
            $name = [string]$Item.name
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                $feature = Get-WindowsFeature -Name $name
                return (@{ Name = [string]$feature.Name; InstallState = [string]$feature.InstallState } | ConvertTo-Json -Compress)
            }
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $name
            return (@{ Name = [string]$feature.FeatureName; State = [string]$feature.State } | ConvertTo-Json -Compress)
        }
    }
    throw 'action'
}

function Get-ActionKey($Item) {
    switch ([string]$Item.action) {
        'wu_search' { return 'wu_search:' + [string]$Item.kb }
        'windows_feature' { return 'windows_feature:' + [string]$Item.name }
        default { return [string]$Item.action }
    }
}

# Dot-sourcing (tests) only loads the functions above.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json
    $message = [Console]::In.ReadLine() | ConvertFrom-Json
    if ($message.command -ne 'add') { exit 0 }
    $arguments = @($message.parameters.extra_args)
    if ($arguments.Count -ne 1) { throw 'arguments' }
    $payload = Confirm-Request ([string]$arguments[0]) $policy
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $marker = Join-Path $StateDir ([string]$payload.id)
    if (Test-Path -LiteralPath $marker) { throw 'replay' }
    New-Item -ItemType File -Path $marker | Out-Null
    $results = @{}
    foreach ($item in @($payload.actions)) {
        try { $results[(Get-ActionKey $item)] = @{ ok = $true; output = (Invoke-ReadOnlyAction $item) } }
        catch { $results[(Get-ActionKey $item)] = @{ ok = $false; error = $_.Exception.GetType().Name } }
    }
    $url = [string]$policy.upload_url
    if ($url -notmatch '^https://[A-Za-z0-9.-]+(:\d{1,5})?/soar-api/agent-context/[0-9]{3,8}$' -or -not $url.EndsWith('/' + [string]$policy.agent_id)) { throw 'upload_url' }
    $token = (Get-Content -LiteralPath ([string]$policy.token_file) -Raw).Trim()
    $body = @{ request_id = [string]$payload.id; agent_id = [string]$payload.agent_id;
               collected_at = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssK'); results = $results } | ConvertTo-Json -Depth 5 -Compress
    Invoke-RestMethod -Method Post -Uri $url -Headers @{ Authorization = 'Bearer ' + $token } -ContentType 'application/json' -Body $body | Out-Null
    Write-Output (@{ eyemole_collection = [string]$payload.id; state = 'uploaded' } | ConvertTo-Json -Compress)
    exit 0
}
catch {
    # Never emit packet, policy, token or key material.
    Write-Output (@{ state = 'rejected'; reason = $_.Exception.Message.Split(' ')[0] } | ConvertTo-Json -Compress)
    exit 1
}
