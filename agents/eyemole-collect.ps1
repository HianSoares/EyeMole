<#
.SYNOPSIS
  Wazuh 4.x Windows Active Response receiver: fixed READ-ONLY collection for EyeMole.

.DESCRIPTION
  Install/configure explicitly (see docs/AUTOMATIC_REMEDIATION.md); called by
  eyemole-collect.cmd. No free commands: the request is HMAC-SHA256 signed by
  the EyeMole worker over the exact payload text, bound to this agent,
  short-lived and single-use. Only these actions run, with validated
  parameters: windows_build (registry CurrentVersion through the 64-bit view,
  native OS architecture), windows_hotfixes (Get-HotFix), wu_updates (Windows
  Update Agent search, read-only: UpdateID, KBs, CVE IDs, SupersededUpdateIDs of
  the updates offered by the configured channel for the CVE and listed KBs),
  windows_feature (Get-WindowsFeature / Get-WindowsOptionalFeature).
  Outputs are uploaded with this agent's token to the URL configured locally.
  Nothing is installed or changed.
#>
$ErrorActionPreference = 'Stop'

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
            'wu_updates' { if ([string]$item.cve -notmatch '^CVE-\d{4}-\d{4,7}$' -or [string]$item.kbs -notmatch '^KB\d{6,8}(,KB\d{6,8}){0,9}$') { throw 'parameters' } }
            'windows_feature' { if ([string]$item.name -notmatch '^[A-Za-z0-9-]{1,64}$') { throw 'parameters' } }
            default { throw 'action' }
        }
    }
    return $payload
}

function Get-EyeMoleOSArchitecture {
    # Native OS architecture, also from a 32-bit process on 64-bit Windows (WOW64) and on ARM64.
    try {
        $value = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        if ($value) { return $value }
    } catch { }
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::Registry64)
    $key = $registry.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
    $value = if ($key) { [string]$key.GetValue('PROCESSOR_ARCHITECTURE') } else { '' }
    if ($value) { return $value }
    if ($env:PROCESSOR_ARCHITEW6432) { return [string]$env:PROCESSOR_ARCHITEW6432 }
    return [string]$env:PROCESSOR_ARCHITECTURE
}

function Get-EyeMoleWindowsBuild {
    # 64-bit registry view: a 32-bit process would otherwise read the WOW6432Node copy.
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::Registry64)
    $cv = $registry.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
    if (-not $cv) { throw 'registry' }
    $process = if ([Environment]::Is64BitProcess) { 'X64' } else { 'X86' }
    try { $process = [string][System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture } catch { }
    return (@{ ProductName = [string]$cv.GetValue('ProductName'); EditionID = [string]$cv.GetValue('EditionID');
               InstallationType = [string]$cv.GetValue('InstallationType'); CurrentBuild = [string]$cv.GetValue('CurrentBuild');
               UBR = [int]$cv.GetValue('UBR'); Architecture = (Get-EyeMoleOSArchitecture);
               ProcessArchitecture = $process; Is64BitProcess = [Environment]::Is64BitProcess } | ConvertTo-Json -Compress)
}

function Get-EyeMoleChannelUpdates($Item) {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $searcher.IncludePotentiallySupersededUpdates = $true
    $all = @($searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates)
    $wanted = @(([string]$Item.kbs).Split(',') | ForEach-Object { $_.Substring(2) })
    $cve = [string]$Item.cve
    $covered = @{}
    foreach ($u in $all) {
        if ((@($u.KBArticleIDs) | Where-Object { $wanted -contains $_ }) -or (@($u.CveIDs) -contains $cve)) { $covered[[string]$u.Identity.UpdateID] = $u }
    }
    for ($round = 0; $round -lt 5; $round++) {  # successors reaching a listed update through SupersededUpdateIDs
        foreach ($u in $all) {
            $id = [string]$u.Identity.UpdateID
            if (-not $covered.ContainsKey($id) -and (@($u.SupersededUpdateIDs) | Where-Object { $covered.ContainsKey([string]$_) })) { $covered[$id] = $u }
        }
    }
    $updates = @($covered.Values | Select-Object -First 50 | ForEach-Object {
        @{ update_id = [string]$_.Identity.UpdateID; title = [string]$_.Title; kb_ids = @($_.KBArticleIDs | ForEach-Object { [string]$_ });
           cve_ids = @($_.CveIDs | ForEach-Object { [string]$_ }); superseded_update_ids = @($_.SupersededUpdateIDs | ForEach-Object { [string]$_ });
           is_downloaded = [bool]$_.IsDownloaded; eula_accepted = [bool]$_.EulaAccepted } })
    return (@{ cve = $cve; kbs = @(([string]$Item.kbs).Split(',')); updates = $updates } | ConvertTo-Json -Compress -Depth 5)
}

function Invoke-ReadOnlyAction($Item) {
    switch ([string]$Item.action) {
        'windows_build' { return (Get-EyeMoleWindowsBuild) }
        'windows_hotfixes' {
            return (ConvertTo-Json -Compress -InputObject @(Get-HotFix | ForEach-Object { [string]$_.HotFixID }))
        }
        'wu_updates' { return (Get-EyeMoleChannelUpdates $Item) }
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
        'wu_updates' { return 'wu_updates:' + [string]$Item.cve }
        'windows_feature' { return 'windows_feature:' + [string]$Item.name }
        default { return [string]$Item.action }
    }
}

# Dot-sourcing (tests) only loads the functions above.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $PolicyPath = Join-Path $env:ProgramData 'EyeMole\collector.json'
    $StateDir = Join-Path $env:ProgramData 'EyeMole\collector-state'
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
