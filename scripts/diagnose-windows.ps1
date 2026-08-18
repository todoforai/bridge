# TODOforAI Bridge - Windows diagnostic.
#
# Collects the facts needed to tell apart the failure modes that all look
# identical from the UI ("bridge signals issues"):
#
#   1. duplicate instances flap-looping (backend kicks each with close 4000)
#   2. antivirus / SmartScreen quarantining or blocking the binary
#   3. no bash on the box (bridge stays "online" but every RUN emits garbage,
#      because the RUN wrapper is bash syntax and the shell falls back to cmd.exe)
#
# Read-only: it reports and suggests, but never changes anything.
#
#   irm https://raw.githubusercontent.com/todoforai/bridge/main/scripts/diagnose-windows.ps1 | iex
#
# Or, if already downloaded:  powershell -ExecutionPolicy Bypass -File diagnose-windows.ps1
#
# Deliberately ASCII-only: Windows PowerShell 5.1 decodes a BOM-less script as
# the ANSI code page, so non-ASCII characters here would render as mojibake.

$ErrorActionPreference = 'Continue'

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Ok($m)      { Write-Host "  OK    $m" -ForegroundColor Green }
function Warn($m)    { Write-Host "  WARN  $m" -ForegroundColor Yellow }
function Bad($m)     { Write-Host "  FAIL  $m" -ForegroundColor Red }
function Info($m)    { Write-Host "  ...   $m" -ForegroundColor DarkGray }

Write-Host "TODOforAI Bridge - Windows diagnostic" -ForegroundColor White
Write-Host ("Host {0} | {1} | PS {2}" -f $env:COMPUTERNAME,
    (Get-CimInstance Win32_OperatingSystem).Caption, $PSVersionTable.PSVersion)

# ---- 1. Binary -------------------------------------------------------------
Section "1. Binary"
$exe = (Get-Command todoforai-bridge -ErrorAction SilentlyContinue).Source
if (-not $exe) {
    $cand = Join-Path $env:USERPROFILE '.todoforai\bin\todoforai-bridge.exe'
    if (Test-Path $cand -PathType Leaf) { $exe = $cand; Warn "not on PATH, found at $exe (open a new shell, or re-run the installer)" }
}
if (-not $exe) { Bad "todoforai-bridge.exe not found - is it installed?" }
else {
    Ok "path: $exe"
    $fi = Get-Item $exe
    Info ("size: {0:N0} bytes | modified: {1}" -f $fi.Length, $fi.LastWriteTime)

    try {
        $v  = (& $exe --version 2>&1 | Out-String).Trim()
        $rc = $LASTEXITCODE
        if ($rc -eq 0) { Ok "version: $v" }
        else {
            # Could be AV, a corrupt download, a missing system DLL, an arch
            # mismatch, or app-control policy - don't guess which.
            Bad "--version exited $rc : $v"
            Info "the binary did not run correctly - possible causes: AV block, corrupt"
            Info "download, unsupported Windows build, or application control policy"
        }
    } catch {
        Bad "could not execute the binary: $($_.Exception.Message)"
    }

    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -eq 'Valid') { Ok "signature: valid ($($sig.SignerCertificate.Subject))" }
    else { Warn "signature: $($sig.Status) - the binary is unsigned, so SmartScreen/AV may block it" }

    # Mark-of-the-Web: a downloaded file keeps this stream and SmartScreen gates it.
    if (Get-Item -Path $exe -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
        Warn "file carries Mark-of-the-Web (downloaded, not unblocked) - Unblock-File '$exe'"
    } else { Ok "no Mark-of-the-Web" }
}

# ---- 2. Duplicate instances (the flap loop) --------------------------------
Section "2. Running instances"
# Two processes only flap if they resolve to the same deviceId. That is a
# function of profile AND owning user (each user has its own credentials.json),
# and the profile can come from --profile/-P or be auto-selected as "dev" for a
# local --host. Report the evidence; only call it a flap when the profile and
# the user match, and even then say "likely" - the device id itself is not
# visible from here.
$procs = @(Get-Process todoforai-bridge -ErrorAction SilentlyContinue)
if ($procs.Count -eq 0) { Warn "no bridge process running" }
elseif ($procs.Count -eq 1) { Ok "exactly one instance (pid $($procs[0].Id), started $($procs[0].StartTime))" }
else {
    Warn "$($procs.Count) bridge processes running"
    $ids = @()
    foreach ($p in $procs) {
        $wp = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -EA SilentlyContinue
        $cl = $wp.CommandLine
        $owner = try { (Invoke-CimMethod -InputObject $wp -MethodName GetOwner -EA Stop) } catch { $null }
        $user  = if ($owner -and $owner.User) { "$($owner.Domain)\$($owner.User)" } else { '(unknown user)' }
        if (-not $cl) { $cl = '(command line unreadable - runs as another user or elevated)' }
        Info "pid $($p.Id) | $user | $cl"

        # Mirror main.c: explicit --profile/-P wins; otherwise a local --host
        # auto-selects the "dev" profile; otherwise "default".
        $prof = $null
        if     ($cl -match '(?:--profile[= ]|-P\s*)([^\s"]+)') { $prof = $Matches[1] }
        elseif ($cl -match '--host[= ]\s*("?)(localhost|::1|\[::1\]|127\.[\d.]+|10\.[\d.]+|192\.168\.[\d.]+|172\.(?:1[6-9]|2\d|3[01])\.[\d.]+)\1') { $prof = 'dev (auto, local --host)' }
        else   { $prof = 'default' }
        $ids += "$user/$prof"
    }
    $unique = @($ids | Sort-Object -Unique)
    if ($unique.Count -eq 1) {
        Bad "all of them are the same user + profile ($($unique[0])) => same deviceId => LIKELY FLAP LOOP"
        Info "each kicks the others off the backend (close code 4000) roughly every second"
        Info "fix: Stop-ScheduledTask -TaskName 'TODOforAI Bridge'; Stop-Process -Name todoforai-bridge -Force"
        Info "then start exactly ONE (the scheduled task, or a terminal - not both)"
    } else {
        Info "user/profile differs ($($unique -join ', ')) => probably separate devices, not a flap loop"
        Info "confirm by comparing deviceId per profile in section 6"
    }
}

Section "3. Autostart"
$task = Get-ScheduledTask -TaskName 'TODOforAI Bridge' -ErrorAction SilentlyContinue
if ($task) {
    Ok "scheduled task present, state: $($task.State)"
    $tinfo = Get-ScheduledTaskInfo -TaskName 'TODOforAI Bridge' -ErrorAction SilentlyContinue
    if ($tinfo) { Info "last run: $($tinfo.LastRunTime) | last result: 0x$('{0:X}' -f $tinfo.LastTaskResult) | missed: $($tinfo.NumberOfMissedRuns)" }
    if ($task.State -eq 'Running' -and $procs.Count -gt 1) {
        Warn "task is Running AND extra processes exist - likely a manual start on top of the task"
    }
} else { Info "no scheduled task (bridge started manually, or installed without -Service)" }

# ---- 4. Antivirus ----------------------------------------------------------
Section "4. Antivirus / Defender"
try {
    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
    foreach ($a in $av) { Info "installed AV: $($a.displayName)" }
    $thirdParty = @($av | Where-Object { $_.displayName -notmatch 'Microsoft Defender|Windows Defender' })
    if ($thirdParty.Count) {
        Warn "third-party AV present ($($thirdParty.displayName -join ', ')) - check its quarantine/logs too, not just Defender"
    }
} catch { Info "could not enumerate AV products" }

try {
    $threats = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending)
    $mine = @($threats | Where-Object { $_.Resources -match 'todoforai' })
    if ($mine.Count) {
        Bad "Defender has flagged the bridge:"
        $mine | Select-Object -First 5 | ForEach-Object {
            $name = (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName
            Info "$($_.InitialDetectionTime) | $name | $($_.Resources -join ', ')"
            Info "  ^ report this exact ThreatName as a false positive: https://www.microsoft.com/wdsi/filesubmission"
        }
    } else { Ok "no Defender detections mentioning todoforai" }

    $pref = Get-MpPreference -ErrorAction Stop
    $bin  = Join-Path $env:USERPROFILE '.todoforai\bin'
    if ($pref.ExclusionPath -contains $bin) { Ok "install dir is excluded from scanning" }
    else { Info "install dir not excluded (workaround if AV keeps eating it: Add-MpPreference -ExclusionPath '$bin')" }
} catch { Info "Defender cmdlets unavailable (a third-party AV may have replaced it)" }

# ---- 5. Shell (silent-breakage check) --------------------------------------
Section "5. Shell for RUN commands"
# pty_win.c resolution order: $BRIDGE_SHELL -> Git Bash -> bash.exe on PATH
# (never the System32 WSL stub) -> cmd.exe. Only a real bash makes RUN work.
#
# BRIDGE_SHELL is an OVERRIDE, not a preference: pty_win.c takes it verbatim and
# never falls through, so if it is set the discovery below is irrelevant to what
# the bridge actually spawns. Report the effective shell, then the fallback
# separately - conflating them would print "OK bash: ..." for a bridge that is
# in fact spawning a broken shell.
$isWslStub = { param($p) $p -like "$env:WINDIR\System32\*" }

$bash = $null   # what the bridge would find if BRIDGE_SHELL were unset
foreach ($p in @("C:\Program Files\Git\bin\bash.exe", "C:\Program Files (x86)\Git\bin\bash.exe")) {
    if (-not $bash -and (Test-Path $p -PathType Leaf)) { $bash = $p }
}
if (-not $bash) {
    $onPath = (Get-Command bash.exe -ErrorAction SilentlyContinue).Source
    if ($onPath -and -not (& $isWslStub $onPath)) { $bash = $onPath }
    elseif ($onPath) { Warn "the only bash on PATH is the WSL stub ($onPath) - the bridge correctly ignores it" }
}

if ($env:BRIDGE_SHELL) {
    Info "BRIDGE_SHELL is set, so it overrides discovery: $env:BRIDGE_SHELL"
    if (-not (Test-Path $env:BRIDGE_SHELL -PathType Leaf)) {
        Bad "effective shell does not exist - every RUN fails to spawn (clear BRIDGE_SHELL)"
    } elseif (& $isWslStub $env:BRIDGE_SHELL) {
        Bad "effective shell is the System32 WSL stub - not a usable shell for RUN (clear BRIDGE_SHELL)"
    } elseif ((Split-Path $env:BRIDGE_SHELL -Leaf) -notmatch '^bash(\.exe)?$') {
        Bad "effective shell is not bash - RUN wrappers are bash syntax, so output will be broken (clear BRIDGE_SHELL)"
    } else {
        Ok "effective shell: $env:BRIDGE_SHELL"
    }
    if ($bash) { Info "without BRIDGE_SHELL the bridge would use: $bash" }
} elseif ($bash) {
    Ok "effective shell: $bash"
} else {
    Bad "no bash found - bridge falls back to cmd.exe and EVERY RUN produces broken output"
    Info "fix: install Git for Windows (https://git-scm.com/download/win)"
}

# ---- 6. Credentials --------------------------------------------------------
# Before connectivity, so section 7 has a stored host to probe.
Section "6. Credentials"
$cred = Join-Path $env:APPDATA 'todoforai\credentials.json'
$backendHost = $null
$backendFrom = $null
if (Test-Path $cred -PathType Leaf) {
    Ok "present: $cred"
    try {
        $c = Get-Content $cred -Raw | ConvertFrom-Json
        # The default profile is flat at the top level; named ones live under "sets".
        $profilesToShow = @([pscustomobject]@{ Name = 'default'; Data = $c })
        if ($c.PSObject.Properties.Name -contains 'sets' -and $c.sets) {
            foreach ($n in $c.sets.PSObject.Properties.Name) {
                $profilesToShow += [pscustomobject]@{ Name = $n; Data = $c.sets.$n }
            }
        }
        foreach ($p in $profilesToShow) {
            $d = $p.Data
            if (-not $d.deviceId) { continue }   # empty default slot is normal when only named profiles exist
            $h = if ($d.backendHost) { $d.backendHost } else { 'api.todofor.ai (default)' }
            Info "profile '$($p.Name)': deviceId $($d.deviceId) | backendHost $h"
            if (-not $d.backendPubkey) {
                Bad "  profile '$($p.Name)' has no backendPubkey - run: todoforai-bridge logout; todoforai-bridge login"
            }
            if (-not $backendHost -and $d.backendHost) {
                $backendHost = $d.backendHost
                $backendFrom = $p.Name
            }
        }
        if (-not ($profilesToShow | Where-Object { $_.Data.deviceId })) {
            Warn "no profile contains a deviceId - run: todoforai-bridge login"
        }
    } catch { Bad "credentials.json is not valid JSON - re-run login" }
} else { Warn "no credentials at $cred - run: todoforai-bridge login" }

# ---- 7. Connectivity -------------------------------------------------------
# Best guess only: this is the first stored host, but a running bridge can point
# somewhere else via --host/--port, NOISE_BACKEND_HOST or BRIDGE_PORT (and a
# local host defaults to port 4000). Cross-check against the command lines in
# section 2 before concluding the network is at fault.
if (-not $backendHost) { $backendHost = 'api.todofor.ai'; $backendFrom = 'built-in default' }
Section "7. Connectivity to ${backendHost}:80 (from profile '$backendFrom')"
# The bridge speaks plain ws:// on port 80 and wraps everything in Noise, so a
# proxy or filter that expects readable HTTP on 80 can silently kill it.
$t = Test-NetConnection -ComputerName $backendHost -Port 80 -WarningAction SilentlyContinue
if ($t.TcpTestSucceeded) { Ok "TCP 80 reachable (remote $($t.RemoteAddress))" }
else {
    Bad "cannot reach ${backendHost}:80"
    Info "possible causes: DNS failure, routing, firewall, proxy, or a backend outage"
    if (-not $t.NameResolutionSucceeded) { Info "name resolution FAILED - this looks like DNS" }
}
if ($env:HTTP_PROXY -or $env:HTTPS_PROXY) {
    Warn "proxy env set (HTTP_PROXY=$env:HTTP_PROXY HTTPS_PROXY=$env:HTTPS_PROXY) - the bridge does NOT use it"
}
try {
    $fw = (Get-NetFirewallProfile -ErrorAction Stop | Where-Object Enabled).Name -join ', '
    if ($fw) { Info "firewall profiles enabled: $fw" }
} catch { }

Write-Host "`nDone. Paste this whole output back into the TODO." -ForegroundColor White
