# TODOforAI Bridge installer (Windows). Run with -h for usage.
# Env overrides: TODOFORAI_PREFIX, TODOFORAI_TAG.
#
#   irm https://todofor.ai/bridge.ps1 | iex
#   iex "& { $(irm https://todofor.ai/bridge.ps1) } -Token ENROLL_TOKEN"
#   iex "& { $(irm https://todofor.ai/bridge.ps1) } -Name host-02"

[CmdletBinding()]
param(
    [string]$Token = "",
    [string]$Name = "",
    [string]$Prefix = "",
    [string]$Tag = "",
    [switch]$Service,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

$Repo = 'todoforai/bridge'
if (-not $Prefix) { $Prefix = $env:TODOFORAI_PREFIX }
if (-not $Prefix) { $Prefix = Join-Path $env:USERPROFILE '.todoforai\bin' }
if (-not $Tag)    { $Tag    = $env:TODOFORAI_TAG }

function Die($msg)  { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host ":: $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "✓ $msg"  -ForegroundColor Green }

if ($Help) {
    @"
TODOforAI Bridge installer (Windows).

  irm https://todofor.ai/bridge.ps1 | iex
  iex "& { $(irm https://todofor.ai/bridge.ps1) } -Token ENROLL_TOKEN"
  iex "& { $(irm https://todofor.ai/bridge.ps1) } -Name host-02"

Options:
  -Token TOKEN     enrollment token (printed in the suggested start command)
  -Name NAME       device name to register under
  -Prefix DIR      install dir (default: %USERPROFILE%\.todoforai\bin)
  -Tag TAG         specific release tag (default: latest)
  -Service         install Scheduled Task so bridge auto-starts at logon
  -Help            show this help
"@ | Write-Host
    exit 0
}

# ── detect arch ─────────────────────────────────────────────────────────────
$pa = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($pa) {
    'AMD64' { 'x64' }
    'ARM64' { 'arm64' }
    default { Die "unsupported arch: $pa" }
}
$asset = "todoforai-bridge-windows-$arch.exe"

# ── resolve release tag (default: latest) ───────────────────────────────────
if (-not $Tag) {
    # Resolve latest via the github.com redirect (not the rate-limited
    # api.github.com, which 403s after 60 req/hr per IP):
    #   /releases/latest → 302 → /releases/tag/<TAG>
    # HttpWebRequest with AllowAutoRedirect=$false returns the 302 as a normal
    # response on both Windows PowerShell 5.1 and PowerShell 7. (Invoke-WebRequest
    # -MaximumRedirection 0 instead *throws* on 5.1, so it can't be used here.)
    $location = $null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $req = [Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
        $req.AllowAutoRedirect = $false
        $req.Method = 'HEAD'
        $req.UserAgent = 'todoforai-bridge-installer'
        $resp = $req.GetResponse()
        $location = $resp.Headers['Location']
        $resp.Close()
    } catch [Net.WebException] {
        if ($_.Exception.Response) {
            $location = $_.Exception.Response.Headers['Location']
            $_.Exception.Response.Close()
        }
    } catch { }

    # Only accept a real .../releases/tag/<TAG> redirect; anything else (error
    # page, login interstitial) must not be mistaken for a version string.
    $expected = "https://github.com/$Repo/releases/tag/"
    if ($location -and $location.StartsWith($expected)) {
        $Tag = $location.Substring($expected.Length)
    }
    if (-not $Tag) { Die "could not determine latest release (see https://github.com/$Repo/releases)" }
}
$url    = "https://github.com/$Repo/releases/download/$Tag/$asset"
$shaUrl = "$url.sha256"

# ── download + verify ───────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("todoforai-bridge-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $bin    = Join-Path $tmp 'todoforai-bridge.exe'
    $shaTxt = Join-Path $tmp 'todoforai-bridge.sha'
    try { Invoke-WebRequest -UseBasicParsing -Uri $url    -OutFile $bin    } catch { Die "download failed: $url" }
    try { Invoke-WebRequest -UseBasicParsing -Uri $shaUrl -OutFile $shaTxt } catch { Die "checksum fetch failed: $shaUrl" }

    $expected = ((Get-Content $shaTxt -Raw).Trim() -split '\s+')[0]
    $actual   = (Get-FileHash $bin -Algorithm SHA256).Hash.ToLower()
    if ($expected.ToLower() -ne $actual) { Die "sha256 mismatch: expected $expected, got $actual" }

    $size = (Get-Item $bin).Length
    $human = if     ($size -ge 1GB) { "{0:N1} GiB" -f ($size/1GB) }
             elseif ($size -ge 1MB) { "{0:N1} MiB" -f ($size/1MB) }
             elseif ($size -ge 1KB) { "{0:N1} KiB" -f ($size/1KB) }
             else                   { "$size B" }
    Ok "downloaded $asset $Tag ($human)"

    $dest = Join-Path $Prefix 'todoforai-bridge.exe'
    # stop existing task if present so we can overwrite a running exe
    Get-ScheduledTask -TaskName 'TODOforAI Bridge' -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
    Move-Item -Force $bin $dest
    # `tfa-bridge` alias alongside `todoforai-bridge` (no symlink privilege needed).
    Copy-Item -Force $dest (Join-Path $Prefix 'tfa-bridge.exe')
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ── shell provisioning (busybox) ────────────────────────────────────────────
# RUN commands require a POSIX shell. If neither Git Bash nor a provisioned
# shell exists, pre-download the pinned busybox-w32 the bridge would otherwise
# fetch on first use (same asset, same canonical path, same sha256 pin as in
# bridge pty_win.c).
$shellDir  = Join-Path $env:USERPROFILE '.todoforai\shell'
$shellExe  = Join-Path $shellDir 'sh.exe'
$gitBash   = @("$env:ProgramFiles\Git\bin\bash.exe", "${env:ProgramFiles(x86)}\Git\bin\bash.exe") |
             Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $gitBash -and -not (Test-Path $shellExe)) {
    $shellUrl = 'https://github.com/todoforai/bridge/releases/download/shell-busybox-FRP-6075/busybox-w64u.exe'
    $shellSha = '6E263D154D8548D1EB936F65D1D8312C80DF31C45974E48D6335E4DCC0F4F34C'
    try {
        New-Item -ItemType Directory -Force -Path $shellDir | Out-Null
        $part = "$shellExe.$PID.part"
        Invoke-WebRequest -UseBasicParsing -Uri $shellUrl -OutFile $part
        if ((Get-FileHash $part -Algorithm SHA256).Hash -eq $shellSha) {
            Move-Item -Force $part $shellExe
            Ok "provisioned minimal shell (busybox) -> $shellExe"
        } else {
            Remove-Item -Force $part
            Info "shell download hash mismatch - the bridge will retry at runtime"
        }
    } catch {
        Info "could not pre-provision shell ($($_.Exception.Message)) - the bridge will retry at runtime"
    }
}

$Bridge = Join-Path $Prefix 'todoforai-bridge.exe'
$Cmd    = $Bridge
$Where  = $Bridge
$Hint   = ""

# ── PATH setup (user PATH) ──────────────────────────────────────────────────
$pathParts = ($env:Path -split ';') | Where-Object { $_ }
if ($pathParts -contains $Prefix) {
    $Cmd = 'todoforai-bridge'
} else {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $userParts = if ($userPath) { ($userPath -split ';') | Where-Object { $_ } } else { @() }
    if (-not ($userParts -contains $Prefix)) {
        $newUserPath = if ($userPath) { "$userPath;$Prefix" } else { $Prefix }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        $Where = "$Bridge, added to user PATH"
        $Hint  = " (open a new shell to pick up PATH)"
    }
    $env:Path = "$env:Path;$Prefix"
    $Cmd = 'todoforai-bridge'
}
Ok "installed $Where$Hint"

# ── next step ───────────────────────────────────────────────────────────────
# `todoforai-bridge` auto-launches login on first run (interactive or via
# --token), then runs the agent in the same process.
$nextCmd = $Cmd
if ($Token -or $Name) {
    $nextCmd = "$nextCmd login"
    if ($Token) { $nextCmd = "$nextCmd --token $Token" }
    if ($Name)  { $nextCmd = "$nextCmd --device-name $Name" }
}
Write-Host ""
Write-Host "  Start the bridge:"
Write-Host ""
Write-Host "      $ " -NoNewline -ForegroundColor Cyan
Write-Host $nextCmd -ForegroundColor Green
Write-Host ""

# ── supervisor setup (Scheduled Task at logon) ──────────────────────────────
if ($Service) {
    try {
        $taskName = 'TODOforAI Bridge'
        $action   = New-ScheduledTaskAction   -Execute $Bridge
        $trigger  = New-ScheduledTaskTrigger  -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -StartWhenAvailable -RestartInterval (New-TimeSpan -Seconds 5) -RestartCount 9999 `
                        -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Ok "scheduled task '$taskName' registered and started"
    } catch {
        Info "could not register scheduled task ($($_.Exception.Message)); run manually: Start-Process -WindowStyle Hidden $Bridge"
    }
}
