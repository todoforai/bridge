# TODOforAI Bridge installer (Windows). Run with -h for usage.
# Env overrides: TODOFORAI_PREFIX, TODOFORAI_TAG.
#
#   irm https://todofor.ai/bridge.ps1 | iex
#   iex "& { $(irm https://todofor.ai/bridge.ps1) } -Token ENROLL_TOKEN"
#   iex "& { $(irm https://todofor.ai/bridge.ps1) } -Token TOK -Name host-02"

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
  iex "& { $(irm https://todofor.ai/bridge.ps1) } -Token TOK -Name host-02"

Options:
  -Token TOKEN     redeem an enrollment token (non-interactive login)
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
    try {
        $Tag = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
    } catch { Die "could not determine latest release (see https://github.com/$Repo/releases)" }
    if (-not $Tag) { Die "could not determine latest release" }
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
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
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

# ── login ───────────────────────────────────────────────────────────────────
if ($Token) {
    Info "redeeming enrollment token"
    if ($Name) {
        & $Bridge login --token $Token --device-name $Name
    } else {
        & $Bridge login --token $Token
    }
    if ($LASTEXITCODE -ne 0) { Die "enrollment failed" }
    Ok "enrolled"
} else {
    Write-Host "→ next: $Cmd login" -ForegroundColor Cyan
}

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
