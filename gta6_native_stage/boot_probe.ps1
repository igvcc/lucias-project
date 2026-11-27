<#
.SYNOPSIS
    LUCIAS PROJECT — Runs a controlled, memory-capped (10.5 GiB Job Object) and time-capped (20s)
    Win32 debug/VEH boot probe for E:\LUCIAS_PROJECT\LuciasProject.exe.
#>
[CmdletBinding()]
param(
    [string]$StageDir = "E:\LUCIAS_PROJECT",
    [string]$CliArgs = "",
    [int]$TimeoutMs = 20000,
    [int]$MemLimitMb = 10752,
    [switch]$D3D12Debug,
    [switch]$SkipVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($TimeoutMs -gt 540000 -or $TimeoutMs -lt 500) {
    throw "Safety rule: TimeoutMs must be between 500 and 540000 (got $TimeoutMs)"
}
if ($MemLimitMb -gt 12288 -or $MemLimitMb -lt 256) {
    throw "Safety rule: MemLimitMb must be between 256 and 12288 (got $MemLimitMb)"
}

# 1. Ensure no leftover LuciasProject.exe or GTA6_PC.exe is running (only if -KillStray is desired; Job Object kills our own child)
foreach ($procName in @("LuciasProject", "GTA6_PC")) {
    $stray = Get-Process -Name $procName -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($StageDir, [System.StringComparison]::OrdinalIgnoreCase) }
    if ($stray) {
        Write-Warning "Killing stray $procName.exe in $StageDir before probe..."
        $stray | Stop-Process -Force
    }
}

# 2. Verify staging integrity first unless skipped
$stageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $SkipVerify) {
    $verifyScript = Join-Path $stageRoot "verify_native_stage.ps1"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $verifyScript -StageDir $StageDir
    if ($LASTEXITCODE -ne 0) {
        throw "verify_native_stage.ps1 failed; aborting boot probe."
    }
}

# 3. Prepare log directory & archive previous shim_trace.log / telemetry_latest.json
$logDir = Join-Path $StageDir "logs"
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$shimLog = Join-Path $logDir "shim_trace.log"
$telemetryJson = Join-Path $logDir "telemetry_latest.json"
if ((Test-Path -LiteralPath $shimLog) -or (Test-Path -LiteralPath $telemetryJson)) {
    $archDir = Join-Path $logDir ("archive\" + (Get-Date -Format "yyyyMMdd_HHmmss"))
    New-Item -ItemType Directory -Path $archDir -Force | Out-Null
    if (Test-Path -LiteralPath $shimLog) { Move-Item -LiteralPath $shimLog -Destination (Join-Path $archDir "shim_trace.log") -Force }
    if (Test-Path -LiteralPath $telemetryJson) { Move-Item -LiteralPath $telemetryJson -Destination (Join-Path $archDir "telemetry_latest.json") -Force }
}

# 4. Ensure gta6_boot_probe.exe is built
$probeDir = Join-Path $stageRoot "boot_probe"
$probeExe = Join-Path $probeDir "target\release\gta6_boot_probe.exe"
if (-not (Test-Path -LiteralPath $probeExe)) {
    Push-Location $probeDir
    try {
        & cargo build --release --offline
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build gta6_boot_probe.exe"
        }
    } finally {
        Pop-Location
    }
}

# 5. Execute bounded boot probe
$targetExe = Join-Path $StageDir "LuciasProject.exe"
Write-Host "LUCIAS PROJECT: Launching bounded boot probe: $targetExe (timeout=${TimeoutMs}ms, mem_cap=${MemLimitMb}MiB, res=1920x1080)..."
$probeArgs = @(
    "--exe", $targetExe,
    "--cwd", $StageDir,
    "--timeout-ms", $TimeoutMs,
    "--mem-limit-mb", $MemLimitMb,
    "--log-dir", $logDir,
    "--shim-log", $shimLog
)
if ($CliArgs) {
    $probeArgs += @("--args", $CliArgs)
}
if ($D3D12Debug) {
    $probeArgs += "--d3d12-debug"
}
& $probeExe @probeArgs
$probeRc = $LASTEXITCODE

# 6. Guarantee zero stray processes remain
foreach ($procName in @("LuciasProject", "GTA6_PC")) {
    $strayAfter = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($strayAfter) {
        Write-Warning "Stray $procName.exe detected post-probe; force stopping!"
        $strayAfter | Stop-Process -Force
    }
}

# 7. Print summary & logs
$reportTxt = Join-Path $logDir "boot_probe_latest.txt"
if (Test-Path -LiteralPath $reportTxt) {
    Write-Host "`n=== boot_probe_latest.txt ==="
    Get-Content -LiteralPath $reportTxt
}
if (Test-Path -LiteralPath $telemetryJson) {
    Write-Host "`n=== telemetry_latest.json ==="
    Get-Content -LiteralPath $telemetryJson
} else {
    Write-Host "`n=== telemetry_latest.json: NOT CREATED ==="
}
if (Test-Path -LiteralPath $shimLog) {
    $lines = @(Get-Content -LiteralPath $shimLog)
    Write-Host "`n=== shim_trace.log ($($lines.Count) lines) ==="
    if ($lines.Count -le 80) {
        $lines | ForEach-Object { Write-Host $_ }
    } else {
        $lines[0..39] | ForEach-Object { Write-Host $_ }
        Write-Host "... ($($lines.Count - 80) lines omitted) ..."
        $lines[($lines.Count - 40)..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
    }
} else {
    Write-Host "`n=== shim_trace.log: NOT CREATED ==="
}

exit $probeRc
