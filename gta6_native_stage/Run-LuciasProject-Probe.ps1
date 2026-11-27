<#
.SYNOPSIS
    LUCIAS PROJECT — Convenience launcher for bounded staging verification and 20s boot probe.
#>
[CmdletBinding()]
param(
    [int]$TimeoutMs = 20000,
    [int]$MemLimitMb = 10752,
    [string]$CliArgs = "",
    [switch]$D3D12Debug,
    [switch]$Restage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Restage) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here "stage_native_pc.ps1")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$bpArgs = @("-TimeoutMs", $TimeoutMs, "-MemLimitMb", $MemLimitMb)
if ($CliArgs) { $bpArgs += @("-CliArgs", $CliArgs) }
if ($D3D12Debug) { $bpArgs += "-D3D12Debug" }
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here "boot_probe.ps1") @bpArgs
exit $LASTEXITCODE
