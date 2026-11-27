<#
.SYNOPSIS
    LUCIAS PROJECT — Stages the 100% native Win64 PC layout into E:\LUCIAS_PROJECT\
    and junctions E:\GTA6_PC -> E:\LUCIAS_PROJECT (zero duplicate bytes).
.DESCRIPTION
    - Strictly read-only on S:\gta\Gta6fordevelopersacces\ and E:\gta_mirror\.
    - Never writes large files to C:.
    - Never launches LuciasProject.exe.
#>
[CmdletBinding()]
param(
    [string]$StageDir = "E:\LUCIAS_PROJECT",
    [string]$LegacyJunctionDir = "E:\GTA6_PC",
    [string]$SourceDir = "S:\gta\Gta6fordevelopersacces",
    [string]$MirrorDir = "E:\gta_mirror",
    [string]$CacheDir = "V:\LUCIAS_PROJECT_Cache",
    [string]$ShimsOutDir = "c:\pulpit\xx\gta6_native_shims\out",
    [string]$PatcherExe = "",
    [bool]$HookVfs = $true,
    [switch]$AllowPartialCache
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PatcherBinary {
    param([string]$ExplicitPath)
    if ($ExplicitPath -and (Test-Path $ExplicitPath)) {
        return (Resolve-Path $ExplicitPath).Path
    }
    $candidates = @(
        "c:\pulpit\xx\gta6_native_shims\target\release\pe_native_patcher.exe",
        "c:\pulpit\xx\gta6_native_shims\target\debug\pe_native_patcher.exe",
        "c:\pulpit\xx\gta6_native_patcher\target\release\pe_native_patcher.exe",
        "c:\pulpit\xx\gta6_native_patcher\target\debug\pe_native_patcher.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            return (Resolve-Path $cand).Path
        }
    }
    throw "Cannot locate pe_native_patcher.exe in target\release or target\debug."
}

function Remove-ReparsePointSafe {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            if ($item.PSIsContainer) {
                [System.IO.Directory]::Delete($Path)
            } else {
                [System.IO.File]::Delete($Path)
            }
        }
    }
}

function Set-DirectoryJunction {
    param(
        [string]$LinkPath,
        [string]$TargetPath
    )
    if (-not (Test-Path -LiteralPath $TargetPath)) {
        throw "Junction target missing: $TargetPath"
    }
    if (Test-Path -LiteralPath $LinkPath) {
        $existing = Get-Item -LiteralPath $LinkPath -Force
        if ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            $normTarget = [System.IO.Path]::GetFullPath($TargetPath).TrimEnd('\')
            $existingTargets = @($existing.Target) | ForEach-Object {
                if ($_) { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }
            }
            if ($existingTargets -contains $normTarget) {
                return "existing"
            }
            [System.IO.Directory]::Delete($LinkPath)
        } else {
            throw "Refusing to overwrite non-junction directory at $LinkPath"
        }
    }
    New-Item -ItemType Junction -Path $LinkPath -Target $TargetPath | Out-Null
    return "created"
}

$AddTypeSrc = @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class LuciasStageWin32 {
    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        IntPtr hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("imagehlp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint MapFileAndCheckSumW(
        string Filename, out uint HeaderSum, out uint CheckSum);

    public static ulong[] GetFileIdAndLinks(string path) {
        IntPtr h = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (h == new IntPtr(-1)) {
            throw new IOException("CreateFileW failed for " + path + " err=" + Marshal.GetLastWin32Error());
        }
        try {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) {
                throw new IOException("GetFileInformationByHandle failed for " + path + " err=" + Marshal.GetLastWin32Error());
            }
            ulong fileId = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            return new ulong[] { info.VolumeSerialNumber, fileId, info.NumberOfLinks };
        } finally {
            CloseHandle(h);
        }
    }

    public static uint[] VerifyPeChecksum(string path) {
        uint hdrSum = 0, calcSum = 0;
        uint rc = MapFileAndCheckSumW(path, out hdrSum, out calcSum);
        return new uint[] { rc, hdrSum, calcSum };
    }
}
"@
if (-not ("LuciasStageWin32" -as [type])) {
    Add-Type -TypeDefinition $AddTypeSrc
}

Write-Host "=== LUCIAS PROJECT Native Staging ==="

# --- Safety Pre-flight ---
$stageRootDrive = [System.IO.Path]::GetPathRoot($StageDir).TrimEnd('\')
if ($stageRootDrive -ieq "C:") {
    throw "Safety rule violation: StageDir must NOT be on C: ($StageDir)"
}
$sourceExe = Join-Path $SourceDir "game_scarlett_master.exe"
if (-not (Test-Path -LiteralPath $sourceExe)) {
    throw "Source executable not found: $sourceExe"
}
if (-not (Test-Path -LiteralPath $MirrorDir)) {
    throw "Mirror directory not found: $MirrorDir"
}
if (-not (Test-Path -LiteralPath $CacheDir)) {
    $fallbackCache = "V:\GTA6_PC_Cache"
    if ($AllowPartialCache -and (Test-Path -LiteralPath $fallbackCache)) {
        Write-Warning "$CacheDir not found yet; using $fallbackCache because -AllowPartialCache was set."
        $CacheDir = $fallbackCache
    } elseif (-not $AllowPartialCache) {
        throw "Cache directory not found: $CacheDir (wait for @m2a or pass -AllowPartialCache)"
    }
}

$eDriveBefore = (Get-PSDrive E).Free
$cDriveBefore = (Get-PSDrive C).Free
Write-Host ("Pre-flight free space -> E: {0:N3} GiB | C: {1:N3} GiB" -f ($eDriveBefore / 1GB), ($cDriveBefore / 1GB))

# --- Migrate legacy E:\GTA6_PC\ safely if it is a real directory ---
if ($LegacyJunctionDir -and ($LegacyJunctionDir -ne $StageDir) -and (Test-Path -LiteralPath $LegacyJunctionDir)) {
    $legItem = Get-Item -LiteralPath $LegacyJunctionDir -Force
    if (-not ($legItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Write-Host "[migrate] Removing old E:\GTA6_PC directory safely (junctions unlinked without touching S:/V:, mirror hardlinks stay intact)..."
        # Unlink any directory junctions inside legacy dir BEFORE removing directory
        foreach ($sub in Get-ChildItem -LiteralPath $LegacyJunctionDir -Force) {
            if ($sub.PSIsContainer -and ($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                [System.IO.Directory]::Delete($sub.FullName)
            }
        }
        Remove-Item -LiteralPath $LegacyJunctionDir -Recurse -Force
    }
}

# --- (a) Create E:\LUCIAS_PROJECT\ ---
if (-not (Test-Path -LiteralPath $StageDir)) {
    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
}
foreach ($localDir in @("overlay", "logs")) {
    $p = Join-Path $StageDir $localDir
    if (-not (Test-Path -LiteralPath $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
}
Write-Host "[a] Stage directory ready: $StageDir"

# --- (b) Run pe_native_patcher.exe (dry-run + patch + verify) -> LuciasProject.exe ---
$patcher = Resolve-PatcherBinary -ExplicitPath $PatcherExe
Write-Host "[b] Using patcher: $patcher"

$dryArgs = @("patch", "--input", $sourceExe, "--dry-run")
if ($HookVfs) { $dryArgs += "--hook-vfs" }
$dryJsonRaw = & $patcher @dryArgs
if ($LASTEXITCODE -ne 0) {
    throw "pe_native_patcher dry-run failed with exit code $LASTEXITCODE"
}
$dryReport = $dryJsonRaw | ConvertFrom-Json
if (-not $dryReport.integrity_verified) {
    throw "pe_native_patcher dry-run reported integrity_verified = false"
}
$expectedRemappedDlls = if ($HookVfs) { 14 } else { 12 }
if ($dryReport.remapped_dlls.Count -lt $expectedRemappedDlls) {
    throw "Unexpected dry-run remapped DLL count: $($dryReport.remapped_dlls.Count) (expected >= $expectedRemappedDlls)"
}
Write-Host "[b1] Dry-run validated: $($dryReport.remapped_dlls.Count) DLLs, $($dryReport.total_remapped_imports) imports, added_section=$($dryReport.added_section)"

$targetExe = Join-Path $StageDir "LuciasProject.exe"
$patchArgs = @("patch", "--input", $sourceExe, "--output", $targetExe)
if ($HookVfs) { $patchArgs += "--hook-vfs" }
$patchJsonRaw = & $patcher @patchArgs
if ($LASTEXITCODE -ne 0) {
    throw "pe_native_patcher patch failed with exit code $LASTEXITCODE"
}
$patchReport = $patchJsonRaw | ConvertFrom-Json
if (-not $patchReport.integrity_verified -or $patchReport.new_subsystem -ne 2) {
    throw "Patch verification failed on $targetExe"
}
Write-Host ("[b2] Patched LuciasProject.exe ({0:N2} MiB, subsystem={1}, checksum=0x{2:X8})" -f ($patchReport.patched_size / 1MB), $patchReport.new_subsystem, $patchReport.new_checksum)

$verifyArgs = @("verify", "--original", $sourceExe, "--patched", $targetExe)
if ($HookVfs) { $verifyArgs += "--hook-vfs" }
$verifyJsonRaw = & $patcher @verifyArgs
if ($LASTEXITCODE -ne 0) {
    throw "pe_native_patcher verify failed on $targetExe (exit $LASTEXITCODE)"
}
$analysis = $verifyJsonRaw | ConvertFrom-Json
$xbldCount = @($analysis.sections | Where-Object { $_.name -eq ".xbld" }).Count
if ($analysis.sections.Count -lt 10 -or $xbldCount -ne 2 -or $analysis.tls_callbacks.Count -ne 2) {
    throw "Post-patch PE analysis check failed: sections=$($analysis.sections.Count), xbld=$xbldCount, tls_callbacks=$($analysis.tls_callbacks.Count)"
}
$chk = [LuciasStageWin32]::VerifyPeChecksum($targetExe)
if ($chk[0] -ne 0 -or $chk[1] -eq 0 -or $chk[1] -ne $chk[2]) {
    throw "PE checksum verification failed: rc=$($chk[0]) header=0x$($chk[1].ToString('X8')) calc=0x$($chk[2].ToString('X8'))"
}
Write-Host ("[b3] Verify mode OK: {0} sections (2x .xbld), {1} TLS callbacks, PE checksum 0x{2:X8} verified" -f $analysis.sections.Count, $analysis.tls_callbacks.Count, $chk[2])

# --- (c) Copy all 14 Win64 DLLs from out\ -> E:\LUCIAS_PROJECT\ ---
$expectedShimDlls = @(
    "xmem_pc.dll",
    "xcrd_pc.dll",
    "ffx_pc.dll",
    "dx12xs_pc.dll",
    "xg_pc.dll",
    "xbvh_pc.dll",
    "chad_pc.dll",
    "audio_pc.dll",
    "bink2_pc.dll",
    "hc_pc.dll",
    "gi_pc.dll",
    "GameInput.dll",
    "vfs_pc.dll",
    "xgameruntime.dll"
)
foreach ($dll in $expectedShimDlls) {
    $srcDll = Join-Path $ShimsOutDir $dll
    if (-not (Test-Path -LiteralPath $srcDll)) {
        throw "Missing required Win64 shim DLL in $ShimsOutDir`: $dll"
    }
    $dstDll = Join-Path $StageDir $dll
    Copy-Item -LiteralPath $srcDll -Destination $dstDll -Force
}
Write-Host "[c] Copied all $($expectedShimDlls.Count) Win64 shim DLLs from $ShimsOutDir -> $StageDir"

# --- (d) Create NTFS hardlinks for 6 large .rpf files from E:\gta_mirror\ ---
$largeRpfs = @("anim.rpf", "audio.rpf", "levels.rpf", "movies.rpf", "navmeshes.rpf", "packs.rpf")
foreach ($rpf in $largeRpfs) {
    $srcRpf = Join-Path $MirrorDir $rpf
    $dstRpf = Join-Path $StageDir $rpf
    if (-not (Test-Path -LiteralPath $srcRpf)) {
        throw "Missing mirror RPF: $srcRpf"
    }
    $srcInfo = [LuciasStageWin32]::GetFileIdAndLinks($srcRpf)
    $needsLink = $true
    if (Test-Path -LiteralPath $dstRpf) {
        $dstInfo = [LuciasStageWin32]::GetFileIdAndLinks($dstRpf)
        if ($srcInfo[0] -eq $dstInfo[0] -and $srcInfo[1] -eq $dstInfo[1]) {
            $needsLink = $false
        } else {
            Remove-Item -LiteralPath $dstRpf -Force
        }
    }
    if ($needsLink) {
        New-Item -ItemType HardLink -Path $dstRpf -Target $srcRpf | Out-Null
    }
    $verifyInfo = [LuciasStageWin32]::GetFileIdAndLinks($dstRpf)
    if ($verifyInfo[1] -ne $srcInfo[1] -or $verifyInfo[2] -lt 2) {
        throw "Hardlink verification failed for $dstRpf (links=$($verifyInfo[2]))"
    }
}
Write-Host "[d] Hardlinked $($largeRpfs.Count) large .rpf files from $MirrorDir (0 extra bytes)"

# --- (e) Create NTFS directory junction E:\LUCIAS_PROJECT\pc_cache -> V:\LUCIAS_PROJECT_Cache\ ---
$pcCacheJunction = Join-Path $StageDir "pc_cache"
if (Test-Path -LiteralPath $CacheDir) {
    $jStatus = Set-DirectoryJunction -LinkPath $pcCacheJunction -TargetPath $CacheDir
    Write-Host "[e] Junction $pcCacheJunction -> $CacheDir ($jStatus)"
} else {
    Write-Warning "[e] Skipped pc_cache junction because $CacheDir does not exist (-AllowPartialCache)."
}

# --- (f) Symlinks/junctions for other required S: files and directories ---
$sJunctionDirs = @("common", "data", "pack", "platform")
$junctionSummary = @()
foreach ($d in $sJunctionDirs) {
    $srcSub = Join-Path $SourceDir $d
    if (Test-Path -LiteralPath $srcSub) {
        $dstSub = Join-Path $StageDir $d
        $st = Set-DirectoryJunction -LinkPath $dstSub -TargetPath $srcSub
        $junctionSummary += "$d($st)"
    }
}

$smallRequiredFiles = @(
    # Smaller .rpf archives
    "appdata0.rpf", "common.rpf", "data.rpf", "script.rpf", "shaders.rpf", "textures.rpf",
    # Package configs & manifests
    "MicrosoftGame.Config", "microsoft_gameconfig.bin", "Catalog000.bin", "resources.pri",
    "Update.alignmentchunk", "appxmanifest.xml", "layout_3202719e-b4b4-421c-9f8f-70d1c4a7d60b_xs.xml",
    # Splash / store logos
    "xbs_logo_150.png", "xbs_logo_44.png", "xbs_logo_480.png", "xbs_logo_store.png", "xbs_splash.png",
    # Non-console runtime / shader / CRT DLLs (excludes replaced Xbox shims & S: PercyScarlett stubs xaudio2_9/dstorage)
    "dxcompiler.dll", "dxil.dll", "XCurl.dll",
    "concrt140.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
    "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
    "vccorlib140.dll", "vcomp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"
)

foreach ($staleStub in @("xaudio2_9.dll", "dstorage.dll", "GTA6_PC.exe", "gta6_pc_config.json")) {
    $stalePath = Join-Path $StageDir $staleStub
    if (Test-Path -LiteralPath $stalePath) {
        Remove-ReparsePointSafe -Path $stalePath
        if (Test-Path -LiteralPath $stalePath) {
            Remove-Item -LiteralPath $stalePath -Force
        }
    }
}

$symlinkCount = 0
$copyFallbackCount = 0
$canSymlink = $true
foreach ($f in $smallRequiredFiles) {
    $srcFile = Join-Path $SourceDir $f
    if (-not (Test-Path -LiteralPath $srcFile)) {
        Write-Warning "Optional/expected S: file missing, skipping: $srcFile"
        continue
    }
    $dstFile = Join-Path $StageDir $f
    $linked = $false
    if ($canSymlink) {
        try {
            Remove-ReparsePointSafe -Path $dstFile
            if (Test-Path -LiteralPath $dstFile) {
                Remove-Item -LiteralPath $dstFile -Force
            }
            New-Item -ItemType SymbolicLink -Path $dstFile -Target $srcFile -ErrorAction Stop | Out-Null
            $linked = $true
            $symlinkCount++
        } catch {
            # Non-elevated Windows without Developer Mode raises privilege error on file symlinks.
            $canSymlink = $false
        }
    }
    if (-not $linked) {
        $needCopy = $true
        if (Test-Path -LiteralPath $dstFile) {
            $dstItem = Get-Item -LiteralPath $dstFile -Force
            $srcItem = Get-Item -LiteralPath $srcFile -Force
            if (-not ($dstItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and $dstItem.Length -eq $srcItem.Length) {
                $needCopy = $false
            }
        }
        if ($needCopy) {
            Remove-ReparsePointSafe -Path $dstFile
            Copy-Item -LiteralPath $srcFile -Destination $dstFile -Force
        }
        $copyFallbackCount++
    }
}
Write-Host "[f] S: junctions: $($junctionSummary -join ', ') | small files: symlinks=$symlinkCount, copy_fallback=$copyFallbackCount"

# --- (g) Write E:\LUCIAS_PROJECT\lucias_project_config.json ---
$configObj = [ordered]@{
    schema_version = 1
    project = "LUCIAS PROJECT"
    target_profile = "RTX3070_R9_5900X_16GB_DualSSD_1080p"
    display = [ordered]@{
        width = 1920
        height = 1080
        refresh_hz = 60
        preset = "1080p_vram_saving"
        dlss_mode = "Quality"
    }
    hardware = [ordered]@{
        gpu = [ordered]@{
            name = "NVIDIA GeForce RTX 3070"
            architecture = "Ampere SM 8.6"
            vram_physical_mib = 8192
            vram_budget_mib = 7200
            vram_target_working_mib = 6850
            wave_mode = "wave32"
            dlss_enabled = $true
            dxr_tier = "dxr_1_1"
        }
        cpu = [ordered]@{
            name = "AMD Ryzen 9 5900X"
            physical_cores = 12
            logical_threads = 24
            ccd0_game_threads = 6
            ccd1_io_worker_threads = 4
        }
        memory = [ordered]@{
            system_ram_gb = 16
            ram_commit_budget_mib = 12288
            ram_target_working_mib = 11500
            upload_ring_mib = 192
            readback_ring_mib = 16
            writewatch_enabled = $false
            shadow_mirror_enabled = $false
        }
    }
    overlay_hud = [ordered]@{
        enabled = $true
        title = "LUCIAS PROJECT"
        toggle_hotkeys = @("F10", "Insert")
        telemetry_json = (Join-Path $StageDir "logs\telemetry_latest.json")
    }
    paths = [ordered]@{
        game_root = $StageDir
        executable = $targetExe
        mirror_root = $MirrorDir
        pc_cache_junction = $pcCacheJunction
        pc_cache_target = $CacheDir
        shaders_dxilpack = (Join-Path $pcCacheJunction "shaders_pc.dxilpack")
        shaders_manifest = (Join-Path $pcCacheJunction "shaders_manifest.json")
        ttdb_pc = (Join-Path $pcCacheJunction "ttdb_pc")
        overlay_dir = (Join-Path $StageDir "overlay")
        logs_dir = (Join-Path $StageDir "logs")
        local_appdata_saves = "%LOCALAPPDATA%\LUCIAS_PROJECT"
    }
    vfs = [ordered]@{
        hook_vfs_iat = $HookVfs
        drive_g = $StageDir
        drive_t = $pcCacheJunction
    }
    staging = [ordered]@{
        pe_patcher = $patcher
        remapped_dlls = $patchReport.remapped_dlls.Count
        remapped_imports = $patchReport.total_remapped_imports
        shim_dll_count = $expectedShimDlls.Count
        hardlinked_rpf_count = $largeRpfs.Count
    }
}
$configPath = Join-Path $StageDir "lucias_project_config.json"
$configJson = $configObj | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($configPath, $configJson + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[g] Wrote config: $configPath"

# --- (h) Junction legacy E:\GTA6_PC -> E:\LUCIAS_PROJECT (zero duplicate files) ---
if ($LegacyJunctionDir -and ($LegacyJunctionDir -ne $StageDir)) {
    $legStatus = Set-DirectoryJunction -LinkPath $LegacyJunctionDir -TargetPath $StageDir
    Write-Host "[h] Compatibility junction $LegacyJunctionDir -> $StageDir ($legStatus)"
}

$eDriveAfter = (Get-PSDrive E).Free
$cDriveAfter = (Get-PSDrive C).Free
$eDeltaGiB = ($eDriveBefore - $eDriveAfter) / 1GB
Write-Host ("Post-stage free space -> E: {0:N3} GiB (delta: {1:N3} GiB) | C: {2:N3} GiB" -f ($eDriveAfter / 1GB), $eDeltaGiB, ($cDriveAfter / 1GB))
Write-Host "LUCIAS PROJECT staging completed successfully. NOTE: LuciasProject.exe was NOT launched."
