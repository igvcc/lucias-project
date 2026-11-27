<#
.SYNOPSIS
    LUCIAS PROJECT — Verifies the staged native Win64 PC layout in E:\LUCIAS_PROJECT\.
.DESCRIPTION
    Checks:
      1. LuciasProject.exe PE32+ integrity (10+ sections, 2x .xbld, 2 TLS callbacks, WINDOWS_GUI, valid checksum, intact .text/.pdata/.reloc/.tls).
      2. All 14 Win64 shim DLLs present, loadable via LoadLibraryW, and resolving 100% of remapped IAT imports + 6 xgameruntime.dll exports.
      3. No stale PercyScarlett shadow stubs (xaudio2_9.dll / dstorage.dll) present in E:\LUCIAS_PROJECT\.
      4. NTFS hardlinks for 6 large .rpf files (E:\gta_mirror\ <-> E:\LUCIAS_PROJECT\) share FileId & nNumberOfLinks >= 2; E: free space > 280 GiB.
      5. E:\LUCIAS_PROJECT\pc_cache junction resolves to V:\LUCIAS_PROJECT_Cache\ (or V:\GTA6_PC_Cache\) with shaders_pc.dxilpack, shaders_manifest.json, ttdb_pc\.
      6. E:\GTA6_PC compatibility junction -> E:\LUCIAS_PROJECT; S: directory junctions (common, data, pack) & required small .rpf / lucias_project_config.json present.
      7. Safety checks: S:\gta\Gta6fordevelopersacces\ untouched, C: free space healthy.
    NEVER launches LuciasProject.exe.
#>
[CmdletBinding()]
param(
    [string]$StageDir = "E:\LUCIAS_PROJECT",
    [string]$LegacyJunctionDir = "E:\GTA6_PC",
    [string]$SourceDir = "S:\gta\Gta6fordevelopersacces",
    [string]$MirrorDir = "E:\gta_mirror",
    [string]$CacheDir = "V:\LUCIAS_PROJECT_Cache",
    [string]$PatcherExe = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Failures = New-Object System.Collections.Generic.List[string]
function Assert-Check {
    param([bool]$Condition, [string]$Label, [string]$Detail = "")
    if ($Condition) {
        Write-Host "[PASS] $Label$(if($Detail){ " -- $Detail" })"
    } else {
        Write-Host "[FAIL] $Label$(if($Detail){ " -- $Detail" })" -ForegroundColor Red
        $script:Failures.Add("$Label ($Detail)")
    }
}

$VerifierCs = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class LuciasStageVerifier {
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetDllDirectoryW(string lpPathName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hLibModule);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcAddress")]
    private static extern IntPtr GetProcAddressOrdinal(IntPtr hModule, IntPtr ordinal);

    public static ulong[] GetFileIdAndLinks(string path) {
        IntPtr h = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (h == new IntPtr(-1)) {
            throw new IOException("CreateFileW failed for " + path + " err=" + Marshal.GetLastWin32Error());
        }
        try {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) {
                throw new IOException("GetFileInformationByHandle failed err=" + Marshal.GetLastWin32Error());
            }
            ulong fileId = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            ulong fileSize = ((ulong)info.FileSizeHigh << 32) | info.FileSizeLow;
            return new ulong[] { info.VolumeSerialNumber, fileId, info.NumberOfLinks, fileSize };
        } finally {
            CloseHandle(h);
        }
    }

    public static uint[] CheckPeChecksum(string path) {
        uint hdr = 0, calc = 0;
        uint rc = MapFileAndCheckSumW(path, out hdr, out calc);
        return new uint[] { rc, hdr, calc };
    }

    private static uint RvaToOffset(byte[] buf, int secTableOff, int numSec, uint rva) {
        for (int i = 0; i < numSec; i++) {
            int o = secTableOff + i * 40;
            uint vSize = BitConverter.ToUInt32(buf, o + 8);
            uint vAddr = BitConverter.ToUInt32(buf, o + 12);
            uint rSize = BitConverter.ToUInt32(buf, o + 16);
            uint rPtr = BitConverter.ToUInt32(buf, o + 20);
            uint span = Math.Max(vSize, rSize);
            if (rva >= vAddr && rva < vAddr + span) {
                uint delta = rva - vAddr;
                if (delta < rSize) return rPtr + delta;
            }
        }
        throw new InvalidDataException("Unmapped RVA 0x" + rva.ToString("X"));
    }

    private static string ReadAsciiZ(byte[] buf, int offset) {
        int end = offset;
        while (end < buf.Length && buf[end] != 0) end++;
        return Encoding.ASCII.GetString(buf, offset, end - offset);
    }

    public static string VerifyDllsAndPeImports(string stageDir, string patchedExePath, string origExePath, string[] expectedDlls) {
        byte[] patched = File.ReadAllBytes(patchedExePath);
        byte[] orig = File.ReadAllBytes(origExePath);

        if (BitConverter.ToUInt16(patched, 0) != 0x5A4D) throw new InvalidDataException("Missing MZ");
        int lfanew = BitConverter.ToInt32(patched, 0x3C);
        if (BitConverter.ToUInt32(patched, lfanew) != 0x4550) throw new InvalidDataException("Missing PE signature");
        int fh = lfanew + 4;
        ushort machine = BitConverter.ToUInt16(patched, fh);
        ushort numSec = BitConverter.ToUInt16(patched, fh + 2);
        ushort optSize = BitConverter.ToUInt16(patched, fh + 16);
        ushort fileChars = BitConverter.ToUInt16(patched, fh + 18);
        int opt = fh + 20;
        ushort optMagic = BitConverter.ToUInt16(patched, opt);
        ushort subsystem = BitConverter.ToUInt16(patched, opt + 68);
        ushort dllChars = BitConverter.ToUInt16(patched, opt + 70);
        if (machine != 0x8664 || optMagic != 0x020B) throw new InvalidDataException("Not PE32+ AMD64");
        if ((fileChars & 0x2000) != 0) throw new InvalidDataException("IMAGE_FILE_DLL unexpectedly set");
        if (subsystem != 2) throw new InvalidDataException("Subsystem != WINDOWS_GUI (got " + subsystem + ")");
        if ((dllChars & 0x1000) != 0) throw new InvalidDataException("APPCONTAINER flag still set");

        int secTable = opt + optSize;
        int xbldCount = 0;
        var critSections = new HashSet<string>(StringComparer.Ordinal) { ".text", ".pdata", ".reloc", ".tls" };
        for (int i = 0; i < numSec; i++) {
            int o = secTable + i * 40;
            string sname = Encoding.ASCII.GetString(patched, o, 8).TrimEnd('\0');
            if (sname == ".xbld") xbldCount++;
            if (critSections.Contains(sname)) {
                uint rSize = BitConverter.ToUInt32(patched, o + 16);
                uint rPtr = BitConverter.ToUInt32(patched, o + 20);
                for (int b = 0; b < (int)rSize; b++) {
                    if (patched[rPtr + b] != orig[rPtr + b]) {
                        throw new InvalidDataException("Critical section " + sname + " mutated at offset 0x" + (rPtr + b).ToString("X"));
                    }
                }
            }
        }
        if (numSec < 10 || xbldCount != 2) {
            throw new InvalidDataException("Section check failed: numSec=" + numSec + " xbld=" + xbldCount);
        }

        SetDllDirectoryW(stageDir);
        var loaded = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
        try {
            foreach (string dll in expectedDlls) {
                string full = Path.Combine(stageDir, dll);
                IntPtr h = LoadLibraryW(full);
                if (h == IntPtr.Zero) {
                    throw new IOException("LoadLibraryW failed for " + full + " err=" + Marshal.GetLastWin32Error());
                }
                loaded[dll] = h;
            }

            uint impRva = BitConverter.ToUInt32(patched, opt + 112 + 8);
            int impOff = (int)RvaToOffset(patched, secTable, numSec, impRva);
            int totalImports = 0;
            int resolvedShimImports = 0;
            int idx = 0;
            while (true) {
                int dOff = impOff + idx * 20;
                uint oft = BitConverter.ToUInt32(patched, dOff);
                uint nameRva = BitConverter.ToUInt32(patched, dOff + 12);
                uint ft = BitConverter.ToUInt32(patched, dOff + 16);
                if (oft == 0 && nameRva == 0 && ft == 0) break;
                string dllName = ReadAsciiZ(patched, (int)RvaToOffset(patched, secTable, numSec, nameRva));
                uint thunkRva = (oft != 0) ? oft : ft;
                int thunkOff = (int)RvaToOffset(patched, secTable, numSec, thunkRva);

                IntPtr shimHandle = IntPtr.Zero;
                loaded.TryGetValue(dllName, out shimHandle);

                int slot = 0;
                while (true) {
                    ulong entry = BitConverter.ToUInt64(patched, thunkOff + slot * 8);
                    if (entry == 0) break;
                    totalImports++;
                    if (shimHandle != IntPtr.Zero) {
                        IntPtr proc;
                        if ((entry & 0x8000000000000000UL) != 0) {
                            ushort ord = (ushort)(entry & 0xFFFF);
                            proc = GetProcAddressOrdinal(shimHandle, new IntPtr(ord));
                            if (proc == IntPtr.Zero) {
                                throw new MissingMethodException("Missing ordinal #" + ord + " in " + dllName);
                            }
                        } else {
                            uint hnRva = (uint)(entry & 0x7FFFFFFF);
                            int hnOff = (int)RvaToOffset(patched, secTable, numSec, hnRva);
                            string sym = ReadAsciiZ(patched, hnOff + 2);
                            proc = GetProcAddress(shimHandle, sym);
                            if (proc == IntPtr.Zero) {
                                throw new MissingMethodException("Missing export " + sym + " in " + dllName);
                            }
                        }
                        resolvedShimImports++;
                    }
                    slot++;
                }
                idx++;
            }

            IntPtr xgr = loaded["xgameruntime.dll"];
            string[] xgrExports = new[] {
                "QueryApiImpl", "InitializeApiImpl", "InitializeApiImplEx",
                "InitializeApiImplEx2", "XErrorReport", "UninitializeApiImpl"
            };
            foreach (string fn in xgrExports) {
                if (GetProcAddress(xgr, fn) == IntPtr.Zero) {
                    throw new MissingMethodException("Missing xgameruntime.dll export: " + fn);
                }
            }

            return string.Format("sections={0}, xbld={1}, total_iat={2}, resolved_shim_iat={3}, xgameruntime_exports=6/6",
                numSec, xbldCount, totalImports, resolvedShimImports);
        } finally {
            foreach (var h in loaded.Values) {
                if (h != IntPtr.Zero) FreeLibrary(h);
            }
            SetDllDirectoryW(null);
        }
    }
}
"@
if (-not ("LuciasStageVerifier" -as [type])) {
    Add-Type -TypeDefinition $VerifierCs
}

Write-Host "=== LUCIAS PROJECT Native Stage Verification ==="
$targetExe = Join-Path $StageDir "LuciasProject.exe"
$sourceExe = Join-Path $SourceDir "game_scarlett_master.exe"
Assert-Check (Test-Path -LiteralPath $StageDir) "Stage directory exists" $StageDir
Assert-Check (Test-Path -LiteralPath $targetExe) "LuciasProject.exe exists" $targetExe
Assert-Check (Test-Path -LiteralPath $sourceExe) "Source Scarlett exe readable" $sourceExe

# 1. PE Checksum & Patcher Verify
if (Test-Path -LiteralPath $targetExe) {
    $chk = [LuciasStageVerifier]::CheckPeChecksum($targetExe)
    Assert-Check ($chk[0] -eq 0 -and $chk[1] -ne 0 -and $chk[1] -eq $chk[2]) "LuciasProject.exe PE checksum valid" ("0x{0:X8}" -f $chk[2])
}

if (-not $PatcherExe) {
    foreach ($c in @(
        "c:\pulpit\xx\gta6_native_shims\target\release\pe_native_patcher.exe",
        "c:\pulpit\xx\gta6_native_shims\target\debug\pe_native_patcher.exe"
    )) {
        if (Test-Path -LiteralPath $c) { $PatcherExe = $c; break }
    }
}
if ($PatcherExe -and (Test-Path -LiteralPath $PatcherExe) -and (Test-Path -LiteralPath $targetExe)) {
    $vOut = & $PatcherExe verify --original $sourceExe --patched $targetExe --hook-vfs
    $vOk = ($LASTEXITCODE -eq 0)
    $ana = $vOut | ConvertFrom-Json
    Assert-Check $vOk "pe_native_patcher verify --hook-vfs" "exit=$LASTEXITCODE"
    Assert-Check ($ana.tls_callbacks.Count -eq 2) "TLS callbacks intact (2)" "count=$($ana.tls_callbacks.Count)"
    Assert-Check ($ana.total_import_count -eq 587) "Total static IAT count == 587" "count=$($ana.total_import_count)"
} else {
    Assert-Check $false "pe_native_patcher.exe present for verification" "not found in target/release or target/debug"
}

# 2. All 14 DLLs present + LoadLibrary + GetProcAddress resolution + no shadow stubs
$expectedDlls = @(
    "xmem_pc.dll", "xcrd_pc.dll", "ffx_pc.dll", "dx12xs_pc.dll",
    "xg_pc.dll", "xbvh_pc.dll", "chad_pc.dll", "audio_pc.dll",
    "bink2_pc.dll", "hc_pc.dll", "gi_pc.dll", "GameInput.dll",
    "vfs_pc.dll", "xgameruntime.dll"
)
$missingDlls = @($expectedDlls | Where-Object { -not (Test-Path -LiteralPath (Join-Path $StageDir $_)) })
Assert-Check ($missingDlls.Count -eq 0) "All 14 Win64 shim DLLs present" $(if ($missingDlls.Count -eq 0) { "14/14 present" } else { "missing: $($missingDlls -join ', ')" })

foreach ($bad in @("xaudio2_9.dll", "dstorage.dll", "amd_fidelityfx_upscaler_xbox.dll")) {
    Assert-Check (-not (Test-Path -LiteralPath (Join-Path $StageDir $bad))) "No stale shadow DLL: $bad"
}

if ($missingDlls.Count -eq 0 -and (Test-Path -LiteralPath $targetExe)) {
    try {
        $peRes = [LuciasStageVerifier]::VerifyDllsAndPeImports($StageDir, $targetExe, $sourceExe, $expectedDlls)
        Assert-Check $true "PE integrity + 14 DLL LoadLibrary + IAT GetProcAddress" $peRes
    } catch {
        Assert-Check $false "PE integrity + 14 DLL LoadLibrary + IAT GetProcAddress" $_.Exception.Message
    }
}

# 3. Hardlinks for 6 large .rpf files + E: free space check
$largeRpfs = @("anim.rpf", "audio.rpf", "levels.rpf", "movies.rpf", "navmeshes.rpf", "packs.rpf")
foreach ($rpf in $largeRpfs) {
    $mPath = Join-Path $MirrorDir $rpf
    $sPath = Join-Path $StageDir $rpf
    if ((Test-Path -LiteralPath $mPath) -and (Test-Path -LiteralPath $sPath)) {
        $mInfo = [LuciasStageVerifier]::GetFileIdAndLinks($mPath)
        $sInfo = [LuciasStageVerifier]::GetFileIdAndLinks($sPath)
        $ok = ($mInfo[0] -eq $sInfo[0]) -and ($mInfo[1] -eq $sInfo[1]) -and ($sInfo[2] -ge 2) -and ($mInfo[3] -eq $sInfo[3])
        Assert-Check $ok "Hardlink $rpf" ("FileId=0x{0:X}, Links={1}, Size={2:N3} GiB" -f $sInfo[1], $sInfo[2], ($sInfo[3] / 1GB))
    } else {
        Assert-Check $false "Hardlink $rpf" "Missing source or staged file"
    }
}
$eFreeGiB = (Get-PSDrive E).Free / 1GB
Assert-Check ($eFreeGiB -gt 280) "E: free space preserved (hardlinks zero extra bytes)" ("{0:N2} GiB free" -f $eFreeGiB)

# 4. pc_cache junction resolution
$pcCache = Join-Path $StageDir "pc_cache"
if (Test-Path -LiteralPath $pcCache) {
    $item = Get-Item -LiteralPath $pcCache -Force
    $isJunc = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    $normExpected = [System.IO.Path]::GetFullPath($CacheDir).TrimEnd('\')
    $normLegacy = [System.IO.Path]::GetFullPath("V:\GTA6_PC_Cache").TrimEnd('\')
    $targets = @($item.Target) | ForEach-Object { if ($_) { [System.IO.Path]::GetFullPath($_).TrimEnd('\') } }
    Assert-Check ($isJunc -and (($targets -contains $normExpected) -or ($targets -contains $normLegacy))) "pc_cache NTFS junction -> $CacheDir" ("targets=$($targets -join ';')")
    Assert-Check (Test-Path -LiteralPath (Join-Path $pcCache "shaders_pc.dxilpack")) "pc_cache\shaders_pc.dxilpack resolves"
    Assert-Check (Test-Path -LiteralPath (Join-Path $pcCache "shaders_manifest.json")) "pc_cache\shaders_manifest.json resolves"
    Assert-Check (Test-Path -LiteralPath (Join-Path $pcCache "ttdb_pc")) "pc_cache\ttdb_pc\ resolves"
} else {
    Assert-Check $false "pc_cache NTFS junction" "Missing $pcCache"
}

# 5. Compatibility junction E:\GTA6_PC -> E:\LUCIAS_PROJECT
if ($LegacyJunctionDir -and ($LegacyJunctionDir -ne $StageDir)) {
    $legOk = $false
    $legDetail = "missing"
    if (Test-Path -LiteralPath $LegacyJunctionDir) {
        $legItem = Get-Item -LiteralPath $LegacyJunctionDir -Force
        $isRep = ($legItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        $normStage = [System.IO.Path]::GetFullPath($StageDir).TrimEnd('\')
        $legTargets = @($legItem.Target) | ForEach-Object { if ($_) { [System.IO.Path]::GetFullPath($_).TrimEnd('\') } }
        $legOk = $isRep -and ($legTargets -contains $normStage)
        $legDetail = "targets=$($legTargets -join ';')"
    }
    Assert-Check $legOk "Legacy junction $LegacyJunctionDir -> $StageDir" $legDetail
}

# 6. S: directory junctions + smaller RPFs + config JSON
foreach ($d in @("common", "data", "pack")) {
    $jp = Join-Path $StageDir $d
    $ok = $false
    if (Test-Path -LiteralPath $jp) {
        $it = Get-Item -LiteralPath $jp -Force
        $ok = (($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -and (Test-Path -LiteralPath $jp)
    }
    Assert-Check $ok "S: junction $d" $jp
}
foreach ($srpf in @("appdata0.rpf", "common.rpf", "data.rpf", "script.rpf", "shaders.rpf", "textures.rpf")) {
    $sp = Join-Path $StageDir $srpf
    Assert-Check (Test-Path -LiteralPath $sp) "Small RPF staged: $srpf"
}
$cfgPath = Join-Path $StageDir "lucias_project_config.json"
if (Test-Path -LiteralPath $cfgPath) {
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
    Assert-Check ($cfg.project -eq "LUCIAS PROJECT" -and $cfg.hardware.gpu.vram_budget_mib -eq 7200 -and $cfg.hardware.memory.system_ram_gb -eq 16) "lucias_project_config.json valid (LUCIAS PROJECT + RTX 3070/16GB)" "vram_budget_mib=$($cfg.hardware.gpu.vram_budget_mib)"
} else {
    Assert-Check $false "lucias_project_config.json present"
}

# 7. Safety: C: free space & S: untouched
$cFreeGiB = (Get-PSDrive C).Free / 1GB
if ($cFreeGiB -lt 5.0) { Write-Warning ("C: free space is below 5.0 GiB ({0:N2} GiB free)" -f $cFreeGiB) }
Assert-Check ($cFreeGiB -gt 3.0) "C: free space healthy" ("{0:N2} GiB free" -f $cFreeGiB)
$recentS = @(Get-ChildItem -LiteralPath $SourceDir -File | Where-Object { $_.LastWriteTime -gt [datetime]"2026-11-26 12:00:00" })
Assert-Check ($recentS.Count -eq 0) "S: strictly read-only (no files modified today)" ("recent_count=$($recentS.Count)")

Write-Host ""
if ($script:Failures.Count -eq 0) {
    Write-Host "LUCIAS PROJECT: ALL CHECKS PASSED." -ForegroundColor Green
    exit 0
} else {
    Write-Host "LUCIAS PROJECT FAILED CHECKS ($($script:Failures.Count)):" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
    exit 1
}
