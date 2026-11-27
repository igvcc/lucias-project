//! **LUCIAS PROJECT** — Read-only PE32+ `.text` signature scanner and patch-manifest verifier
//! for `game_scarlett_master.exe` (`LuciasProject.exe`).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Parsed PE32+ section header summary (read-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

/// Minimal PE32+ image metadata needed for RVA -> file offset translation and `.text` scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pe64Summary {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub sections: Vec<PeSection>,
}

impl Pe64Summary {
    /// Parses PE32+ headers from any seekable read-only stream (`File`, `Cursor<&[u8]>`).
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self, String> {
        let mut dos = [0u8; 64];
        reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        reader.read_exact(&mut dos).map_err(|e| e.to_string())?;
        if &dos[0..2] != b"MZ" {
            return Err("missing MZ signature".into());
        }
        let pe_offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
        reader.seek(SeekFrom::Start(pe_offset)).map_err(|e| e.to_string())?;

        let mut pe_hdr = [0u8; 24];
        reader.read_exact(&mut pe_hdr).map_err(|e| e.to_string())?;
        if &pe_hdr[0..4] != b"PE\0\0" {
            return Err("missing PE signature".into());
        }
        let num_sections = u16::from_le_bytes(pe_hdr[6..8].try_into().unwrap()) as usize;
        let opt_size = u16::from_le_bytes(pe_hdr[20..22].try_into().unwrap()) as usize;
        if opt_size < 112 {
            return Err(format!("unexpected OptionalHeader size {opt_size}"));
        }

        let mut opt = vec![0u8; opt_size];
        reader.read_exact(&mut opt).map_err(|e| e.to_string())?;
        let magic = u16::from_le_bytes(opt[0..2].try_into().unwrap());
        if magic != 0x020B {
            return Err(format!("not PE32+ (magic={magic:#x})"));
        }
        let entry_point_rva = u32::from_le_bytes(opt[16..20].try_into().unwrap());
        let image_base = u64::from_le_bytes(opt[24..32].try_into().unwrap());

        let mut sections = Vec::with_capacity(num_sections);
        let mut sec_buf = [0u8; 40];
        for _ in 0..num_sections {
            reader.read_exact(&mut sec_buf).map_err(|e| e.to_string())?;
            let raw_name = &sec_buf[0..8];
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
            sections.push(PeSection {
                name,
                virtual_address: u32::from_le_bytes(sec_buf[12..16].try_into().unwrap()),
                virtual_size: u32::from_le_bytes(sec_buf[8..12].try_into().unwrap()),
                size_of_raw_data: u32::from_le_bytes(sec_buf[16..20].try_into().unwrap()),
                pointer_to_raw_data: u32::from_le_bytes(sec_buf[20..24].try_into().unwrap()),
            });
        }
        Ok(Self {
            image_base,
            entry_point_rva,
            sections,
        })
    }

    pub fn text_section(&self) -> Option<&PeSection> {
        self.sections.iter().find(|s| s.name == ".text")
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        for s in &self.sections {
            let span = s.virtual_size.max(s.size_of_raw_data);
            if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span) {
                let delta = rva - s.virtual_address;
                if delta < s.size_of_raw_data {
                    return Some(u64::from(s.pointer_to_raw_data) + u64::from(delta));
                }
            }
        }
        None
    }
}

/// Masked byte pattern (e.g. `"C5 FC 11 07 ?? ?? ?? ??"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<u8>,
}

impl BytePattern {
    pub fn parse(ida_pattern: &str) -> Result<Self, String> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for tok in ida_pattern.split_whitespace() {
            if tok == "?" || tok == "??" {
                bytes.push(0);
                mask.push(0);
            } else {
                let val = u8::from_str_radix(tok, 16)
                    .map_err(|_| format!("invalid hex token in pattern: {tok}"))?;
                bytes.push(val);
                mask.push(0xFF);
            }
        }
        if bytes.is_empty() {
            return Err("empty pattern".into());
        }
        Ok(Self { bytes, mask })
    }

    pub fn matches_at(&self, slice: &[u8]) -> bool {
        if slice.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(self.mask.iter())
            .zip(slice.iter())
            .all(|((&b, &m), &s)| (s & m) == (b & m))
    }

    /// Scans `haystack` starting at `base_rva` and returns all matching RVAs.
    pub fn scan_all(&self, haystack: &[u8], base_rva: u32) -> Vec<u32> {
        let len = self.bytes.len();
        if haystack.len() < len {
            return Vec::new();
        }
        let first_fixed = self.mask.iter().position(|&m| m == 0xFF);
        let mut out = Vec::new();
        let mut i = 0usize;
        let limit = haystack.len() - len;
        while i <= limit {
            if let Some(pos) = first_fixed {
                let target = self.bytes[pos];
                if let Some(rel) = haystack[i + pos..=limit + pos].iter().position(|&b| b == target) {
                    i += rel;
                } else {
                    break;
                }
            }
            if self.matches_at(&haystack[i..i + len]) {
                out.push(base_rva + i as u32);
            }
            i += 1;
        }
        out
    }
}

/// One verified call-site / thunk / IAT entry in `game_scarlett_master.exe`.
#[derive(Debug, Clone, Copy)]
pub struct SignatureManifestEntry {
    pub id: &'static str,
    pub dll: &'static str,
    pub symbol: &'static str,
    pub iat_rva: u32,
    pub thunk_rva: Option<u32>,
    pub site_rva: u32,
    pub call_rva: u32,
    pub pattern: &'static str,
    pub notes: &'static str,
}

/// Verified `.text` signatures & RVAs from `S:\gta\Gta6fordevelopersacces\game_scarlett_master.exe`.
/// Wildcarded `??` bytes cover RIP-relative disp32s only, keeping all opcodes, registers, and immediate constants exact.
pub const SCARLETT_MANIFEST: &[SignatureManifestEntry] = &[
    SignatureManifestEntry {
        id: "VM_CONFIG",
        dll: "d3d12_xs.dll",
        symbol: "D3D12ConfigureVirtualMemoryX",
        iat_rva: 0x6793c08,
        thunk_rva: Some(0x5f3fd60),
        site_rva: 0x1e1cfa9,
        call_rva: 0x1e1cfe0,
        pattern: "C5 FC 11 07 C5 F8 77 E8 ?? ?? ?? ?? 34 01 0F B6 F0 48 83 CE 02 48 C1 E6 21 48 89 F1 48 C1 E9 0C 81 C1 FF FF 3F 00 C1 E9 16 E8 ?? ?? ?? ?? 83 C0 02 48 89 F9 89 47 04 E8 ?? ?? ?? ?? 85 C0 79 01",
        notes: "VirtualMemoryConfig(0x20B) setup; computes 16/24 GiB VA reserve (2|3)<<33, then calls XMemVirtualAlloc(0x20402000, flags=0x21/0x03)",
    },
    SignatureManifestEntry {
        id: "D3D12_CREATE_DEVICE",
        dll: "d3d12_xs.dll",
        symbol: "D3D12XboxCreateDevice",
        iat_rva: 0x6793c18,
        thunk_rva: Some(0x5f3fd80),
        site_rva: 0x247858c,
        call_rva: 0x24785b7,
        pattern: "C7 02 04 00 02 00 C7 42 08 00 00 10 00 89 42 20 0F B6 05 ?? ?? ?? ?? 89 42 24 C7 42 3C 20 00 00 00 C7 42 28 01 00 00 00 C5 F8 77 E8 ?? ?? ?? ?? 89 C1",
        notes: "Params(0x50B): version=0x20004, scratch=0x100000, flags_3c=0x20, IID_ID3D12Device11 @0x61e0638",
    },
    SignatureManifestEntry {
        id: "XMEM_MAP_PHYS",
        dll: "xmem.dll",
        symbol: "XMemMapPhysicalPages",
        iat_rva: 0x6793a40,
        thunk_rva: Some(0x5f3fce0),
        site_rva: 0x1e6c25d,
        call_rva: 0x1e6c295,
        pattern: "41 B9 23 00 00 00 31 C9 41 B8 00 20 40 20 C7 44 24 20 04 20 00 00 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 85 C0 75 08 CC 48 8B 05 ?? ?? ?? ?? 48 89 C1 48 89 F2 49 89 F8 E8 ?? ?? ?? ?? 48 85 C0",
        notes: "Reserves 0x20402000 placeholder with flags=0x23 protect=0x2004, then maps allocated 64 KiB physical pages",
    },
    SignatureManifestEntry {
        id: "XMEM_MAP_SCATTER",
        dll: "xmem.dll",
        symbol: "XMemMapPhysicalPagesScatter",
        iat_rva: 0x6793a48,
        thunk_rva: Some(0x5f3fd20),
        site_rva: 0xf2cc2e,
        call_rva: 0xf2cc3e,
        pattern: "85 C0 74 1A 89 C2 48 83 EC 20 4C 89 F9 49 89 D8 E8 ?? ?? ?? ?? 48 83 C4 20 85 C0 75 01 CC 48 8B",
        notes: "Scatter-maps compacted 64 KiB physical page arrays into reserved VA slots",
    },
    SignatureManifestEntry {
        id: "BVH_BUILD_BATCHED_1",
        dll: "XboxBvhBuilder.dll",
        symbol: "?BuildRaytracingAccelerationStructureBatched2X@XboxBvhBuilder@@QEAAXPEAUID3D12GraphicsCommandList6@@IPEBUD3D12XBOX_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_BATCHED_DESC2@@@Z",
        iat_rva: 0x6793f88,
        thunk_rva: None,
        site_rva: 0xfe4fd8,
        call_rva: 0xfe4fec,
        pattern: "48 83 EC 20 48 8B 7D F0 41 89 D8 4D 89 E1 48 89 FA C5 F8 77 FF 15 ?? ?? ?? ?? 48 83 C4 20 4C 3B",
        notes: "Batched BVH build (stride=0x50, max batch=16, 256B aligned scratch/dest)",
    },
    SignatureManifestEntry {
        id: "BVH_BUILD_BATCHED_2",
        dll: "XboxBvhBuilder.dll",
        symbol: "?BuildRaytracingAccelerationStructureBatched2X@XboxBvhBuilder@@QEAAXPEAUID3D12GraphicsCommandList6@@IPEBUD3D12XBOX_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_BATCHED_DESC2@@@Z",
        iat_rva: 0x6793f88,
        thunk_rva: None,
        site_rva: 0x2490298,
        call_rva: 0x24902ac,
        pattern: "48 83 EC 20 48 8B 7D F0 41 89 D8 4D 89 E1 48 89 FA C5 F8 77 FF 15 ?? ?? ?? ?? 48 83 C4 20 4C 3B",
        notes: "Second batched BVH build call-site with identical 0x50-byte descriptor loop",
    },
    SignatureManifestEntry {
        id: "BVH_REHYDRATE",
        dll: "XboxBvhBuilder.dll",
        symbol: "?RehydrateRaytracingAccelerationStructureBatched2X@XboxBvhBuilder@@QEAAJPEAUID3D12GraphicsCommandList8@@IPEBUD3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC@@PEB_K@Z",
        iat_rva: 0x6793fa0,
        thunk_rva: None,
        site_rva: 0xea6d38,
        call_rva: 0xea6d5a,
        pattern: "41 83 F8 10 72 6B 48 8B 0D ?? ?? ?? ?? 48 8D 44 24 60 4C 8D 8C 24 E0 00 00 00 48 89 44 24 20 C5 F8 77 FF 15 ?? ?? ?? ?? 48 8B",
        notes: "Streamed BVH rehydration (max 16 batch check `cmp r8d, 0x10`)",
    },
    SignatureManifestEntry {
        id: "BVH_PREBUILD",
        dll: "XboxBvhBuilder.dll",
        symbol: "?GetRaytracingAccelerationStructurePrebuildInfo@XboxBvhBuilder@@QEAAXPEBUD3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS@@PEBUD3D12XBOX_XDXR_STREAM_DESC@@PEAUD3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO@@@Z",
        iat_rva: 0x6793f98,
        thunk_rva: None,
        site_rva: 0x75947,
        call_rva: 0x7595c,
        pattern: "C5 F8 57 C0 31 DB 45 31 C0 4D 89 F1 C4 C1 78 29 06 49 89 5E 10 FF 15 ?? ?? ?? ?? C4 C1 78 28 06",
        notes: "Prebuild info query (returns 24-byte D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO)",
    },
    SignatureManifestEntry {
        id: "XG_TEXTURE_COMPUTER",
        dll: "xg_xs.dll",
        symbol: "XGCreateTextureComputer",
        iat_rva: 0x6793f60,
        thunk_rva: Some(0x5f3ff40),
        site_rva: 0x16f7128,
        call_rva: 0x16f7141,
        pattern: "48 8D 4C 24 50 48 8D 54 24 38 4C 89 C6 C5 FC 11 49 18 C5 FC 11 01 C5 F8 77 E8 ?? ?? ?? ?? 8A 46",
        notes: "Creates XGTextureAddressComputer from 0x38-byte D3D12_RESOURCE_DESC on stack",
    },
    SignatureManifestEntry {
        id: "FFX_DISPATCH",
        dll: "amd_fidelityfx_loader_xbox.dll",
        symbol: "ffxDispatch",
        iat_rva: 0x6793fd8,
        thunk_rva: Some(0x5f3ffb0),
        site_rva: 0x28f03ba,
        call_rva: 0x28f03db,
        pattern: "4C 8D BC 24 00 01 00 00 4C 8D A7 28 01 00 00 4C 89 F9 49 89 47 10 E8 ?? ?? ?? ?? 4C 89 E1 4C 89 FA E8 ?? ?? ?? ?? 8B 87 08 01",
        notes: "FidelityFX FSR/upscaler dispatch site (cmdList at [r12+0x127c8], context at [rdi+0x128])",
    },
];

/// Result of verifying one manifest entry against a PE32+ file/stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub id: &'static str,
    pub site_rva: u32,
    pub matched_at_rva: bool,
    pub call_rel32_verified: bool,
}

/// Verifies every `SCARLETT_MANIFEST` entry at its exact `site_rva` in a read-only PE stream.
/// Also checks that thunked `E8 rel32` calls resolve to `thunk_rva` and direct `FF 15 disp32`
/// calls resolve to `iat_rva`.
pub fn verify_manifest_read_only<R: Read + Seek>(
    reader: &mut R,
    manifest: &[SignatureManifestEntry],
) -> Result<Vec<VerificationReport>, String> {
    let pe = Pe64Summary::parse(reader)?;
    let mut reports = Vec::with_capacity(manifest.len());
    for entry in manifest {
        let pat = BytePattern::parse(entry.pattern)?;
        let off = pe
            .rva_to_file_offset(entry.site_rva)
            .ok_or_else(|| format!("site_rva {:#x} outside mapped sections", entry.site_rva))?;
        let mut buf = vec![0u8; pat.bytes.len()];
        reader.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
        reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
        let matched_at_rva = pat.matches_at(&buf);

        // Verify the call instruction at call_rva points to expected thunk_rva or iat_rva.
        let call_off = pe
            .rva_to_file_offset(entry.call_rva)
            .ok_or_else(|| format!("call_rva {:#x} outside mapped sections", entry.call_rva))?;
        let mut call_bytes = [0u8; 6];
        reader.seek(SeekFrom::Start(call_off)).map_err(|e| e.to_string())?;
        reader.read_exact(&mut call_bytes).map_err(|e| e.to_string())?;
        let call_rel32_verified = if call_bytes[0] == 0xE8 {
            let disp = i32::from_le_bytes(call_bytes[1..5].try_into().unwrap());
            let target = (entry.call_rva as i64 + 5 + disp as i64) as u32;
            entry.thunk_rva == Some(target)
        } else if call_bytes[0] == 0xFF && call_bytes[1] == 0x15 {
            let disp = i32::from_le_bytes(call_bytes[2..6].try_into().unwrap());
            let target = (entry.call_rva as i64 + 6 + disp as i64) as u32;
            entry.iat_rva == target
        } else {
            false
        };

        reports.push(VerificationReport {
            id: entry.id,
            site_rva: entry.site_rva,
            matched_at_rva,
            call_rel32_verified,
        });
    }
    Ok(reports)
}

/// Convenience wrapper opening a file strictly read-only (`File::open`) to verify the manifest.
pub fn verify_manifest_on_file(path: &Path) -> Result<Vec<VerificationReport>, String> {
    let mut f = File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    verify_manifest_read_only(&mut f, SCARLETT_MANIFEST)
}
