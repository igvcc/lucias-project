use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use object::read::pe::PeFile64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

pub mod subsystem {
    pub const WINDOWS_GUI: u16 = 2;
    pub const WINDOWS_CUI: u16 = 3;
    pub const XBOX: u16 = 14;
    pub const XBOX_CODE_CATALOG: u16 = 17;
}

pub mod dll_flags {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const APPCONTAINER: u16 = 0x1000;
    pub const GUARD_CF: u16 = 0x4000;
}

pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const EXCEPTION: usize = 3;
    pub const BASERELOC: usize = 5;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
}

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed PE32+ image: {0}")]
    Malformed(&'static str),
    #[error("unsupported PE format: {0}")]
    Unsupported(String),
    #[error("RVA 0x{0:x} does not map to backed file data")]
    UnmappedRva(u32),
    #[error("cannot allocate {0} bytes in PE for longer DLL name(s)")]
    NoSpaceForStrings(usize),
    #[error("integrity verification failed: {0}")]
    Integrity(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSummary {
    pub index: usize,
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportSymbolKind {
    Name { hint: u16, name: String },
    Ordinal(u16),
}

impl std::fmt::Display for ImportSymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportSymbolKind::Name { name, .. } => f.write_str(name),
            ImportSymbolKind::Ordinal(ord) => write!(f, "#{ord}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntryInfo {
    pub symbol: ImportSymbolKind,
    pub iat_slot_rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDllInfo {
    pub dll: String,
    pub name_rva: u32,
    pub descriptor_file_offset: usize,
    pub is_delay_load: bool,
    pub entries: Vec<ImportEntryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysis {
    pub machine: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_rva: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub data_directories: Vec<(u32, u32)>,
    pub sections: Vec<SectionSummary>,
    pub imports: Vec<ImportDllInfo>,
    pub delay_imports: Vec<ImportDllInfo>,
    pub total_import_count: usize,
    pub total_delay_import_count: usize,
    pub tls_callbacks: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct PatchConfig {
    pub dll_remap: BTreeMap<String, String>,
    pub force_windows_gui: bool,
    pub strip_console_flags: bool,
    pub allow_new_section: bool,
    pub hook_vfs: bool,
}

impl Default for PatchConfig {
    fn default() -> Self {
        Self {
            dll_remap: default_console_dll_remap(),
            force_windows_gui: true,
            strip_console_flags: true,
            allow_new_section: true,
            hook_vfs: false,
        }
    }
}

/// Default 12-DLL Xbox Scarlett -> Win64 PC shim mapping.
pub fn default_console_dll_remap() -> BTreeMap<String, String> {
    let pairs = [
        ("xmem.dll", "xmem_pc.dll"),
        ("d3d12_xs.dll", "dx12xs_pc.dll"),
        ("xg_xs.dll", "xg_pc.dll"),
        ("xcrdapi.dll", "xcrd_pc.dll"),
        ("chad.dll", "chad_pc.dll"),
        ("xboxbvhbuilder.dll", "xbvh_pc.dll"),
        ("amd_fidelityfx_loader_xbox.dll", "ffx_pc.dll"),
        ("bink2scarlett.dll", "bink2_pc.dll"),
        ("xapu.dll", "audio_pc.dll"),
        ("acphal.dll", "audio_pc.dll"),
        ("libhttpclient.gdk.dll", "hc_pc.dll"),
        ("gameinput.dll", "gi_pc.dll"),
    ];
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Optional VFS + loader + virtual registry redirection mapping
/// (`G:\`/`T:\`, local `xgameruntime.dll`, and `HKLM\...\OEM\ConsoleMode` Series S/X profile).
pub fn vfs_hook_dll_remap() -> [(&'static str, &'static str); 5] {
    [
        ("api-ms-win-core-file-l1-1-0.dll", "vfs_pc.dll"),
        ("api-ms-win-core-file-l2-1-0.dll", "vfs_pc.dll"),
        ("api-ms-win-core-libraryloader-l1-2-0.dll", "vfs_pc.dll"),
        ("api-ms-win-core-libraryloader-l1-2-1.dll", "vfs_pc.dll"),
        ("advapi32.dll", "vfs_pc.dll"),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemapAction {
    pub original_dll: String,
    pub new_dll: String,
    pub old_name_rva: u32,
    pub new_name_rva: u32,
    pub placement: String,
    pub is_delay_load: bool,
    pub import_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchReport {
    pub source_size: usize,
    pub patched_size: usize,
    pub old_subsystem: u16,
    pub new_subsystem: u16,
    pub old_dll_characteristics: u16,
    pub new_dll_characteristics: u16,
    pub old_checksum: u32,
    pub new_checksum: u32,
    pub remapped_dlls: Vec<RemapAction>,
    pub total_remapped_imports: usize,
    pub added_section: Option<String>,
    pub integrity_verified: bool,
}

struct HeaderOffsets {
    e_lfanew: usize,
    file_header: usize,
    optional_header: usize,
    section_table: usize,
    num_sections: usize,
    size_of_optional_header: usize,
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, PatchError> {
    let b: [u8; 2] = data
        .get(off..off + 2)
        .ok_or(PatchError::Malformed("unexpected EOF reading u16"))?
        .try_into()
        .unwrap();
    Ok(u16::from_le_bytes(b))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, PatchError> {
    let b: [u8; 4] = data
        .get(off..off + 4)
        .ok_or(PatchError::Malformed("unexpected EOF reading u32"))?
        .try_into()
        .unwrap();
    Ok(u32::from_le_bytes(b))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64, PatchError> {
    let b: [u8; 8] = data
        .get(off..off + 8)
        .ok_or(PatchError::Malformed("unexpected EOF reading u64"))?
        .try_into()
        .unwrap();
    Ok(u64::from_le_bytes(b))
}

fn write_u16(data: &mut [u8], off: usize, v: u16) -> Result<(), PatchError> {
    let dst = data
        .get_mut(off..off + 2)
        .ok_or(PatchError::Malformed("write u16 out of bounds"))?;
    dst.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], off: usize, v: u32) -> Result<(), PatchError> {
    let dst = data
        .get_mut(off..off + 4)
        .ok_or(PatchError::Malformed("write u32 out of bounds"))?;
    dst.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn parse_offsets(data: &[u8]) -> Result<HeaderOffsets, PatchError> {
    if data.len() < 0x40 || read_u16(data, 0)? != IMAGE_DOS_SIGNATURE {
        return Err(PatchError::Malformed("missing MZ DOS header"));
    }
    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if read_u32(data, e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err(PatchError::Malformed("missing PE\\0\\0 signature"));
    }
    let file_header = e_lfanew + 4;
    let machine = read_u16(data, file_header)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(PatchError::Unsupported(format!(
            "machine 0x{machine:04x} != AMD64"
        )));
    }
    let num_sections = read_u16(data, file_header + 2)? as usize;
    let size_of_optional_header = read_u16(data, file_header + 16)? as usize;
    let optional_header = file_header + 20;
    let magic = read_u16(data, optional_header)?;
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(PatchError::Unsupported(format!(
            "optional header magic 0x{magic:04x} != PE32+ (0x020b)"
        )));
    }
    let section_table = optional_header + size_of_optional_header;
    if data.len() < section_table + num_sections * 40 {
        return Err(PatchError::Malformed("section table truncated"));
    }
    Ok(HeaderOffsets {
        e_lfanew,
        file_header,
        optional_header,
        section_table,
        num_sections,
        size_of_optional_header,
    })
}

fn parse_sections(data: &[u8], hdr: &HeaderOffsets) -> Result<Vec<SectionSummary>, PatchError> {
    let mut out = Vec::with_capacity(hdr.num_sections);
    for i in 0..hdr.num_sections {
        let off = hdr.section_table + i * 40;
        let raw_name = data
            .get(off..off + 8)
            .ok_or(PatchError::Malformed("section name OOB"))?;
        let name = String::from_utf8_lossy(raw_name)
            .trim_end_matches('\0')
            .to_string();
        let virtual_size = read_u32(data, off + 8)?;
        let virtual_address = read_u32(data, off + 12)?;
        let size_of_raw_data = read_u32(data, off + 16)?;
        let pointer_to_raw_data = read_u32(data, off + 20)?;
        let characteristics = read_u32(data, off + 36)?;
        out.push(SectionSummary {
            index: i,
            name,
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
            characteristics,
        });
    }
    Ok(out)
}

pub fn rva_to_file_offset(sections: &[SectionSummary], rva: u32) -> Option<usize> {
    for s in sections {
        let span = s.virtual_size.max(s.size_of_raw_data);
        if rva >= s.virtual_address && rva - s.virtual_address < span {
            let delta = rva - s.virtual_address;
            if delta < s.size_of_raw_data {
                return Some((s.pointer_to_raw_data + delta) as usize);
            }
        }
    }
    None
}

fn read_cstr_at_rva(data: &[u8], sections: &[SectionSummary], rva: u32) -> Result<String, PatchError> {
    let off = rva_to_file_offset(sections, rva).ok_or(PatchError::UnmappedRva(rva))?;
    let tail = data.get(off..).ok_or(PatchError::Malformed("string RVA OOB"))?;
    let nul = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(PatchError::Malformed("unterminated C string"))?;
    Ok(String::from_utf8_lossy(&tail[..nul]).into_owned())
}

fn parse_thunk_list(
    data: &[u8],
    sections: &[SectionSummary],
    ilt_rva: u32,
    iat_rva: u32,
) -> Result<Vec<ImportEntryInfo>, PatchError> {
    let lookup_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
    if lookup_rva == 0 {
        return Ok(Vec::new());
    }
    let mut off = rva_to_file_offset(sections, lookup_rva).ok_or(PatchError::UnmappedRva(lookup_rva))?;
    let mut slot_rva = iat_rva;
    let mut entries = Vec::new();
    loop {
        let val = read_u64(data, off)?;
        off += 8;
        if val == 0 {
            break;
        }
        let symbol = if val & (1u64 << 63) != 0 {
            ImportSymbolKind::Ordinal((val & 0xFFFF) as u16)
        } else {
            let hint_rva = (val & 0x7FFF_FFFF) as u32;
            let hoff = rva_to_file_offset(sections, hint_rva).ok_or(PatchError::UnmappedRva(hint_rva))?;
            let hint = read_u16(data, hoff)?;
            let name_bytes = data
                .get(hoff + 2..)
                .ok_or(PatchError::Malformed("import hint name OOB"))?;
            let nul = name_bytes
                .iter()
                .position(|&b| b == 0)
                .ok_or(PatchError::Malformed("unterminated import name"))?;
            let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
            ImportSymbolKind::Name { hint, name }
        };
        entries.push(ImportEntryInfo {
            symbol,
            iat_slot_rva: slot_rva,
        });
        slot_rva = slot_rva.saturating_add(8);
    }
    Ok(entries)
}

pub fn analyze_pe(data: &[u8]) -> Result<PeAnalysis, PatchError> {
    // Also validate with `object` crate's PE64 parser.
    let _obj_pe = PeFile64::parse(data)
        .map_err(|_| PatchError::Malformed("object::PeFile64 failed to parse image"))?;

    let hdr = parse_offsets(data)?;
    let opt = hdr.optional_header;
    let machine = read_u16(data, hdr.file_header)?;
    let entry_rva = read_u32(data, opt + 16)?;
    let image_base = read_u64(data, opt + 24)?;
    let section_alignment = read_u32(data, opt + 32)?;
    let file_alignment = read_u32(data, opt + 36)?;
    let size_of_image = read_u32(data, opt + 56)?;
    let size_of_headers = read_u32(data, opt + 60)?;
    let checksum = read_u32(data, opt + 64)?;
    let subsystem = read_u16(data, opt + 68)?;
    let dll_characteristics = read_u16(data, opt + 70)?;
    let num_dd = read_u32(data, opt + 108)? as usize;

    let mut data_directories = Vec::with_capacity(num_dd);
    for i in 0..num_dd {
        let rva = read_u32(data, opt + 112 + i * 8)?;
        let sz = read_u32(data, opt + 112 + i * 8 + 4)?;
        data_directories.push((rva, sz));
    }

    let sections = parse_sections(data, &hdr)?;

    // Standard Imports
    let mut imports = Vec::new();
    if let Some(&(imp_rva, imp_sz)) = data_directories.get(dir::IMPORT) {
        if imp_rva != 0 && imp_sz != 0 {
            let mut off = rva_to_file_offset(&sections, imp_rva).ok_or(PatchError::UnmappedRva(imp_rva))?;
            loop {
                let ilt_rva = read_u32(data, off)?;
                let name_rva = read_u32(data, off + 12)?;
                let iat_rva = read_u32(data, off + 16)?;
                if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                    break;
                }
                let dll = read_cstr_at_rva(data, &sections, name_rva)?;
                let entries = parse_thunk_list(data, &sections, ilt_rva, iat_rva)?;
                imports.push(ImportDllInfo {
                    dll,
                    name_rva,
                    descriptor_file_offset: off,
                    is_delay_load: false,
                    entries,
                });
                off += 20;
            }
        }
    }

    // Delay Imports
    let mut delay_imports = Vec::new();
    if let Some(&(dimp_rva, dimp_sz)) = data_directories.get(dir::DELAY_IMPORT) {
        if dimp_rva != 0 && dimp_sz != 0 {
            let mut off = rva_to_file_offset(&sections, dimp_rva).ok_or(PatchError::UnmappedRva(dimp_rva))?;
            loop {
                let attrs = read_u32(data, off)?;
                let name_rva = read_u32(data, off + 4)?;
                let iat_rva = read_u32(data, off + 12)?;
                let int_rva = read_u32(data, off + 16)?;
                if attrs == 0 && name_rva == 0 && iat_rva == 0 && int_rva == 0 {
                    break;
                }
                let dll = read_cstr_at_rva(data, &sections, name_rva)?;
                let entries = parse_thunk_list(data, &sections, int_rva, iat_rva)?;
                delay_imports.push(ImportDllInfo {
                    dll,
                    name_rva,
                    descriptor_file_offset: off,
                    is_delay_load: true,
                    entries,
                });
                off += 32;
            }
        }
    }

    // TLS callbacks
    let mut tls_callbacks = Vec::new();
    if let Some(&(tls_rva, tls_sz)) = data_directories.get(dir::TLS) {
        if tls_rva != 0 && tls_sz >= 32 {
            if let Some(tls_off) = rva_to_file_offset(&sections, tls_rva) {
                let cb_va = read_u64(data, tls_off + 24)?;
                if cb_va > image_base {
                    if let Ok(cb_rva) = u32::try_from(cb_va - image_base) {
                        if let Some(mut cb_off) = rva_to_file_offset(&sections, cb_rva) {
                            for _ in 0..256 {
                                let va = read_u64(data, cb_off)?;
                                cb_off += 8;
                                if va == 0 {
                                    break;
                                }
                                tls_callbacks.push(va);
                            }
                        }
                    }
                }
            }
        }
    }

    let total_import_count = imports.iter().map(|m| m.entries.len()).sum();
    let total_delay_import_count = delay_imports.iter().map(|m| m.entries.len()).sum();

    let _ = hdr.e_lfanew;
    let _ = hdr.size_of_optional_header;

    Ok(PeAnalysis {
        machine,
        subsystem,
        dll_characteristics,
        image_base,
        size_of_image,
        entry_rva,
        section_alignment,
        file_alignment,
        size_of_headers,
        checksum,
        data_directories,
        sections,
        imports,
        delay_imports,
        total_import_count,
        total_delay_import_count,
        tls_callbacks,
    })
}

fn align_up(val: u32, align: u32) -> u32 {
    if align <= 1 {
        return val;
    }
    let mask = align - 1;
    (val.saturating_add(mask)) & !mask
}

/// Standard Windows PE checksum (`CheckSumMappedFile` equivalent).
pub fn compute_pe_checksum(data: &[u8], checksum_field_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if i == checksum_field_offset || i == checksum_field_offset + 2 {
            i += 2;
            continue;
        }
        let word = u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }
    if i < data.len() {
        sum += data[i] as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

pub fn patch_pe_bytes(input: &[u8], config: &PatchConfig) -> Result<(Vec<u8>, PatchReport), PatchError> {
    let before = analyze_pe(input)?;
    let mut out = input.to_vec();
    let hdr = parse_offsets(&out)?;
    let opt = hdr.optional_header;

    let mut remap: HashMap<String, String> = config
        .dll_remap
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    if config.hook_vfs {
        for (k, v) in vfs_hook_dll_remap() {
            remap.insert(k.to_string(), v.to_string());
        }
    }

    // Patch Subsystem & DllCharacteristics if requested.
    let old_subsystem = before.subsystem;
    let mut new_subsystem = old_subsystem;
    if config.force_windows_gui
        && (old_subsystem == subsystem::XBOX || old_subsystem == subsystem::XBOX_CODE_CATALOG)
    {
        new_subsystem = subsystem::WINDOWS_GUI;
        write_u16(&mut out, opt + 68, new_subsystem)?;
    }

    let old_dll_characteristics = before.dll_characteristics;
    let mut new_dll_characteristics = old_dll_characteristics;
    if config.strip_console_flags {
        new_dll_characteristics &= !(dll_flags::APPCONTAINER | dll_flags::FORCE_INTEGRITY);
        if new_dll_characteristics != old_dll_characteristics {
            write_u16(&mut out, opt + 70, new_dll_characteristics)?;
        }
    }

    // Collect all descriptors that need remapping.
    #[derive(Clone)]
    struct PendingRemap {
        orig_dll: String,
        new_dll: String,
        old_name_rva: u32,
        desc_off: usize,
        is_delay: bool,
        import_count: usize,
    }

    let mut pending = Vec::new();
    for m in before.imports.iter().chain(before.delay_imports.iter()) {
        if let Some(target) = remap.get(&m.dll.to_ascii_lowercase()) {
            pending.push(PendingRemap {
                orig_dll: m.dll.clone(),
                new_dll: target.clone(),
                old_name_rva: m.name_rva,
                desc_off: m.descriptor_file_offset,
                is_delay: m.is_delay_load,
                import_count: m.entries.len(),
            });
        }
    }

    // Separate in-place replacements (new.len() <= old.len()) from longer replacements.
    let mut longer_names: Vec<String> = Vec::new();
    for item in &pending {
        if item.new_dll.len() > item.orig_dll.len() && !longer_names.contains(&item.new_dll) {
            longer_names.push(item.new_dll.clone());
        }
    }
    let bytes_needed_for_longer: usize = longer_names.iter().map(|s| s.len() + 1).sum();

    // Try finding zero-padded tail slack in an existing readable, non-discardable section (prefer .rdata).
    let mut placed_longer_rvas: HashMap<String, (u32, String)> = HashMap::new();
    let mut added_section: Option<String> = None;

    if bytes_needed_for_longer > 0 {
        let mut candidate_secs: Vec<&SectionSummary> = before
            .sections
            .iter()
            .filter(|s| {
                (s.characteristics & IMAGE_SCN_MEM_READ) != 0
                    && (s.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
                    && s.size_of_raw_data > s.virtual_size
            })
            .collect();
        // Prefer .rdata first
        candidate_secs.sort_by_key(|s| if s.name == ".rdata" { 0 } else { 1 });

        let mut allocated_in_slack = false;
        for sec in candidate_secs {
            let slack = (sec.size_of_raw_data - sec.virtual_size) as usize;
            if slack >= bytes_needed_for_longer {
                let start_off = sec.pointer_to_raw_data as usize + sec.virtual_size as usize;
                let end_off = start_off + bytes_needed_for_longer;
                if out
                    .get(start_off..end_off)
                    .is_some_and(|slice| slice.iter().all(|&b| b == 0))
                {
                    let mut cursor_delta = sec.virtual_size;
                    for s in &longer_names {
                        let write_off = sec.pointer_to_raw_data as usize + cursor_delta as usize;
                        let rva = sec.virtual_address + cursor_delta;
                        let bytes = s.as_bytes();
                        out[write_off..write_off + bytes.len()].copy_from_slice(bytes);
                        out[write_off + bytes.len()] = 0;
                        placed_longer_rvas.insert(
                            s.clone(),
                            (rva, format!("section-slack({})", sec.name)),
                        );
                        cursor_delta += (bytes.len() + 1) as u32;
                    }
                    // Update section VirtualSize (still <= SizeOfRawData, so SizeOfImage unchanged).
                    let sec_hdr_off = hdr.section_table + sec.index * 40;
                    write_u32(&mut out, sec_hdr_off + 8, cursor_delta)?;
                    allocated_in_slack = true;
                    break;
                }
            }
        }

        if !allocated_in_slack {
            if !config.allow_new_section {
                return Err(PatchError::NoSpaceForStrings(bytes_needed_for_longer));
            }
            let sec_table_end = hdr.section_table + hdr.num_sections * 40;
            if sec_table_end + 40 > before.size_of_headers as usize {
                return Err(PatchError::NoSpaceForStrings(bytes_needed_for_longer));
            }

            let new_va = before
                .sections
                .iter()
                .map(|s| align_up(s.virtual_address + s.virtual_size.max(s.size_of_raw_data), before.section_alignment))
                .max()
                .unwrap_or(before.section_alignment);
            let raw_offset = align_up(out.len() as u32, before.file_alignment);
            if out.len() < raw_offset as usize {
                out.resize(raw_offset as usize, 0);
            }

            let mut sec_data = Vec::with_capacity(bytes_needed_for_longer);
            for s in &longer_names {
                let rva = new_va + sec_data.len() as u32;
                sec_data.extend_from_slice(s.as_bytes());
                sec_data.push(0);
                placed_longer_rvas.insert(s.clone(), (rva, "new-section(.pcshim)".to_string()));
            }
            let virtual_size = sec_data.len() as u32;
            let raw_size = align_up(virtual_size, before.file_alignment);
            sec_data.resize(raw_size as usize, 0);
            out.extend_from_slice(&sec_data);

            // Write new IMAGE_SECTION_HEADER
            let sh_off = sec_table_end;
            let mut name_buf = [0u8; 8];
            name_buf[..7].copy_from_slice(b".pcshim");
            out[sh_off..sh_off + 8].copy_from_slice(&name_buf);
            write_u32(&mut out, sh_off + 8, virtual_size)?;
            write_u32(&mut out, sh_off + 12, new_va)?;
            write_u32(&mut out, sh_off + 16, raw_size)?;
            write_u32(&mut out, sh_off + 20, raw_offset)?;
            // reloc/linenumbers = 0
            for z in (24..36).step_by(4) {
                write_u32(&mut out, sh_off + z, 0)?;
            }
            write_u32(
                &mut out,
                sh_off + 36,
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            )?;

            // Increment NumberOfSections and update SizeOfImage
            write_u16(&mut out, hdr.file_header + 2, (hdr.num_sections + 1) as u16)?;
            let new_size_of_image = align_up(new_va + virtual_size, before.section_alignment);
            write_u32(&mut out, opt + 56, new_size_of_image)?;
            added_section = Some(".pcshim".to_string());
        }
    }

    // Apply each DLL remap to its descriptor (and in-place string if shorter/equal).
    let mut actions = Vec::with_capacity(pending.len());
    let mut total_remapped_imports = 0usize;
    for item in pending {
        total_remapped_imports += item.import_count;
        let (new_rva, placement) = if item.new_dll.len() <= item.orig_dll.len() {
            let str_off = rva_to_file_offset(&before.sections, item.old_name_rva)
                .ok_or(PatchError::UnmappedRva(item.old_name_rva))?;
            let old_len = item.orig_dll.len();
            let new_bytes = item.new_dll.as_bytes();
            out[str_off..str_off + new_bytes.len()].copy_from_slice(new_bytes);
            out[str_off + new_bytes.len()..str_off + old_len + 1].fill(0);
            (item.old_name_rva, "in-place".to_string())
        } else {
            let (rva, place) = placed_longer_rvas
                .get(&item.new_dll)
                .cloned()
                .ok_or(PatchError::NoSpaceForStrings(item.new_dll.len() + 1))?;
            let name_rva_field_off = if item.is_delay {
                item.desc_off + 4
            } else {
                item.desc_off + 12
            };
            write_u32(&mut out, name_rva_field_off, rva)?;
            (rva, place)
        };
        actions.push(RemapAction {
            original_dll: item.orig_dll,
            new_dll: item.new_dll,
            old_name_rva: item.old_name_rva,
            new_name_rva: new_rva,
            placement,
            is_delay_load: item.is_delay,
            import_count: item.import_count,
        });
    }

    // Recompute PE checksum.
    let checksum_off = opt + 64;
    write_u32(&mut out, checksum_off, 0)?;
    let new_checksum = compute_pe_checksum(&out, checksum_off);
    write_u32(&mut out, checksum_off, new_checksum)?;

    // Verify integrity of patched PE against original PE!
    verify_patched_integrity(&before, input, &out, &remap)?;

    Ok((
        out.clone(),
        PatchReport {
            source_size: input.len(),
            patched_size: out.len(),
            old_subsystem,
            new_subsystem,
            old_dll_characteristics,
            new_dll_characteristics,
            old_checksum: before.checksum,
            new_checksum,
            remapped_dlls: actions,
            total_remapped_imports,
            added_section,
            integrity_verified: true,
        },
    ))
}

pub fn verify_patched_integrity(
    before: &PeAnalysis,
    orig_bytes: &[u8],
    patched_bytes: &[u8],
    remap: &HashMap<String, String>,
) -> Result<(), PatchError> {
    let after = analyze_pe(patched_bytes)?;

    if before.entry_rva != after.entry_rva {
        return Err(PatchError::Integrity("AddressOfEntryPoint changed".into()));
    }
    if before.image_base != after.image_base {
        return Err(PatchError::Integrity("ImageBase changed".into()));
    }
    if before.tls_callbacks != after.tls_callbacks {
        return Err(PatchError::Integrity("TLS callbacks changed".into()));
    }

    // Verify every original section kept its VA, raw offset, raw size, and critical sections (.text/.pdata/.reloc/.tls) are byte-identical.
    for (idx, bs) in before.sections.iter().enumerate() {
        let Some(as_) = after.sections.get(idx) else {
            return Err(PatchError::Integrity(format!("missing section {idx}")));
        };
        if bs.virtual_address != as_.virtual_address
            || bs.pointer_to_raw_data != as_.pointer_to_raw_data
            || bs.size_of_raw_data != as_.size_of_raw_data
        {
            return Err(PatchError::Integrity(format!(
                "section {} layout shifted",
                bs.name
            )));
        }
        if matches!(bs.name.as_str(), ".text" | ".pdata" | ".reloc" | ".tls") && bs.size_of_raw_data > 0 {
            let start = bs.pointer_to_raw_data as usize;
            let end = start + bs.size_of_raw_data as usize;
            if orig_bytes.get(start..end) != patched_bytes.get(start..end) {
                return Err(PatchError::Integrity(format!(
                    "critical section {} bytes mutated",
                    bs.name
                )));
            }
        }
    }

    // Verify DataDirectory entries for BASERELOC, EXCEPTION, TLS, EXPORT didn't move.
    for &dd_idx in &[dir::EXPORT, dir::EXCEPTION, dir::BASERELOC, dir::TLS] {
        if before.data_directories.get(dd_idx) != after.data_directories.get(dd_idx) {
            return Err(PatchError::Integrity(format!(
                "data directory[{dd_idx}] changed"
            )));
        }
    }

    // Verify every single import entry and IAT slot RVA matches 1:1.
    if before.imports.len() != after.imports.len()
        || before.delay_imports.len() != after.delay_imports.len()
    {
        return Err(PatchError::Integrity("import descriptor count changed".into()));
    }
    for (bm, am) in before
        .imports
        .iter()
        .chain(before.delay_imports.iter())
        .zip(after.imports.iter().chain(after.delay_imports.iter()))
    {
        let expected_dll = remap
            .get(&bm.dll.to_ascii_lowercase())
            .map(String::as_str)
            .unwrap_or(&bm.dll);
        if am.dll != expected_dll {
            return Err(PatchError::Integrity(format!(
                "DLL remap mismatch: expected {expected_dll}, got {}",
                am.dll
            )));
        }
        if bm.entries.len() != am.entries.len() {
            return Err(PatchError::Integrity(format!(
                "symbol count changed for {}",
                bm.dll
            )));
        }
        for (be, ae) in bm.entries.iter().zip(am.entries.iter()) {
            if be.iat_slot_rva != ae.iat_slot_rva || be.symbol != ae.symbol {
                return Err(PatchError::Integrity(format!(
                    "import slot mismatch in {} ({})",
                    bm.dll, be.symbol
                )));
            }
        }
    }

    Ok(())
}

pub fn analyze_file(path: &Path) -> Result<PeAnalysis, PatchError> {
    let bytes = fs::read(path)?;
    analyze_pe(&bytes)
}

/// Verify an already-patched PE file against the original PE file and expected remap config.
pub fn verify_files(
    original_path: &Path,
    patched_path: &Path,
    config: &PatchConfig,
) -> Result<PeAnalysis, PatchError> {
    let orig_bytes = fs::read(original_path)?;
    let patched_bytes = fs::read(patched_path)?;
    let before = analyze_pe(&orig_bytes)?;
    let mut remap: HashMap<String, String> = config
        .dll_remap
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    if config.hook_vfs {
        for (k, v) in vfs_hook_dll_remap() {
            remap.insert((*k).to_string(), (*v).to_string());
        }
    }
    verify_patched_integrity(&before, &orig_bytes, &patched_bytes, &remap)?;
    analyze_pe(&patched_bytes)
}

pub fn patch_file(
    input_path: &Path,
    output_path: Option<&Path>,
    config: &PatchConfig,
) -> Result<PatchReport, PatchError> {
    let input = fs::read(input_path)?;
    let (patched, report) = patch_pe_bytes(&input, config)?;
    if let Some(out) = output_path {
        if out == input_path {
            return Err(PatchError::Unsupported(
                "refusing to overwrite input PE in-place; specify a separate output path".into(),
            ));
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out, patched)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE32+ image with `.text`, `.rdata` (packed import table + DLL strings),
    /// `.pdata`, `.tls`, and `.reloc` sections to test both in-place and longer-name remapping.
    fn make_synthetic_pe(with_rdata_slack: bool, subsystem_val: u16) -> Vec<u8> {
        let section_align = 0x1000u32;
        let file_align = 0x200u32;
        let num_sections = 5u16; // .text, .rdata, .pdata, .tls, .reloc
        let e_lfanew = 0x80usize;
        let opt_size = 0xF0u16;
        let size_of_headers = 0x400u32;

        // .rdata contents at RVA 0x2000, raw 0x600:
        // Place 3 descriptors (xmem.dll, XboxBvhBuilder.dll, GameInput.dll) + terminator = 4*20 = 80 bytes
        // ILTs, IATs, Hint/Name, packed DLL names (no slack between names!).
        let rdata_rva = 0x2000u32;
        let mut rdata = vec![0u8; 0x300];
        let mut cursor = 80usize; // after 4*20 import descriptors

        let push_bytes = |buf: &mut Vec<u8>, cur: &mut usize, bytes: &[u8]| -> u32 {
            let rva = rdata_rva + *cur as u32;
            buf[*cur..*cur + bytes.len()].copy_from_slice(bytes);
            *cur += bytes.len();
            rva
        };

        // Symbols
        let hn_xmem = push_bytes(&mut rdata, &mut cursor, b"\x00\x00XMemAlloc\0");
        let hn_bvh = push_bytes(&mut rdata, &mut cursor, b"\x00\x00??1XboxBvhBuilder@@QEAA@XZ\0");

        // Align cursor to 8 for thunks
        cursor = (cursor + 7) & !7;

        let ilt_xmem_rva = rdata_rva + cursor as u32;
        rdata[cursor..cursor + 8].copy_from_slice(&(hn_xmem as u64).to_le_bytes());
        cursor += 16;
        let iat_xmem_rva = rdata_rva + cursor as u32;
        rdata[cursor..cursor + 8].copy_from_slice(&(hn_xmem as u64).to_le_bytes());
        cursor += 16;

        let ilt_bvh_rva = rdata_rva + cursor as u32;
        rdata[cursor..cursor + 8].copy_from_slice(&(hn_bvh as u64).to_le_bytes());
        cursor += 16;
        let iat_bvh_rva = rdata_rva + cursor as u32;
        rdata[cursor..cursor + 8].copy_from_slice(&(hn_bvh as u64).to_le_bytes());
        cursor += 16;

        // Ordinal #1 for GameInput.dll
        let ord1: u64 = (1u64 << 63) | 1;
        let ilt_gi_rva = rdata_rva + cursor as u32;
        rdata[cursor..cursor + 8].copy_from_slice(&ord1.to_le_bytes());
        cursor += 16;
        let iat_gi_rva = rdata_rva + cursor as u32;
        rdata[cursor..cursor + 8].copy_from_slice(&ord1.to_le_bytes());
        cursor += 16;

        // Pack DLL names tightly back-to-back (zero gap!)
        let name_xmem_rva = push_bytes(&mut rdata, &mut cursor, b"xmem.dll\0");
        let name_bvh_rva = push_bytes(&mut rdata, &mut cursor, b"XboxBvhBuilder.dll\0");
        let name_gi_rva = push_bytes(&mut rdata, &mut cursor, b"GameInput.dll\0");

        // Write 3 descriptors
        let write_desc = |buf: &mut [u8], idx: usize, ilt: u32, name: u32, iat: u32| {
            let o = idx * 20;
            buf[o..o + 4].copy_from_slice(&ilt.to_le_bytes());
            buf[o + 12..o + 16].copy_from_slice(&name.to_le_bytes());
            buf[o + 16..o + 20].copy_from_slice(&iat.to_le_bytes());
        };
        write_desc(&mut rdata, 0, ilt_xmem_rva, name_xmem_rva, iat_xmem_rva);
        write_desc(&mut rdata, 1, ilt_bvh_rva, name_bvh_rva, iat_bvh_rva);
        write_desc(&mut rdata, 2, ilt_gi_rva, name_gi_rva, iat_gi_rva);

        let rdata_vsize = if with_rdata_slack {
            cursor as u32 // leaves > 0x100 bytes of zero slack before 0x400 raw_size
        } else {
            0x200u32 // exactly raw_size = 0x200 -> zero slack!
        };
        if !with_rdata_slack {
            rdata.truncate(0x200);
        } else {
            rdata.resize(0x400, 0);
        }
        let rdata_rsize = rdata.len() as u32;

        // .tls at RVA 0x4000, raw 0xC00 (or after rdata)
        let mut tls_sec = vec![0u8; 0x200];
        // TLS directory at offset 0 (RVA 0x4000), AddressOfCallBacks at offset 24 -> 0x140004030
        let cb_va = 0x1_4000_4030u64;
        tls_sec[24..32].copy_from_slice(&cb_va.to_le_bytes());
        tls_sec[0x30..0x38].copy_from_slice(&0x1_4000_1000u64.to_le_bytes());

        let text_sec = vec![0xCCu8; 0x200];
        let pdata_sec = vec![0x11u8; 0x200];
        let reloc_sec = vec![0x22u8; 0x200];

        let mut img = vec![0u8; size_of_headers as usize];
        img[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        img[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        img[e_lfanew..e_lfanew + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        let fh = e_lfanew + 4;
        img[fh..fh + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        img[fh + 2..fh + 4].copy_from_slice(&num_sections.to_le_bytes());
        img[fh + 16..fh + 18].copy_from_slice(&opt_size.to_le_bytes());
        img[fh + 18..fh + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        let opt = fh + 20;
        img[opt..opt + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        img[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint
        img[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // ImageBase
        img[opt + 32..opt + 36].copy_from_slice(&section_align.to_le_bytes());
        img[opt + 36..opt + 40].copy_from_slice(&file_align.to_le_bytes());
        img[opt + 56..opt + 60].copy_from_slice(&0x6000u32.to_le_bytes()); // SizeOfImage
        img[opt + 60..opt + 64].copy_from_slice(&size_of_headers.to_le_bytes());
        img[opt + 68..opt + 70].copy_from_slice(&subsystem_val.to_le_bytes());
        img[opt + 70..opt + 72].copy_from_slice(&(dll_flags::DYNAMIC_BASE | dll_flags::APPCONTAINER).to_le_bytes());
        img[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        // DataDirectories: IMPORT=1, EXCEPTION=3, BASERELOC=5, TLS=9
        let set_dd = |buf: &mut [u8], idx: usize, rva: u32, sz: u32| {
            let o = opt + 112 + idx * 8;
            buf[o..o + 4].copy_from_slice(&rva.to_le_bytes());
            buf[o + 4..o + 8].copy_from_slice(&sz.to_le_bytes());
        };
        set_dd(&mut img, dir::IMPORT, rdata_rva, 80);
        set_dd(&mut img, dir::EXCEPTION, 0x3000, 0x200);
        set_dd(&mut img, dir::TLS, 0x4000, 0x28);
        set_dd(&mut img, dir::BASERELOC, 0x5000, 0x200);

        let st = opt + opt_size as usize;
        let secs: [(&[u8], u32, u32, u32, u32); 5] = [
            (b".text\0\0\0", 0x1000, 0x200, 0x400, 0x6000_0020),
            (b".rdata\0\0", 0x2000, rdata_vsize, 0x600, 0x4000_0040),
            (b".pdata\0\0", 0x3000, 0x200, (0x600 + rdata_rsize), 0x4000_0040),
            (b".tls\0\0\0\0", 0x4000, 0x200, (0x800 + rdata_rsize), 0xC000_0040),
            (b".reloc\0\0", 0x5000, 0x200, (0xA00 + rdata_rsize), 0x4200_0040),
        ];
        for (i, (name, va, vs, roff, chars)) in secs.iter().enumerate() {
            let o = st + i * 40;
            let rsz = if i == 1 { rdata_rsize } else { 0x200 };
            img[o..o + 8].copy_from_slice(name);
            img[o + 8..o + 12].copy_from_slice(&vs.to_le_bytes());
            img[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            img[o + 16..o + 20].copy_from_slice(&rsz.to_le_bytes());
            img[o + 20..o + 24].copy_from_slice(&roff.to_le_bytes());
            img[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }

        img.extend_from_slice(&text_sec);
        img.extend_from_slice(&rdata);
        img.extend_from_slice(&pdata_sec);
        img.extend_from_slice(&tls_sec);
        img.extend_from_slice(&reloc_sec);
        img
    }

    #[test]
    fn patches_slack_without_corrupting_adjacent_strings_or_sections() {
        let pe = make_synthetic_pe(true, subsystem::XBOX);
        let (patched, report) = patch_pe_bytes(&pe, &PatchConfig::default()).unwrap();
        assert!(report.integrity_verified);
        assert_eq!(report.old_subsystem, subsystem::XBOX);
        assert_eq!(report.new_subsystem, subsystem::WINDOWS_GUI);
        assert_eq!(report.new_dll_characteristics & dll_flags::APPCONTAINER, 0);
        assert_eq!(report.added_section, None);
        assert_eq!(report.remapped_dlls.len(), 3);

        let after = analyze_pe(&patched).unwrap();
        let dlls: Vec<_> = after.imports.iter().map(|m| m.dll.as_str()).collect();
        assert_eq!(dlls, vec!["xmem_pc.dll", "xbvh_pc.dll", "gi_pc.dll"]);
        assert_eq!(after.imports[1].entries[0].symbol.to_string(), "??1XboxBvhBuilder@@QEAA@XZ");
        assert_eq!(after.imports[2].entries[0].symbol, ImportSymbolKind::Ordinal(1));
    }

    #[test]
    fn appends_pcshim_section_when_no_slack_exists() {
        let pe = make_synthetic_pe(false, subsystem::XBOX);
        let (patched, report) = patch_pe_bytes(&pe, &PatchConfig::default()).unwrap();
        assert!(report.integrity_verified);
        assert_eq!(report.added_section.as_deref(), Some(".pcshim"));
        let after = analyze_pe(&patched).unwrap();
        assert_eq!(after.sections.len(), 6);
        assert_eq!(after.sections[5].name, ".pcshim");
        assert_eq!(after.imports[0].dll, "xmem_pc.dll");
        assert_eq!(after.imports[1].dll, "xbvh_pc.dll");
        assert_eq!(after.imports[2].dll, "gi_pc.dll");
    }

    #[test]
    fn refuses_in_place_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.exe");
        fs::write(&path, make_synthetic_pe(true, subsystem::XBOX)).unwrap();
        let err = patch_file(&path, Some(&path), &PatchConfig::default()).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
    }
}
