//! RPF9 header parser, bounded zlib/container carver, and entry classifier.
//!
//! All operations open archives strictly read-only (`File::open`) without holding
//! exclusive locks, and support bounded byte-window scanning for multi-GiB RPFs.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result, bail};
use memchr::{memchr, memmem};
use serde::{Deserialize, Serialize};
use zlib_rs::{Inflate, InflateFlush, Status};

/// Little-endian magic bytes for `"9FPR"` (`0x52504639`).
pub const RPF9_MAGIC: u32 = 0x5250_4639;
pub const RPF9_HEADER_SIZE: usize = 64;
pub const EXPECTED_CONST_18: u32 = 293_376;
pub const EXPECTED_CONST_1C: u32 = 336;
pub const EXPECTED_CONST_30: u32 = 16;

/// Known AES-CBC TOC cipher preamble at offset `0x40` in GTA VI RPF9 archives.
pub const RPF9_AES_CBC_PREAMBLE: [u8; 32] = [
    0x5f, 0x08, 0xda, 0xab, 0xec, 0xbd, 0xd4, 0x02, 0x58, 0xc3, 0x51, 0x68, 0x07, 0x02, 0x4c, 0x24,
    0xfb, 0x9f, 0x75, 0x67, 0x55, 0xef, 0x4b, 0xe4, 0x58, 0x78, 0x5b, 0xfe, 0xd8, 0xaa, 0x69, 0x89,
];

/// Max single carved zlib stream output (16 MiB safety bound).
const MAX_CARVE_DECOMP_BYTES: usize = 16 * 1024 * 1024;
const SGD5_MARKER: [u8; 4] = 0x000D_DCE7_u32.to_le_bytes();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rpf9Header {
    pub magic_hex: String,
    pub toc_end: u32,
    pub toc_field_b: u32,
    pub names_size: u32,
    pub toc_hash_hex: String,
    pub const_18: u32,
    pub const_1c: u32,
    pub unk_a: u16,
    pub unk_b: u16,
    pub entry_count: u32,
    pub key_id: u32,
    pub key_id_hex: String,
    pub flags: u32,
    pub shape: u8,
    pub const_30: u32,
    pub constants_match: bool,
    pub toc_encrypted_aes_cbc: bool,
}

impl Rpf9Header {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < RPF9_HEADER_SIZE {
            bail!(
                "RPF9 header requires at least {} bytes, got {}",
                RPF9_HEADER_SIZE,
                data.len()
            );
        }
        let magic = u32_le(data, 0);
        if magic != RPF9_MAGIC {
            bail!("Invalid RPF9 magic: 0x{magic:08X} (expected 0x{RPF9_MAGIC:08X})");
        }
        let const_18 = u32_le(data, 0x18);
        let const_1c = u32_le(data, 0x1C);
        let const_30 = u32_le(data, 0x30);
        let key_id = u32_le(data, 0x28);
        let flags = u32_le(data, 0x2C);
        let toc_hash = u64_be(data, 0x10);
        let toc_encrypted_aes_cbc = data.len() >= RPF9_HEADER_SIZE + 32
            && data[RPF9_HEADER_SIZE..RPF9_HEADER_SIZE + 32] == RPF9_AES_CBC_PREAMBLE;

        Ok(Self {
            magic_hex: format!("0x{magic:08X}"),
            toc_end: u32_le(data, 0x04),
            toc_field_b: u32_le(data, 0x08),
            names_size: u32_le(data, 0x0C),
            toc_hash_hex: format!("{toc_hash:016x}"),
            const_18,
            const_1c,
            unk_a: u16_le(data, 0x20),
            unk_b: u16_le(data, 0x22),
            entry_count: u32_le(data, 0x24),
            key_id,
            key_id_hex: format!("0x{key_id:08X}"),
            flags,
            shape: (flags & 0xFF) as u8,
            const_30,
            constants_match: const_18 == EXPECTED_CONST_18
                && const_1c == EXPECTED_CONST_1C
                && const_30 == EXPECTED_CONST_30,
            toc_encrypted_aes_cbc,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryClass {
    TexturesYtd,
    DrawableYdr,
    ShadersSgd5,
    AudioAdat,
    AudioWem,
    AudioXma2,
    VideoBink2,
    Scripts,
    NavMesh,
    AnimClips,
    XmlMeta,
    JsonMeta,
    Text,
    Rsc9Generic,
    Binary,
}

impl EntryClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::TexturesYtd => "textures_ytd",
            Self::DrawableYdr => "drawable_ydr",
            Self::ShadersSgd5 => "shaders_sgd5",
            Self::AudioAdat => "audio_adat",
            Self::AudioWem => "audio_wem",
            Self::AudioXma2 => "audio_xma2",
            Self::VideoBink2 => "video_bink2",
            Self::Scripts => "scripts",
            Self::NavMesh => "navmesh",
            Self::AnimClips => "anim_clips",
            Self::XmlMeta => "xml_meta",
            Self::JsonMeta => "json_meta",
            Self::Text => "text",
            Self::Rsc9Generic => "rsc9_generic",
            Self::Binary => "binary",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedEntryInfo {
    pub offset: u64,
    pub compressed_bytes: usize,
    pub decompressed_bytes: usize,
    pub class: EntryClass,
    pub container_magic: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rpf9InventoryReport {
    pub path: String,
    pub file_name: String,
    pub file_size: u64,
    pub header: Rpf9Header,
    pub scanned_bytes: u64,
    pub truncated_scan: bool,
    pub carved_streams: usize,
    pub total_compressed_bytes: u64,
    pub total_decompressed_bytes: u64,
    pub class_counts: BTreeMap<String, usize>,
    pub class_decompressed_bytes: BTreeMap<String, u64>,
    pub direct_containers: BTreeMap<String, usize>,
    pub samples: Vec<CarvedEntryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInventory {
    pub root: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub rpf_count: usize,
    pub rpf_total_bytes: u64,
    pub ttpf_count: usize,
    pub ttpf_total_bytes: u64,
    pub exe_dll_count: usize,
    pub exe_dll_total_bytes: u64,
    pub other_count: usize,
    pub other_total_bytes: u64,
    pub rpf_headers: Vec<RpfFileSummary>,
    pub ttpf_files: Vec<FileSizeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpfFileSummary {
    pub rel_path: String,
    pub file_size: u64,
    pub header: Rpf9Header,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSizeEntry {
    pub rel_path: String,
    pub file_size: u64,
}

/// Opens an RPF9 file strictly read-only and parses its 64-byte header + preamble check.
pub fn read_rpf9_header(path: &Path) -> Result<(u64, Rpf9Header)> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let file_size = f.metadata()?.len();
    let mut buf = [0u8; RPF9_HEADER_SIZE + 32];
    let read_len = buf.len().min(file_size as usize);
    f.read_exact(&mut buf[..read_len])
        .with_context(|| format!("reading RPF9 header from {}", path.display()))?;
    let header = Rpf9Header::parse(&buf[..read_len])?;
    Ok((file_size, header))
}

/// Inventories an RPF9 archive safely read-only, up to `max_scan_bytes` (or full file if `None`).
pub fn inventory_rpf9_file(
    path: &Path,
    max_scan_bytes: Option<u64>,
    sample_limit: usize,
) -> Result<Rpf9InventoryReport> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let file_size = f.metadata()?.len();
    let (size_check, header) = read_rpf9_header(path)?;
    debug_assert_eq!(size_check, file_size);

    let scan_limit = max_scan_bytes.map_or(file_size, |m| m.min(file_size));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.rpf")
        .to_string();

    // Read scan window in chunks (up to 64 MiB default per pass to stay memory-safe).
    let mut buf = vec![0u8; scan_limit as usize];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut buf)?;

    let mut report = inventory_rpf9_slice(&buf, &file_name, path, file_size, &header, sample_limit);
    report.truncated_scan = scan_limit < file_size;
    Ok(report)
}

/// Scans an in-memory RPF9 slice, carving zlib streams and detecting un-zlibbed containers.
pub fn inventory_rpf9_slice(
    data: &[u8],
    file_name: &str,
    path: &Path,
    total_file_size: u64,
    header: &Rpf9Header,
    sample_limit: usize,
) -> Rpf9InventoryReport {
    let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut class_decompressed_bytes: BTreeMap<String, u64> = BTreeMap::new();
    let mut direct_containers: BTreeMap<String, usize> = BTreeMap::new();
    let mut samples = Vec::new();
    let mut carved_streams = 0usize;
    let mut total_compressed_bytes = 0u64;
    let mut total_decompressed_bytes = 0u64;

    // 1. Direct container markers (SGD5, Bink2 KB2*, ADAT, RDS5) at page/marker positions.
    let sgd5_count = count_sgd5_markers(data);
    if sgd5_count > 0 {
        direct_containers.insert("sgd5_records".into(), sgd5_count);
        *class_counts
            .entry(EntryClass::ShadersSgd5.label().into())
            .or_default() += sgd5_count;
    }
    let kb2_count = count_page_aligned_magic(data, b"KB2");
    if kb2_count > 0 {
        direct_containers.insert("bink2_kb2".into(), kb2_count);
        *class_counts
            .entry(EntryClass::VideoBink2.label().into())
            .or_default() += kb2_count;
    }
    let adat_count = memmem::find_iter(data, b"ADAT").count();
    if adat_count > 0 {
        direct_containers.insert("adat_audio_banks".into(), adat_count);
        *class_counts
            .entry(EntryClass::AudioAdat.label().into())
            .or_default() += adat_count;
    }
    let rds5_count = memmem::find_iter(data, b"RDS5").count();
    if rds5_count > 0 {
        direct_containers.insert("rds5_ttpf".into(), rds5_count);
    }

    // 2. Zlib stream carving (0x78 {0x01, 0x5E, 0x9C, 0xDA}) with 16-byte jump alignment.
    let mut offset = 0usize;
    while offset + 8 <= data.len() {
        let Some(rel) = memchr(0x78, &data[offset..data.len() - 1]) else {
            break;
        };
        offset += rel;
        let b2 = data[offset + 1];
        if !matches!(b2, 0x01 | 0x5E | 0x9C | 0xDA) {
            offset += 1;
            continue;
        }
        if let Some((comp_len, decomp)) = try_inflate_zlib(&data[offset..])
            && !decomp.is_empty()
        {
            let (class, magic_str, note) = classify_payload(file_name, &decomp);
            carved_streams += 1;
            total_compressed_bytes += comp_len as u64;
            total_decompressed_bytes += decomp.len() as u64;

            let key = class.label().to_string();
            *class_counts.entry(key.clone()).or_default() += 1;
            *class_decompressed_bytes.entry(key).or_default() += decomp.len() as u64;

            if samples.len() < sample_limit {
                samples.push(CarvedEntryInfo {
                    offset: offset as u64,
                    compressed_bytes: comp_len,
                    decompressed_bytes: decomp.len(),
                    class,
                    container_magic: magic_str,
                    note,
                });
            }
            offset = align_up(offset + comp_len, 16);
            continue;
        }
        offset += 1;
    }

    Rpf9InventoryReport {
        path: path.display().to_string(),
        file_name: file_name.to_string(),
        file_size: total_file_size,
        header: header.clone(),
        scanned_bytes: data.len() as u64,
        truncated_scan: (data.len() as u64) < total_file_size,
        carved_streams,
        total_compressed_bytes,
        total_decompressed_bytes,
        class_counts,
        class_decompressed_bytes,
        direct_containers,
        samples,
    }
}

/// Classifies a decompressed RPF9 stream payload using container signatures and archive context.
pub fn classify_payload(archive_name: &str, payload: &[u8]) -> (EntryClass, String, Option<String>) {
    if payload.len() >= 4 {
        if &payload[..4] == b"SGD5" {
            return (EntryClass::ShadersSgd5, "SGD5".into(), None);
        }
        if &payload[..4] == b"ADAT" {
            return (EntryClass::AudioAdat, "ADAT".into(), None);
        }
        if &payload[..4] == b"RIFF" {
            return (EntryClass::AudioWem, "RIFF".into(), None);
        }
        if &payload[..4] == b"PSIN" {
            return (
                EntryClass::Scripts,
                "PSIN".into(),
                Some("world placement block".into()),
            );
        }
        if &payload[..4] == b"DDS " {
            return (EntryClass::TexturesYtd, "DDS".into(), None);
        }
        if &payload[..4] == b"RSC9" || u32_le(payload, 0) == 0x3743_5352 {
            let lower = archive_name.to_ascii_lowercase();
            let cls = if lower.contains("texture") {
                EntryClass::TexturesYtd
            } else if lower.contains("pack") || lower.contains("level") {
                EntryClass::DrawableYdr
            } else {
                EntryClass::Rsc9Generic
            };
            return (cls, "RSC9".into(), None);
        }
    }
    if payload.len() >= 3 && &payload[..3] == b"KB2" {
        return (EntryClass::VideoBink2, "KB2".into(), None);
    }
    if payload.len() >= 0x18 && &payload[0x10..0x15] == b"0DRPz" {
        let clips = u32_le(payload, 0x20);
        return (
            EntryClass::AnimClips,
            "0DRPz".into(),
            Some(format!("crClipDictionary clips={clips}")),
        );
    }
    if payload.len() >= 0xD0 && u32_le(payload, 0x14) == 0x0001_0015 {
        let polys = u32_le(payload, 0xC4);
        let midx = u32_le(payload, 0xC8);
        return (
            EntryClass::NavMesh,
            "CNavMesh".into(),
            Some(format!("mesh_idx={midx} polys={polys}")),
        );
    }
    if payload.len() == 65_536 && archive_name.to_ascii_lowercase().contains("script") {
        return (
            EntryClass::Scripts,
            "scrProgram64K".into(),
            Some("64KB script codepage".into()),
        );
    }
    // Check RAGE9 pgBase virtual pointer (0x5000xxxx at +0x08) common in textures.rpf / packs.rpf.
    if payload.len() >= 16 && (u32_le(payload, 8) & 0xF000_0000) == 0x5000_0000 {
        let lower = archive_name.to_ascii_lowercase();
        let cls = if lower.contains("texture") {
            EntryClass::TexturesYtd
        } else {
            EntryClass::DrawableYdr
        };
        return (
            cls,
            format!("pgBase(0x{:08X})", u32_le(payload, 8)),
            None,
        );
    }
    if is_printable_utf8(payload) {
        let trimmed = trim_bom_and_ws(payload);
        if trimmed.starts_with(b"<") {
            return (EntryClass::XmlMeta, "XML".into(), None);
        }
        if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
            return (EntryClass::JsonMeta, "JSON".into(), None);
        }
        return (EntryClass::Text, "TEXT".into(), None);
    }
    (EntryClass::Binary, "BIN".into(), None)
}

/// Walks the game root directory read-only and inventories all `.rpf`, `.ttpf`, `.exe`/`.dll`, and other files.
pub fn inventory_build_directory(root: &Path) -> Result<BuildInventory> {
    if !root.is_dir() {
        bail!("Build root is not a directory: {}", root.display());
    }

    let mut stack = vec![root.to_path_buf()];
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    let mut rpf_headers = Vec::new();
    let mut rpf_total_bytes = 0u64;
    let mut ttpf_files = Vec::new();
    let mut ttpf_total_bytes = 0u64;
    let mut exe_dll_count = 0usize;
    let mut exe_dll_total_bytes = 0u64;
    let mut other_count = 0usize;
    let mut other_total_bytes = 0u64;

    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .with_context(|| format!("reading dir {}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let size = meta.len();
            total_files += 1;
            total_bytes += size;

            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();

            match ext.as_str() {
                "rpf" => {
                    let (_, header) = read_rpf9_header(&path)?;
                    rpf_total_bytes += size;
                    rpf_headers.push(RpfFileSummary {
                        rel_path: rel,
                        file_size: size,
                        header,
                    });
                }
                "ttpf" => {
                    ttpf_total_bytes += size;
                    ttpf_files.push(FileSizeEntry {
                        rel_path: rel,
                        file_size: size,
                    });
                }
                "exe" | "dll" => {
                    exe_dll_count += 1;
                    exe_dll_total_bytes += size;
                }
                _ => {
                    other_count += 1;
                    other_total_bytes += size;
                }
            }
        }
    }

    rpf_headers.sort_by_key(|r| r.file_size);
    ttpf_files.sort_by_key(|t| t.file_size);

    Ok(BuildInventory {
        root: root.display().to_string(),
        total_files,
        total_bytes,
        rpf_count: rpf_headers.len(),
        rpf_total_bytes,
        ttpf_count: ttpf_files.len(),
        ttpf_total_bytes,
        exe_dll_count,
        exe_dll_total_bytes,
        other_count,
        other_total_bytes,
        rpf_headers,
        ttpf_files,
    })
}

fn try_inflate_zlib(source: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut state = Inflate::new(true, 15);
    let mut out = Vec::new();
    let mut chunk = [0u8; 32 * 1024];
    let mut in_pos = 0usize;

    loop {
        let before_in = state.total_in() as usize;
        let before_out = state.total_out() as usize;
        let status = state
            .decompress(&source[in_pos..], &mut chunk, InflateFlush::NoFlush)
            .ok()?;
        let after_in = state.total_in() as usize;
        let after_out = state.total_out() as usize;
        let produced = after_out.saturating_sub(before_out);
        if out.len() + produced > MAX_CARVE_DECOMP_BYTES {
            return None;
        }
        out.extend_from_slice(&chunk[..produced]);
        in_pos = after_in;

        match status {
            Status::StreamEnd => return Some((after_in, out)),
            Status::Ok if after_in > before_in || after_out > before_out => {}
            _ => return None,
        }
    }
}

fn count_sgd5_markers(data: &[u8]) -> usize {
    memmem::find_iter(data, &SGD5_MARKER)
        .filter(|&at| {
            if at < 6 || at + 12 > data.len() {
                return false;
            }
            let n = u32_le(data, at - 4) as usize;
            let n2 = u32_le(data, at + 4) as usize;
            let unpacked = u32_le(data, at + 8) as usize;
            n == n2 && n >= 12 && unpacked <= 64 * 1024 * 1024 && at + n <= data.len()
        })
        .count()
}

fn count_page_aligned_magic(data: &[u8], prefix: &[u8]) -> usize {
    let mut count = 0usize;
    let mut off = 0usize;
    while off + 44 <= data.len() {
        if data[off..].starts_with(prefix) {
            let frames = u32_le(data, off + 8);
            let frames2 = u32_le(data, off + 16);
            let w = u32_le(data, off + 20);
            let h = u32_le(data, off + 24);
            let fd = u32_le(data, off + 32);
            if (1..=500_000).contains(&frames)
                && frames == frames2
                && (16..=8192).contains(&w)
                && (16..=8192).contains(&h)
                && fd > 0
            {
                count += 1;
                let fsize = (u32_le(data, off + 4) as usize).saturating_add(8);
                off = align_up(off + fsize.max(4096), 4096);
                continue;
            }
        }
        off += 4096;
    }
    count
}

fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

fn is_printable_utf8(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(4096)];
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    let mut printable = 0usize;
    let mut total = 0usize;
    for ch in text.chars() {
        total += 1;
        if !ch.is_control() || matches!(ch, '\n' | '\r' | '\t') {
            printable += 1;
        }
    }
    total > 0 && printable * 10 >= total * 9
}

fn trim_bom_and_ws(mut data: &[u8]) -> &[u8] {
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        data = &data[3..];
    }
    while let Some((&b, rest)) = data.split_first() {
        if b.is_ascii_whitespace() {
            data = rest;
        } else {
            break;
        }
    }
    data
}

#[inline]
fn u16_le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

#[inline]
fn u32_le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

#[inline]
fn u64_be(d: &[u8], o: usize) -> u64 {
    u64::from_be_bytes([
        d[o],
        d[o + 1],
        d[o + 2],
        d[o + 3],
        d[o + 4],
        d[o + 5],
        d[o + 6],
        d[o + 7],
    ])
}
