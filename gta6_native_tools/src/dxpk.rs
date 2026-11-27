//! DXPK v1 — Packed DXIL shader archive format (spec locked in board #443).
//!
//! # On-disk layout (all little-endian)
//! ```text
//! Header (32 bytes at offset 0):
//!   0x00..0x04: magic        u32  = 0x4B505844 ("DXPK")
//!   0x04..0x08: version      u32  = 1
//!   0x08..0x0C: entry_count  u32
//!   0x0C..0x10: flags        u32  = 0 (uncompressed raw DXIL blobs)
//!   0x10..0x18: index_offset u64  = 32
//!   0x18..0x20: data_offset  u64  = 32 + entry_count * 24
//!
//! Index table (entry_count * 24 bytes at index_offset, strictly sorted ascending by hash):
//!   0x00..0x08: hash         u64  FNV-1a 64-bit of the input Xbox DXBC container bytes
//!   0x08..0x10: offset       u64  absolute file offset to the PC SM 6.6 DXIL blob (4-byte aligned, >= data_offset)
//!   0x10..0x14: size         u32  byte length of the PC DXIL blob
//!   0x14:       stage        u8   0=Unknown, 1=VS, 2=PS, 3=CS, 4=GS, 5=HS, 6=LS, 7=ES, 8=MS
//!   0x15:       source_kind  u8   0=SGD5, 1=ACCC/FSPX, 2=DXBC
//!   0x16..0x18: reserved     u16  = 0
//!
//! Data region (data_offset..EOF):
//!   Concatenated raw PC SM 6.6 DXIL blobs (4-byte aligned; identical DXIL blobs may share (offset, size)).
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DXPK_MAGIC: u32 = 0x4B50_5844; // "DXPK"
pub const DXPK_VERSION: u32 = 1;
pub const HEADER_SIZE: u64 = 32;
pub const INDEX_ENTRY_SIZE: u64 = 24;

/// FNV-1a 64-bit hash of `data`.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DxpkStage {
    Unknown = 0,
    Vs = 1,
    Ps = 2,
    Cs = 3,
    Gs = 4,
    Hs = 5,
    Ls = 6,
    Es = 7,
    Ms = 8,
}

impl DxpkStage {
    pub fn from_name(s: &str) -> Self {
        match s {
            "VS" => Self::Vs,
            "PS" => Self::Ps,
            "CS" => Self::Cs,
            "GS" => Self::Gs,
            "HS" => Self::Hs,
            "LS" => Self::Ls,
            "ES" => Self::Es,
            "MS" => Self::Ms,
            _ => Self::Unknown,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Vs,
            2 => Self::Ps,
            3 => Self::Cs,
            4 => Self::Gs,
            5 => Self::Hs,
            6 => Self::Ls,
            7 => Self::Es,
            8 => Self::Ms,
            _ => Self::Unknown,
        }
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Vs => "VS",
            Self::Ps => "PS",
            Self::Cs => "CS",
            Self::Gs => "GS",
            Self::Hs => "HS",
            Self::Ls => "LS",
            Self::Es => "ES",
            Self::Ms => "MS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DxpkSourceKind {
    Sgd5 = 0,
    AcccFspx = 1,
    Dxbc = 2,
}

impl DxpkSourceKind {
    pub fn from_label(s: &str) -> Self {
        if s.starts_with("SGD5") {
            Self::Sgd5
        } else if s.contains("ACCC") || s.contains("FSPX") {
            Self::AcccFspx
        } else {
            Self::Dxbc
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Sgd5,
            1 => Self::AcccFspx,
            _ => Self::Dxbc,
        }
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::Sgd5 => "SGD5",
            Self::AcccFspx => "ACCC/FSPX",
            Self::Dxbc => "DXBC",
        }
    }
}

/// One 24-byte entry in the DXPK index table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DxpkIndexEntry {
    pub hash: u64,
    pub offset: u64,
    pub size: u32,
    pub stage: DxpkStage,
    pub source_kind: DxpkSourceKind,
}

impl DxpkIndexEntry {
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.hash.to_le_bytes())?;
        w.write_all(&self.offset.to_le_bytes())?;
        w.write_all(&self.size.to_le_bytes())?;
        w.write_all(&[self.stage as u8, self.source_kind as u8])?;
        w.write_all(&0u16.to_le_bytes())?; // reserved
        Ok(())
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 24];
        r.read_exact(&mut buf)?;
        Ok(Self {
            hash: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            offset: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            size: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            stage: DxpkStage::from_u8(buf[20]),
            source_kind: DxpkSourceKind::from_u8(buf[21]),
        })
    }
}

struct PendingShader {
    hash: u64,
    stage: DxpkStage,
    source_kind: DxpkSourceKind,
    blob_idx: usize,
}

/// In-memory builder for a DXPK v1 archive.
///
/// Deduplicates input shaders by FNV-1a-64 hash of the source Xbox DXBC bytes,
/// and also shares identical output DXIL blobs in the data section.
#[derive(Default)]
pub struct DxpkPack {
    seen_hashes: HashSet<u64>,
    pending: Vec<PendingShader>,
    unique_blobs: Vec<Vec<u8>>,
    blob_dedup: HashMap<[u8; 32], usize>,
}

impl DxpkPack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn unique_blob_count(&self) -> usize {
        self.unique_blobs.len()
    }

    /// Insert a shader using a precomputed FNV-1a-64 hash of the source Xbox DXBC bytes.
    /// Returns `true` if added, `false` if duplicate hash already present.
    pub fn insert_prehashed(
        &mut self,
        hash: u64,
        dxil: Vec<u8>,
        stage: DxpkStage,
        source_kind: DxpkSourceKind,
    ) -> bool {
        if !self.seen_hashes.insert(hash) {
            return false;
        }
        let dxil_digest = *blake3::hash(&dxil).as_bytes();
        let blob_idx = if let Some(&idx) = self.blob_dedup.get(&dxil_digest) {
            if self.unique_blobs[idx] == dxil {
                idx
            } else {
                let idx = self.unique_blobs.len();
                self.unique_blobs.push(dxil);
                idx
            }
        } else {
            let idx = self.unique_blobs.len();
            self.unique_blobs.push(dxil);
            self.blob_dedup.insert(dxil_digest, idx);
            idx
        };

        self.pending.push(PendingShader {
            hash,
            stage,
            source_kind,
            blob_idx,
        });
        true
    }

    /// Insert a shader by its raw input Xbox DXBC bytes and translated PC DXIL blob.
    /// Returns `(added, hash)` where `added == false` if an entry with the same DXBC hash already exists.
    pub fn insert_with_hash(
        &mut self,
        dxbc_bytes: &[u8],
        dxil: Vec<u8>,
        stage: DxpkStage,
        source_kind: DxpkSourceKind,
    ) -> (bool, u64) {
        let hash = fnv1a64(dxbc_bytes);
        let added = self.insert_prehashed(hash, dxil, stage, source_kind);
        (added, hash)
    }

    /// Convenience wrapper returning just `added: bool`.
    pub fn insert(
        &mut self,
        dxbc_bytes: &[u8],
        dxil: Vec<u8>,
        stage: DxpkStage,
        source_kind: DxpkSourceKind,
    ) -> bool {
        self.insert_with_hash(dxbc_bytes, dxil, stage, source_kind).0
    }

    /// Write the DXPK v1 pack to `path`, returning `(total_file_bytes, unique_dxil_blob_bytes)`.
    pub fn write_to_file(&mut self, path: &Path) -> Result<(u64, u64)> {
        self.pending.sort_by_key(|p| p.hash);

        let count = u32::try_from(self.pending.len())
            .context("DXPK entry count exceeds u32::MAX")?;
        let index_offset: u64 = HEADER_SIZE;
        let data_offset: u64 = HEADER_SIZE + u64::from(count) * INDEX_ENTRY_SIZE;

        // Compute 4-byte-aligned absolute offsets for each unique DXIL blob.
        let mut blob_layouts: Vec<(u64, u32)> = Vec::with_capacity(self.unique_blobs.len());
        let mut cursor: u64 = data_offset;
        let mut unique_dxil_bytes: u64 = 0;
        for blob in &self.unique_blobs {
            let sz = u32::try_from(blob.len()).context("DXIL blob exceeds u32::MAX")?;
            blob_layouts.push((cursor, sz));
            let aligned_len = (blob.len() as u64).next_multiple_of(4);
            cursor += aligned_len;
            unique_dxil_bytes += blob.len() as u64;
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let mut w = BufWriter::with_capacity(1024 * 1024, file);

        // 32-byte Header
        w.write_all(&DXPK_MAGIC.to_le_bytes())?;
        w.write_all(&DXPK_VERSION.to_le_bytes())?;
        w.write_all(&count.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?; // flags = 0
        w.write_all(&index_offset.to_le_bytes())?;
        w.write_all(&data_offset.to_le_bytes())?;

        // Index table (24 bytes * count, sorted ascending by hash)
        for p in &self.pending {
            let (abs_off, sz) = blob_layouts[p.blob_idx];
            let entry = DxpkIndexEntry {
                hash: p.hash,
                offset: abs_off,
                size: sz,
                stage: p.stage,
                source_kind: p.source_kind,
            };
            entry.write_to(&mut w)?;
        }

        // Data region (4-byte aligned DXIL blobs)
        let zeros = [0u8; 4];
        for blob in &self.unique_blobs {
            w.write_all(blob)?;
            let rem = blob.len() % 4;
            if rem != 0 {
                w.write_all(&zeros[..4 - rem])?;
            }
        }
        w.flush()?;

        Ok((cursor, unique_dxil_bytes))
    }
}

/// Reader for an on-disk DXPK v1 file (header + sorted index table + O(log N) binary-search lookup).
pub struct DxpkReader {
    pub version: u32,
    pub flags: u32,
    pub entry_count: u32,
    pub index_offset: u64,
    pub data_offset: u64,
    pub file_size: u64,
    pub entries: Vec<DxpkIndexEntry>,
    path: PathBuf,
}

impl DxpkReader {
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let file_size = f.metadata()?.len();
        let mut hdr = [0u8; 32];
        f.read_exact(&mut hdr)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != DXPK_MAGIC {
            bail!("DXPK magic mismatch: got 0x{magic:08X}, expected 0x{DXPK_MAGIC:08X}");
        }
        let version = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if version != DXPK_VERSION {
            bail!("DXPK version {version} unsupported (expected {DXPK_VERSION})");
        }
        let entry_count = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let flags = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let index_offset = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let data_offset = u64::from_le_bytes(hdr[24..32].try_into().unwrap());

        let expected_data_off = index_offset + u64::from(entry_count) * INDEX_ENTRY_SIZE;
        if data_offset < expected_data_off || data_offset > file_size {
            bail!(
                "Invalid DXPK data_offset {data_offset} (expected >= {expected_data_off}, file_size={file_size})"
            );
        }

        f.seek(SeekFrom::Start(index_offset))?;
        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let e = DxpkIndexEntry::read_from(&mut f)?;
            if e.offset < data_offset || e.offset + u64::from(e.size) > file_size {
                bail!(
                    "DXPK entry hash 0x{:016x} has out-of-bounds span [{}..{}) (data_offset={}, file_size={})",
                    e.hash,
                    e.offset,
                    e.offset + u64::from(e.size),
                    data_offset,
                    file_size
                );
            }
            entries.push(e);
        }

        Ok(Self {
            version,
            flags,
            entry_count,
            index_offset,
            data_offset,
            file_size,
            entries,
            path: path.to_path_buf(),
        })
    }

    /// Returns true if the index is strictly sorted ascending by hash (no duplicates).
    pub fn is_sorted_unique(&self) -> bool {
        self.entries.windows(2).all(|w| w[0].hash < w[1].hash)
    }

    /// Binary-search index entry by FNV-1a-64 hash of Xbox DXBC bytes.
    pub fn find_entry(&self, hash: u64) -> Option<&DxpkIndexEntry> {
        self.entries
            .binary_search_by_key(&hash, |e| e.hash)
            .ok()
            .map(|idx| &self.entries[idx])
    }

    /// Retrieve PC SM 6.6 DXIL blob for a given Xbox DXBC FNV-1a-64 hash.
    pub fn get_by_hash(&self, hash: u64) -> Result<Option<Vec<u8>>> {
        let Some(e) = self.find_entry(hash) else {
            return Ok(None);
        };
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(e.offset))?;
        let mut blob = vec![0u8; e.size as usize];
        f.read_exact(&mut blob)?;
        Ok(Some(blob))
    }

    /// Convenience: hash raw Xbox DXBC bytes and look up the translated PC DXIL blob.
    pub fn lookup_dxbc(&self, dxbc_bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_by_hash(fnv1a64(dxbc_bytes))
    }
}

/// Per-shader entry in `shaders_manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub index: usize,
    pub name: String,
    pub source_file: String,
    pub source_kind: String,
    pub stage: String,
    pub dxbc_hash_hex: String,
    pub input_dxbc_bytes: usize,
    pub dxil_bytes: usize,
    pub deduplicated: bool,
    pub translated_ok: bool,
    pub error: Option<String>,
}

pub const PROJECT_NAME: &str = "LUCIAS PROJECT";

fn default_project_name() -> String {
    PROJECT_NAME.to_string()
}

/// Summary written to `shaders_manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackShadersManifest {
    #[serde(default = "default_project_name")]
    pub project: String,
    pub dxpk_version: u32,
    pub dxilpack_path: String,
    pub total_input_shaders: usize,
    pub translated_ok: usize,
    pub unique_packed: usize,
    pub unique_dxil_blobs: usize,
    pub deduplicated: usize,
    pub failed: usize,
    pub total_input_dxbc_bytes: u64,
    pub total_dxil_bytes: u64,
    pub unique_dxil_bytes: u64,
    pub file_bytes: u64,
    pub stage_counts: BTreeMap<String, usize>,
    pub source_kind_counts: BTreeMap<String, usize>,
    pub failure_reasons: BTreeMap<String, usize>,
    pub entries: Vec<ManifestEntry>,
}
