//! `DXPK` v1 shader pack reader for `LUCIAS PROJECT`
//! (`pc_cache\shaders_pc.dxilpack` -> `V:\LUCIAS_PROJECT_Cache\shaders_pc.dxilpack` -> legacy `V:\GTA6_PC_Cache\shaders_pc.dxilpack`).
//!
//! Layout (all little-endian):
//! - Header (32 bytes at offset 0):
//!   - `0x00..0x04`: `magic` = `b"DXPK"`
//!   - `0x04..0x08`: `version: u32` = `1`
//!   - `0x08..0x0C`: `entry_count: u32`
//!   - `0x0C..0x10`: `flags: u32` = `0`
//!   - `0x10..0x18`: `index_offset: u64` = `32`
//!   - `0x18..0x20`: `data_offset: u64` = `32 + entry_count * 24`
//! - Index table (`entry_count` x 24 bytes at `index_offset`, sorted ascending by `hash`):
//!   - `0x00..0x08`: `hash: u64` (FNV-1a 64-bit of input Xbox DXBC bytes)
//!   - `0x08..0x10`: `offset: u64` (absolute file offset, >= `data_offset`)
//!   - `0x10..0x14`: `size: u32`
//!   - `0x14`: `stage: u8`
//!   - `0x15`: `source_kind: u8`
//!   - `0x16..0x18`: `reserved: u16`

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DXPK_MAGIC: [u8; 4] = *b"DXPK";
pub const DXPK_VERSION: u32 = 1;
pub const DXPK_HEADER_SIZE: usize = 32;
pub const DXPK_ENTRY_SIZE: usize = 24;
pub const DEFAULT_SHADER_PACK_PATH: &str = r"V:\LUCIAS_PROJECT_Cache\shaders_pc.dxilpack";
pub const LEGACY_SHADER_PACK_PATH: &str = r"V:\GTA6_PC_Cache\shaders_pc.dxilpack";
pub const LOCAL_CACHE_SHADER_PACK_PATH: &str = r"pc_cache\shaders_pc.dxilpack";

/// Resolves the active DXPK shader pack path in priority order:
/// `LUCIAS_SHADER_PACK` / `GTA6_SHADER_PACK` -> `<exe_dir>\pc_cache\shaders_pc.dxilpack` ->
/// `pc_cache\shaders_pc.dxilpack` -> `V:\LUCIAS_PROJECT_Cache\shaders_pc.dxilpack` ->
/// `V:\GTA6_PC_Cache\shaders_pc.dxilpack`.
pub fn resolve_shader_pack_path() -> PathBuf {
    for key in ["LUCIAS_SHADER_PACK", "GTA6_SHADER_PACK"] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(LOCAL_CACHE_SHADER_PACK_PATH);
            if p.exists() {
                return p;
            }
        }
    }
    let rel = PathBuf::from(LOCAL_CACHE_SHADER_PACK_PATH);
    if rel.exists() {
        return rel;
    }
    let primary = PathBuf::from(DEFAULT_SHADER_PACK_PATH);
    if primary.exists() {
        return primary;
    }
    let legacy = PathBuf::from(LEGACY_SHADER_PACK_PATH);
    if legacy.exists() {
        return legacy;
    }
    primary
}

pub const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
pub const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Computes FNV-1a 64-bit hash over input Xbox DXBC container bytes.
#[inline]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A_OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DxpkHeader {
    pub version: u32,
    pub entry_count: u32,
    pub flags: u32,
    pub index_offset: u64,
    pub data_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DxpkEntry {
    pub hash: u64,
    pub offset: u64,
    pub size: u32,
    pub stage: u8,
    pub source_kind: u8,
}

/// Indexed reader for `shaders_pc.dxilpack` supporting both O(1) hash-table
/// lookup and O(log N) binary-search lookup over the sorted index table.
pub struct DxpkReader {
    path: PathBuf,
    header: DxpkHeader,
    file_len: u64,
    entries: Vec<DxpkEntry>,
    o1_index: HashMap<u64, usize>,
}

impl DxpkReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_buf = path.as_ref().to_path_buf();
        let mut file = File::open(&path_buf)
            .map_err(|e| format!("failed to open {}: {e}", path_buf.display()))?;
        let file_len = file
            .metadata()
            .map_err(|e| format!("metadata error: {e}"))?
            .len();
        if file_len < DXPK_HEADER_SIZE as u64 {
            return Err("DXPK file smaller than 32-byte header".into());
        }

        let mut hdr = [0u8; DXPK_HEADER_SIZE];
        file.read_exact(&mut hdr)
            .map_err(|e| format!("failed reading DXPK header: {e}"))?;
        if hdr[0..4] != DXPK_MAGIC {
            return Err("invalid DXPK magic".into());
        }
        let version = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if version != DXPK_VERSION {
            return Err(format!("unsupported DXPK version {version}"));
        }
        let entry_count = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let flags = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let index_offset = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let data_offset = u64::from_le_bytes(hdr[24..32].try_into().unwrap());

        let index_bytes_len = u64::from(entry_count)
            .checked_mul(DXPK_ENTRY_SIZE as u64)
            .ok_or_else(|| "DXPK entry count overflow".to_string())?;
        let index_end = index_offset
            .checked_add(index_bytes_len)
            .ok_or_else(|| "DXPK index offset overflow".to_string())?;
        if index_end > file_len || data_offset > file_len || index_end > data_offset {
            return Err("DXPK index/data bounds exceed file length".into());
        }

        file.seek(SeekFrom::Start(index_offset))
            .map_err(|e| format!("seek to index failed: {e}"))?;
        let mut raw_index = vec![0u8; index_bytes_len as usize];
        file.read_exact(&mut raw_index)
            .map_err(|e| format!("failed reading DXPK index: {e}"))?;

        let mut entries = Vec::with_capacity(entry_count as usize);
        let mut o1_index = HashMap::with_capacity(entry_count as usize);
        let (chunks, _) = raw_index.as_chunks::<DXPK_ENTRY_SIZE>();
        for (idx, chunk) in chunks.iter().enumerate() {
            let hash = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let offset = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            let size = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
            let stage = chunk[20];
            let source_kind = chunk[21];
            let blob_end = offset
                .checked_add(u64::from(size))
                .ok_or_else(|| "DXPK blob offset overflow".to_string())?;
            if offset < data_offset || blob_end > file_len {
                return Err(format!(
                    "DXPK entry {hash:#018x} out of bounds ({offset}..{blob_end} > {file_len})"
                ));
            }
            entries.push(DxpkEntry {
                hash,
                offset,
                size,
                stage,
                source_kind,
            });
            o1_index.insert(hash, idx);
        }

        // Verify sorted ascending for binary search.
        for w in entries.windows(2) {
            if w[0].hash > w[1].hash {
                return Err("DXPK index is not sorted ascending by hash".into());
            }
        }

        Ok(Self {
            path: path_buf,
            header: DxpkHeader {
                version,
                entry_count,
                flags,
                index_offset,
                data_offset,
            },
            file_len,
            entries,
            o1_index,
        })
    }

    pub fn open_default() -> Result<Self, String> {
        Self::open(resolve_shader_pack_path())
    }

    pub fn header(&self) -> DxpkHeader {
        self.header
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[DxpkEntry] {
        &self.entries
    }

    /// O(1) hash-table metadata lookup by FNV-1a 64-bit hash.
    pub fn find_entry(&self, hash: u64) -> Option<DxpkEntry> {
        let &idx = self.o1_index.get(&hash)?;
        Some(self.entries[idx])
    }

    /// O(log N) binary-search metadata lookup over the sorted index.
    pub fn find_entry_binary_search(&self, hash: u64) -> Option<DxpkEntry> {
        let idx = self.entries.binary_search_by_key(&hash, |e| e.hash).ok()?;
        Some(self.entries[idx])
    }

    /// Reads the PC SM 6.6 DXIL blob for `hash`.
    pub fn read_blob_by_hash(&self, hash: u64) -> Result<Option<(DxpkEntry, Vec<u8>)>, String> {
        let Some(entry) = self.find_entry(hash) else {
            return Ok(None);
        };
        let mut file = File::open(&self.path)
            .map_err(|e| format!("failed to reopen {}: {e}", self.path.display()))?;
        file.seek(SeekFrom::Start(entry.offset))
            .map_err(|e| format!("seek failed: {e}"))?;
        let mut buf = vec![0u8; entry.size as usize];
        file.read_exact(&mut buf)
            .map_err(|e| format!("read blob failed: {e}"))?;
        Ok(Some((entry, buf)))
    }

    /// Hashes input Xbox DXBC bytecode and looks up the precompiled PC DXIL blob.
    pub fn lookup_xbox_bytecode(
        &self,
        xbox_dxbc: &[u8],
    ) -> Result<Option<(DxpkEntry, Vec<u8>)>, String> {
        self.read_blob_by_hash(fnv1a_64(xbox_dxbc))
    }
}

static GLOBAL_PACK: OnceLock<Option<DxpkReader>> = OnceLock::new();

pub fn global_shader_pack() -> Option<&'static DxpkReader> {
    GLOBAL_PACK
        .get_or_init(|| DxpkReader::open_default().ok())
        .as_ref()
}

pub fn lookup_pc_dxil(xbox_dxbc: &[u8]) -> Option<Vec<u8>> {
    let hash = fnv1a_64(xbox_dxbc);
    if let Some(pack) = global_shader_pack() {
        if let Ok(Some((_, blob))) = pack.read_blob_by_hash(hash) {
            shim_common::telemetry::record_dxpk_hit();
            return Some(blob);
        }
    }
    shim_common::telemetry::record_dxpk_miss(hash, "DXBC");
    None
}

/// Checks whether `xbox_dxbc` exists in the DXPK cache and updates telemetry counters.
pub fn probe_dxpk_for_telemetry(xbox_dxbc: &[u8], stage: &str) -> bool {
    let hash = fnv1a_64(xbox_dxbc);
    if let Some(pack) = global_shader_pack() {
        if pack.find_entry(hash).is_some() {
            shim_common::telemetry::record_dxpk_hit();
            return true;
        }
    }
    shim_common::telemetry::record_dxpk_miss(hash, stage);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_dxpk(dir: &Path) -> PathBuf {
        let p = dir.join("test.dxilpack");
        let dxbc_a = b"DXBC_XBOX_VS_A";
        let dxbc_b = b"DXBC_XBOX_PS_B";
        let ha = fnv1a_64(dxbc_a);
        let hb = fnv1a_64(dxbc_b);

        let mut items = vec![
            (ha, 1u8, 0u8, b"DXIL_VS_PAYLOAD".to_vec()),
            (hb, 2u8, 1u8, b"DXIL_PS_PAYLOAD".to_vec()),
        ];
        items.sort_by_key(|x| x.0);

        let count = items.len() as u32;
        let data_offset = 32u64 + u64::from(count) * 24u64;
        let mut data = Vec::new();
        let mut index = Vec::new();
        for (h, stage, src, blob) in items {
            let off = data_offset + data.len() as u64;
            index.extend_from_slice(&h.to_le_bytes());
            index.extend_from_slice(&off.to_le_bytes());
            index.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            index.push(stage);
            index.push(src);
            index.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(&blob);
            while data.len() % 4 != 0 {
                data.push(0);
            }
        }

        let mut out = Vec::new();
        out.extend_from_slice(&DXPK_MAGIC);
        out.extend_from_slice(&DXPK_VERSION.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&32u64.to_le_bytes());
        out.extend_from_slice(&data_offset.to_le_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        std::fs::write(&p, out).unwrap();
        p
    }

    #[test]
    fn reads_o1_and_binary_search_entries() {
        let dir = std::env::temp_dir().join(format!("dxpk_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = build_test_dxpk(&dir);
        let reader = DxpkReader::open(&path).unwrap();
        assert_eq!(reader.entry_count(), 2);

        let ha = fnv1a_64(b"DXBC_XBOX_VS_A");
        let e1 = reader.find_entry(ha).unwrap();
        let e2 = reader.find_entry_binary_search(ha).unwrap();
        assert_eq!(e1, e2);

        let (entry, blob) = reader.lookup_xbox_bytecode(b"DXBC_XBOX_VS_A").unwrap().unwrap();
        assert_eq!(entry.stage, 1);
        assert_eq!(blob, b"DXIL_VS_PAYLOAD");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
