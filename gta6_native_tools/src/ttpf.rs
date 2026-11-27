//! TTPF (`RDS5` / `ETPF`) streaming texture archive parser, Xbox Series X BCPack +
//! RDNA2 tile deswizzler, and standard PC DDS (DX10) exporter.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use victory_formats::bcpack::{self, Tables as BcPackTables};
use zlib_rs::{Inflate, InflateFlush, Status};

const DDS_MAGIC: u32 = 0x2053_4444; // "DDS "
const DX10_FOURCC: u32 = 0x3031_5844; // "DX10"

const DDSD_CAPS: u32 = 0x1;
const DDSD_HEIGHT: u32 = 0x2;
const DDSD_WIDTH: u32 = 0x4;
const DDSD_PITCH: u32 = 0x8;
const DDSD_PIXELFORMAT: u32 = 0x1000;
const DDSD_LINEARSIZE: u32 = 0x80000;
const DDPF_FOURCC: u32 = 0x4;
const DDSCAPS_TEXTURE: u32 = 0x1000;
const D3D10_RESOURCE_DIMENSION_TEXTURE2D: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtpfCodec {
    Raw = 0,
    BcPackBc1 = 1,
    BcPackBc2 = 2,
    BcPackBc3 = 3,
    BcPackBc4 = 4,
    BcPackBc5 = 5,
    BcPackBc6H = 6,
    BcPackBc7 = 7,
    Zlib = 8,
}

impl TtpfCodec {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Raw,
            1 => Self::BcPackBc1,
            2 => Self::BcPackBc2,
            3 => Self::BcPackBc3,
            4 => Self::BcPackBc4,
            5 => Self::BcPackBc5,
            6 => Self::BcPackBc6H,
            7 => Self::BcPackBc7,
            8 => Self::Zlib,
            other => bail!("Unknown RDS5 chunk codec {other}"),
        })
    }

    pub fn bc_id(self) -> Option<u8> {
        match self {
            Self::BcPackBc1 => Some(1),
            Self::BcPackBc3 => Some(3),
            Self::BcPackBc4 => Some(4),
            Self::BcPackBc5 => Some(5),
            Self::BcPackBc6H => Some(6),
            Self::BcPackBc7 => Some(7),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::BcPackBc1 => "BCPack_BC1",
            Self::BcPackBc2 => "BCPack_BC2",
            Self::BcPackBc3 => "BCPack_BC3",
            Self::BcPackBc4 => "BCPack_BC4",
            Self::BcPackBc5 => "BCPack_BC5",
            Self::BcPackBc6H => "BCPack_BC6H",
            Self::BcPackBc7 => "BCPack_BC7",
            Self::Zlib => "ZLIB",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfHeader {
    pub chunk_count: usize,
    pub total_uncompressed_size: u64,
    pub header_pages: u32,
    pub etpf_offset: u64,
    pub etpf_version: u32,
    pub texture_count: usize,
    pub etpf_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfChunk {
    pub index: usize,
    pub file_offset: u64,
    pub file_end: u64,
    pub virtual_offset: u64,
    pub uncompressed_size: u64,
    pub codec: TtpfCodec,
}

impl TtpfChunk {
    pub fn compressed_size(&self) -> u64 {
        self.file_end.saturating_sub(self.file_offset)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfEntry {
    pub index: usize,
    pub width: u32,
    pub height: u32,
    pub format_byte: u8,
    pub dxgi_format: u8,
    pub dxgi_name: String,
    pub has_mips: bool,
    pub page_4k: u32,
    pub virtual_offset: u64,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub codec: TtpfCodec,
    pub flags: u32,
    pub hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfInspectReport {
    pub path: String,
    pub file_size: u64,
    pub header: TtpfHeader,
    pub codec_chunk_counts: BTreeMap<String, usize>,
    pub codec_compressed_bytes: BTreeMap<String, u64>,
    pub codec_uncompressed_bytes: BTreeMap<String, u64>,
    pub dxgi_format_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfExportItem {
    pub index: usize,
    pub file_name: String,
    pub width: u32,
    pub height: u32,
    pub dxgi_format: u8,
    pub dxgi_name: String,
    pub codec: String,
    pub tile_mode: String,
    pub input_compressed_bytes: u64,
    pub input_virtual_bytes: u64,
    pub output_dds_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfExportSummary {
    pub source_archive: String,
    pub total_entries_in_archive: usize,
    pub exported_count: usize,
    pub failed_count: usize,
    pub total_input_compressed_bytes: u64,
    pub total_input_virtual_bytes: u64,
    pub total_output_dds_bytes: u64,
    pub items: Vec<TtpfExportItem>,
}

#[derive(Debug, Clone, Copy)]
pub struct DxgiLayoutInfo {
    pub name: &'static str,
    pub is_block_compressed: bool,
    pub bytes_per_element: usize,
}

pub fn dxgi_info(dxgi: u8) -> Option<DxgiLayoutInfo> {
    Some(match dxgi {
        10 => DxgiLayoutInfo { name: "R16G16B16A16_FLOAT", is_block_compressed: false, bytes_per_element: 8 },
        11 => DxgiLayoutInfo { name: "R16G16B16A16_UNORM", is_block_compressed: false, bytes_per_element: 8 },
        24 => DxgiLayoutInfo { name: "R10G10B10A2_UNORM", is_block_compressed: false, bytes_per_element: 4 },
        27 => DxgiLayoutInfo { name: "R8G8B8A8_TYPELESS", is_block_compressed: false, bytes_per_element: 4 },
        28 => DxgiLayoutInfo { name: "R8G8B8A8_UNORM", is_block_compressed: false, bytes_per_element: 4 },
        29 => DxgiLayoutInfo { name: "R8G8B8A8_UNORM_SRGB", is_block_compressed: false, bytes_per_element: 4 },
        34 => DxgiLayoutInfo { name: "R16G16_FLOAT", is_block_compressed: false, bytes_per_element: 4 },
        41 => DxgiLayoutInfo { name: "R32_FLOAT", is_block_compressed: false, bytes_per_element: 4 },
        49 => DxgiLayoutInfo { name: "R8G8_UNORM", is_block_compressed: false, bytes_per_element: 2 },
        54 => DxgiLayoutInfo { name: "R16_FLOAT", is_block_compressed: false, bytes_per_element: 2 },
        56 => DxgiLayoutInfo { name: "R16_UNORM", is_block_compressed: false, bytes_per_element: 2 },
        61 => DxgiLayoutInfo { name: "R8_UNORM", is_block_compressed: false, bytes_per_element: 1 },
        65 => DxgiLayoutInfo { name: "A8_UNORM", is_block_compressed: false, bytes_per_element: 1 },
        70 => DxgiLayoutInfo { name: "BC1_TYPELESS", is_block_compressed: true, bytes_per_element: 8 },
        71 => DxgiLayoutInfo { name: "BC1_UNORM", is_block_compressed: true, bytes_per_element: 8 },
        72 => DxgiLayoutInfo { name: "BC1_UNORM_SRGB", is_block_compressed: true, bytes_per_element: 8 },
        73 => DxgiLayoutInfo { name: "BC2_TYPELESS", is_block_compressed: true, bytes_per_element: 16 },
        74 => DxgiLayoutInfo { name: "BC2_UNORM", is_block_compressed: true, bytes_per_element: 16 },
        75 => DxgiLayoutInfo { name: "BC2_UNORM_SRGB", is_block_compressed: true, bytes_per_element: 16 },
        76 => DxgiLayoutInfo { name: "BC3_TYPELESS", is_block_compressed: true, bytes_per_element: 16 },
        77 => DxgiLayoutInfo { name: "BC3_UNORM", is_block_compressed: true, bytes_per_element: 16 },
        78 => DxgiLayoutInfo { name: "BC3_UNORM_SRGB", is_block_compressed: true, bytes_per_element: 16 },
        79 => DxgiLayoutInfo { name: "BC4_TYPELESS", is_block_compressed: true, bytes_per_element: 8 },
        80 => DxgiLayoutInfo { name: "BC4_UNORM", is_block_compressed: true, bytes_per_element: 8 },
        81 => DxgiLayoutInfo { name: "BC4_SNORM", is_block_compressed: true, bytes_per_element: 8 },
        82 => DxgiLayoutInfo { name: "BC5_TYPELESS", is_block_compressed: true, bytes_per_element: 16 },
        83 => DxgiLayoutInfo { name: "BC5_UNORM", is_block_compressed: true, bytes_per_element: 16 },
        84 => DxgiLayoutInfo { name: "BC5_SNORM", is_block_compressed: true, bytes_per_element: 16 },
        87 => DxgiLayoutInfo { name: "B8G8R8A8_UNORM", is_block_compressed: false, bytes_per_element: 4 },
        91 => DxgiLayoutInfo { name: "B8G8R8A8_UNORM_SRGB", is_block_compressed: false, bytes_per_element: 4 },
        94 => DxgiLayoutInfo { name: "BC6H_TYPELESS", is_block_compressed: true, bytes_per_element: 16 },
        95 => DxgiLayoutInfo { name: "BC6H_UF16", is_block_compressed: true, bytes_per_element: 16 },
        96 => DxgiLayoutInfo { name: "BC6H_SF16", is_block_compressed: true, bytes_per_element: 16 },
        97 => DxgiLayoutInfo { name: "BC7_TYPELESS", is_block_compressed: true, bytes_per_element: 16 },
        98 => DxgiLayoutInfo { name: "BC7_UNORM", is_block_compressed: true, bytes_per_element: 16 },
        99 => DxgiLayoutInfo { name: "BC7_UNORM_SRGB", is_block_compressed: true, bytes_per_element: 16 },
        _ => return None,
    })
}

pub struct TtpfArchive {
    file: File,
    pub file_size: u64,
    pub header: TtpfHeader,
    pub chunks: Vec<TtpfChunk>,
    pub entries: Vec<TtpfEntry>,
    tables: BcPackTables,
}

impl TtpfArchive {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let file_size = file.metadata()?.len();
        let mut hdr = [0u8; 24];
        file.read_exact(&mut hdr)?;
        if &hdr[..4] != b"RDS5" {
            bail!("Invalid TTPF magic in {} (expected RDS5)", path.display());
        }
        let n_chunks = u32_le(&hdr, 4) as usize;
        if n_chunks > 10_000_000 {
            bail!("Implausible TTPF chunk count {n_chunks}");
        }
        let tot_uncomp = u64_le(&hdr, 8) & 0xFF_FFFF_FFFF;
        let hdr_pages = u32_le(&hdr, 16);
        let etpf_offset = u64::from(hdr_pages) * 0x100;

        let mut chunk_bytes = vec![0u8; n_chunks * 8];
        if !chunk_bytes.is_empty() {
            file.read_exact(&mut chunk_bytes)?;
        }

        let mut chunks = Vec::with_capacity(n_chunks);
        let mut prev_c = etpf_offset;
        let mut vstart = 0u64;
        let mut cur_codec = TtpfCodec::Raw;

        for i in 0..n_chunks {
            let lo = u32_le(&chunk_bytes, i * 8);
            let hi = u32_le(&chunk_bytes, i * 8 + 4);
            let cend = u64::from(lo & 0x03FF_FFFF) * 0x100;
            let next_codec = TtpfCodec::from_u8(((lo >> 26) & 0xF) as u8)?;
            let r = u64::from((lo >> 30) & 0x3);
            let vend = u64::from(hi & 0x000F_FFFF) * 0x4000 + r * 0x1000;

            if cend > prev_c && vend > vstart {
                chunks.push(TtpfChunk {
                    index: chunks.len(),
                    file_offset: prev_c,
                    file_end: cend,
                    virtual_offset: vstart,
                    uncompressed_size: vend - vstart,
                    codec: cur_codec,
                });
                vstart = vend;
            }
            prev_c = cend;
            cur_codec = next_codec;
        }

        if etpf_offset + 16 > file_size {
            bail!("ETPF offset 0x{etpf_offset:X} exceeds file size");
        }
        file.seek(SeekFrom::Start(etpf_offset))?;
        let mut ehdr = [0u8; 16];
        file.read_exact(&mut ehdr)?;
        if &ehdr[..4] != b"ETPF" {
            bail!("Invalid ETPF magic at 0x{etpf_offset:X}");
        }
        let etpf_version = u32_le(&ehdr, 4);
        let tex_count = u32_le(&ehdr, 8) as usize;
        let etpf_flags = u32_le(&ehdr, 12);
        if tex_count > 2_000_000 {
            bail!("Implausible ETPF texture count {tex_count}");
        }

        let mut recs = vec![0u8; tex_count * 16];
        if !recs.is_empty() {
            file.read_exact(&mut recs)?;
        }
        let hash_len = tex_count * 8;
        let has_hashes = etpf_offset + 16 + recs.len() as u64 + hash_len as u64 <= file_size;
        let mut hashes = vec![0u8; if has_hashes { hash_len } else { 0 }];
        if !hashes.is_empty() {
            file.read_exact(&mut hashes)?;
        }

        let mut raw_records = Vec::with_capacity(tex_count);
        let mut distinct_offsets = Vec::with_capacity(tex_count);
        for i in 0..tex_count {
            let off = i * 16;
            let u0 = u32_le(&recs, off);
            let u1 = u32_le(&recs, off + 4);
            let u2 = u32_le(&recs, off + 8);
            let u3 = u32_le(&recs, off + 12);

            let width = (u0 & 0x3FFF) + 1;
            let height = ((u0 >> 14) & 0x3FFF) + 1;
            let format_byte = (u1 & 0xFF) as u8;
            let dxgi = ((u1 >> 3) & 0x7F) as u8;
            let has_mips = (u1 >> 24) > 0;
            let page_4k = u2 & 0x001F_FFFF;
            let virt_off = u64::from(page_4k) * 0x1000;
            let hash = if has_hashes {
                u64_le(&hashes, i * 8)
            } else {
                0
            };
            distinct_offsets.push(virt_off);
            raw_records.push((width, height, format_byte, dxgi, has_mips, page_4k, virt_off, u3, hash));
        }

        distinct_offsets.sort_unstable();
        distinct_offsets.dedup();
        let mut entries = Vec::with_capacity(tex_count);
        for (i, r) in raw_records.into_iter().enumerate() {
            let (width, height, format_byte, dxgi, has_mips, page_4k, virt_off, flags, hash) = r;
            let info = dxgi_info(dxgi);
            let is_bc = info.is_none_or(|x| x.is_block_compressed);
            let bpe = info.map_or(16, |x| x.bytes_per_element);
            let ew = if is_bc { width.div_ceil(4) } else { width }.max(1) as u64;
            let eh = if is_bc { height.div_ceil(4) } else { height }.max(1) as u64;
            let est = (ew * eh * bpe as u64).max(0x10000);

            let next_off = match distinct_offsets.binary_search(&virt_off) {
                Ok(pos) if pos + 1 < distinct_offsets.len() => distinct_offsets[pos + 1],
                _ => (virt_off + est).min(tot_uncomp),
            };
            let alloc_sz = next_off.saturating_sub(virt_off).max(0x1000);
            let (comp_sz, codec) = span_chunk_stats(&chunks, virt_off, alloc_sz);
            let dxgi_name = info
                .map(|x| x.name.to_string())
                .unwrap_or_else(|| format!("DXGI_{dxgi}"));

            entries.push(TtpfEntry {
                index: i,
                width,
                height,
                format_byte,
                dxgi_format: dxgi,
                dxgi_name,
                has_mips,
                page_4k,
                virtual_offset: virt_off,
                uncompressed_size: alloc_sz,
                compressed_size: comp_sz,
                codec,
                flags,
                hash_hex: format!("{hash:016x}"),
            });
        }

        let tables = BcPackTables::builtin().map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(Self {
            file,
            file_size,
            header: TtpfHeader {
                chunk_count: chunks.len(),
                total_uncompressed_size: tot_uncomp,
                header_pages: hdr_pages,
                etpf_offset,
                etpf_version,
                texture_count: tex_count,
                etpf_flags,
            },
            chunks,
            entries,
            tables,
        })
    }

    pub fn inspect_report(&self, path: &Path) -> TtpfInspectReport {
        let mut codec_chunk_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut codec_compressed_bytes: BTreeMap<String, u64> = BTreeMap::new();
        let mut codec_uncompressed_bytes: BTreeMap<String, u64> = BTreeMap::new();
        for c in &self.chunks {
            let key = c.codec.name().to_string();
            *codec_chunk_counts.entry(key.clone()).or_default() += 1;
            *codec_compressed_bytes.entry(key.clone()).or_default() += c.compressed_size();
            *codec_uncompressed_bytes.entry(key).or_default() += c.uncompressed_size;
        }
        let mut dxgi_format_counts: BTreeMap<String, usize> = BTreeMap::new();
        for e in &self.entries {
            *dxgi_format_counts.entry(e.dxgi_name.clone()).or_default() += 1;
        }
        TtpfInspectReport {
            path: path.display().to_string(),
            file_size: self.file_size,
            header: self.header.clone(),
            codec_chunk_counts,
            codec_compressed_bytes,
            codec_uncompressed_bytes,
            dxgi_format_counts,
        }
    }

    pub fn read_virtual(&mut self, virtual_offset: u64, length: usize) -> Result<Vec<u8>> {
        let mut cache = VecDeque::new();
        read_virtual_cached(
            &mut self.file,
            self.file_size,
            &self.chunks,
            &self.tables,
            &mut cache,
            virtual_offset,
            length,
        )
    }

    /// Extracts and deswizzles `entry` into a complete PC DDS (DX10) file buffer.
    pub fn export_entry_to_dds(&mut self, entry: &TtpfEntry) -> Result<(Vec<u8>, &'static str)> {
        let mut cache = VecDeque::new();
        export_entry_with_cache(
            &mut self.file,
            self.file_size,
            &self.chunks,
            &self.tables,
            &mut cache,
            entry,
        )
    }
}

fn read_and_decompress_chunk_cached(
    file: &mut File,
    file_size: u64,
    tables: &BcPackTables,
    cache: &mut VecDeque<(usize, Vec<u8>)>,
    chunk: &TtpfChunk,
) -> Result<Vec<u8>> {
    if let Some((_, cached)) = cache.iter().find(|(idx, _)| *idx == chunk.index) {
        return Ok(cached.clone());
    }
    if chunk.file_end > file_size {
        bail!("Chunk {} exceeds archive length", chunk.index);
    }
    let comp_sz = chunk.compressed_size() as usize;
    let mut compressed = vec![0u8; comp_sz];
    file.seek(SeekFrom::Start(chunk.file_offset))?;
    file.read_exact(&mut compressed)?;

    let decoded = if chunk.codec == TtpfCodec::Zlib || is_zlib_header(&compressed) {
        inflate_zlib(&compressed, chunk.uncompressed_size as usize)?
    } else if chunk.codec == TtpfCodec::Raw || chunk.compressed_size() == chunk.uncompressed_size {
        compressed
    } else if let Some(bc) = chunk.codec.bc_id() {
        let mut dst = vec![0u8; chunk.uncompressed_size as usize];
        bcpack::decode(bc, &compressed, &mut dst, tables)
            .map_err(|e| anyhow::anyhow!("chunk {} {}: {e}", chunk.index, chunk.codec.name()))?;
        dst
    } else {
        bail!(
            "Unsupported RDS5 chunk {} codec {}",
            chunk.index,
            chunk.codec.name()
        );
    };

    if cache.len() >= 4 {
        cache.pop_front();
    }
    cache.push_back((chunk.index, decoded.clone()));
    Ok(decoded)
}

fn read_virtual_cached(
    file: &mut File,
    file_size: u64,
    chunks: &[TtpfChunk],
    tables: &BcPackTables,
    cache: &mut VecDeque<(usize, Vec<u8>)>,
    virtual_offset: u64,
    length: usize,
) -> Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let end = virtual_offset + length as u64;
    let first_idx = chunks.partition_point(|c| c.virtual_offset + c.uncompressed_size <= virtual_offset);
    let mut out = vec![0u8; length];
    let mut covered = 0usize;

    for chunk in &chunks[first_idx..] {
        if chunk.virtual_offset >= end {
            break;
        }
        let data = read_and_decompress_chunk_cached(file, file_size, tables, cache, chunk)?;
        let s0 = chunk.virtual_offset.max(virtual_offset);
        let s1 = (chunk.virtual_offset + data.len() as u64).min(end);
        if s1 > s0 {
            let src_off = (s0 - chunk.virtual_offset) as usize;
            let dst_off = (s0 - virtual_offset) as usize;
            let count = (s1 - s0) as usize;
            out[dst_off..dst_off + count].copy_from_slice(&data[src_off..src_off + count]);
            covered += count;
        }
    }
    if covered == 0 {
        bail!("Virtual range [0x{virtual_offset:X}, 0x{end:X}) matched no readable RDS5 chunk");
    }
    Ok(out)
}

fn export_entry_with_cache(
    file: &mut File,
    file_size: u64,
    chunks: &[TtpfChunk],
    tables: &BcPackTables,
    cache: &mut VecDeque<(usize, Vec<u8>)>,
    entry: &TtpfEntry,
) -> Result<(Vec<u8>, &'static str)> {
    let info = dxgi_info(entry.dxgi_format)
        .with_context(|| format!("Unsupported DXGI format {}", entry.dxgi_format))?;
    let mip0_lin = compute_mip_size(entry.width, entry.height, info);
    let use_64k = (!entry.has_mips || !info.is_block_compressed) && mip0_lin > 65_536;
    let mip0_padded = if use_64k {
        compute_padded_64kb(entry.width, entry.height, info)
    } else {
        compute_padded_4kb(entry.width, entry.height, info)
    };

    let tail_bound = (mip0_padded as u64) * 2 + 65_536;
    let has_tail = entry.has_mips
        && entry.uncompressed_size > mip0_padded as u64
        && entry.uncompressed_size <= tail_bound;

    let read_size = (entry.uncompressed_size as usize).min(mip0_padded);
    let raw = if has_tail {
        let tail_off = entry.virtual_offset + (entry.uncompressed_size - mip0_padded as u64);
        let candidate = read_virtual_cached(
            file,
            file_size,
            chunks,
            tables,
            cache,
            tail_off,
            mip0_padded,
        )?;
        if is_uniform_prefix(&candidate, 256) {
            read_virtual_cached(
                file,
                file_size,
                chunks,
                tables,
                cache,
                entry.virtual_offset,
                read_size,
            )?
        } else {
            candidate
        }
    } else {
        read_virtual_cached(
            file,
            file_size,
            chunks,
            tables,
            cache,
            entry.virtual_offset,
            read_size,
        )?
    };

    let (linear, mode) = if use_64k {
        (
            deswizzle_64kb(&raw, entry.width, entry.height, info),
            "SW_64KB_D",
        )
    } else {
        (
            deswizzle_4kb_d(&raw, entry.width, entry.height, info),
            "SW_4KB_D",
        )
    };

    let mut dds = build_dds_dx10_header(entry.width, entry.height, entry.dxgi_format, info);
    dds.extend_from_slice(&linear);
    Ok((dds, mode))
}

/// Converts up to `limit` textures from a `.ttpf` archive into PC `.dds` files in `out_dir`.
pub fn convert_ttpf_samples(
    ttpf_path: &Path,
    out_dir: &Path,
    limit: usize,
) -> Result<TtpfExportSummary> {
    std::fs::create_dir_all(out_dir)?;
    let mut archive = TtpfArchive::open(ttpf_path)?;
    let entries = archive.entries.clone();
    let total_entries = entries.len();

    let mut items = Vec::new();
    let mut failed_count = 0usize;
    let mut total_in_comp = 0u64;
    let mut total_in_virt = 0u64;
    let mut total_out_dds = 0u64;

    for entry in entries.into_iter().take(limit) {
        match archive.export_entry_to_dds(&entry) {
            Ok((dds, tile_mode)) => {
                let fname = format!(
                    "tex_{:05}_{}x{}_{}_{}.dds",
                    entry.index, entry.width, entry.height, entry.dxgi_name, entry.hash_hex
                );
                let out_path = out_dir.join(&fname);
                let mut f = File::create(&out_path)?;
                f.write_all(&dds)?;

                total_in_comp += entry.compressed_size;
                total_in_virt += entry.uncompressed_size;
                total_out_dds += dds.len() as u64;
                items.push(TtpfExportItem {
                    index: entry.index,
                    file_name: fname,
                    width: entry.width,
                    height: entry.height,
                    dxgi_format: entry.dxgi_format,
                    dxgi_name: entry.dxgi_name,
                    codec: entry.codec.name().to_string(),
                    tile_mode: tile_mode.to_string(),
                    input_compressed_bytes: entry.compressed_size,
                    input_virtual_bytes: entry.uncompressed_size,
                    output_dds_bytes: dds.len(),
                });
            }
            Err(_) => {
                failed_count += 1;
            }
        }
    }

    Ok(TtpfExportSummary {
        source_archive: ttpf_path.display().to_string(),
        total_entries_in_archive: total_entries,
        exported_count: items.len(),
        failed_count,
        total_input_compressed_bytes: total_in_comp,
        total_input_virtual_bytes: total_in_virt,
        total_output_dds_bytes: total_out_dds,
        items,
    })
}

pub fn build_dds_dx10_header(
    width: u32,
    height: u32,
    dxgi_format: u8,
    info: DxgiLayoutInfo,
) -> Vec<u8> {
    let pitch_or_linear = if info.is_block_compressed {
        compute_mip_size(width, height, info) as u32
    } else {
        width * info.bytes_per_element as u32
    };
    let flags = DDSD_CAPS
        | DDSD_HEIGHT
        | DDSD_WIDTH
        | DDSD_PIXELFORMAT
        | if info.is_block_compressed {
            DDSD_LINEARSIZE
        } else {
            DDSD_PITCH
        };

    let mut hdr = vec![0u8; 148];
    hdr[0..4].copy_from_slice(&DDS_MAGIC.to_le_bytes());
    hdr[4..8].copy_from_slice(&124u32.to_le_bytes());
    hdr[8..12].copy_from_slice(&flags.to_le_bytes());
    hdr[12..16].copy_from_slice(&height.to_le_bytes());
    hdr[16..20].copy_from_slice(&width.to_le_bytes());
    hdr[20..24].copy_from_slice(&pitch_or_linear.to_le_bytes());
    hdr[24..28].copy_from_slice(&1u32.to_le_bytes()); // depth
    hdr[28..32].copy_from_slice(&1u32.to_le_bytes()); // mip count
    hdr[76..80].copy_from_slice(&32u32.to_le_bytes()); // ddspf.dwSize
    hdr[80..84].copy_from_slice(&DDPF_FOURCC.to_le_bytes());
    hdr[84..88].copy_from_slice(&DX10_FOURCC.to_le_bytes());
    hdr[108..112].copy_from_slice(&DDSCAPS_TEXTURE.to_le_bytes());

    // DDS_HEADER_DXT10 (20 bytes at offset 128)
    hdr[128..132].copy_from_slice(&u32::from(dxgi_format).to_le_bytes());
    hdr[132..136].copy_from_slice(&D3D10_RESOURCE_DIMENSION_TEXTURE2D.to_le_bytes());
    hdr[140..144].copy_from_slice(&1u32.to_le_bytes()); // arraySize
    hdr
}

pub fn compute_mip_size(width: u32, height: u32, info: DxgiLayoutInfo) -> usize {
    let ew = if info.is_block_compressed {
        width.div_ceil(4)
    } else {
        width
    }
    .max(1) as usize;
    let eh = if info.is_block_compressed {
        height.div_ceil(4)
    } else {
        height
    }
    .max(1) as usize;
    ew * eh * info.bytes_per_element
}

pub fn deswizzle_4kb_d(raw: &[u8], width: u32, height: u32, info: DxgiLayoutInfo) -> Vec<u8> {
    let ew = if info.is_block_compressed {
        width.div_ceil(4)
    } else {
        width
    }
    .max(1) as usize;
    let eh = if info.is_block_compressed {
        height.div_ceil(4)
    } else {
        height
    }
    .max(1) as usize;
    let bpe = info.bytes_per_element;
    let (tw, th) = tile_dims_4kb(bpe);
    let pw = ew.div_ceil(tw) * tw;
    let ph = eh.div_ceil(th) * th;
    let needed = pw * ph * bpe;
    let lin_len = ew * eh * bpe;
    if raw.len() < needed {
        return normalize_linear(raw, lin_len);
    }
    let mut out = vec![0u8; lin_len];
    let tiles_x = pw / tw;
    let elems_per_tile = tw * th;
    for y in 0..eh {
        let ty = y / th;
        let ly = y % th;
        for x in 0..ew {
            let tx = x / tw;
            let lx = x % tw;
            let t_idx = ty * tiles_x + tx;
            let m = morton_4kb(lx, ly, bpe);
            let src_off = (t_idx * elems_per_tile + m) * bpe;
            let dst_off = (y * ew + x) * bpe;
            out[dst_off..dst_off + bpe].copy_from_slice(&raw[src_off..src_off + bpe]);
        }
    }
    out
}

pub fn deswizzle_64kb(raw: &[u8], width: u32, height: u32, info: DxgiLayoutInfo) -> Vec<u8> {
    let bw = if info.is_block_compressed {
        width.div_ceil(4)
    } else {
        width
    }
    .max(1) as usize;
    let bh = if info.is_block_compressed {
        height.div_ceil(4)
    } else {
        height
    }
    .max(1) as usize;
    let bpe = info.bytes_per_element;
    let (tw, th, shift) = tile_dims_64kb(bpe);
    let pw = bw.div_ceil(tw) * tw;
    let ph = bh.div_ceil(th) * th;
    let needed = pw * ph * bpe;

    let mut owned;
    let src = if raw.len() >= needed {
        &raw[..needed]
    } else {
        owned = vec![0u8; needed];
        let copy_n = raw.len().min(needed);
        owned[..copy_n].copy_from_slice(&raw[..copy_n]);
        &owned
    };

    let mut out = vec![0u8; bw * bh * bpe];
    let tiles_x = pw / tw;
    for y in 0..bh {
        let ty = y / th;
        let ly = y % th;
        for x in 0..bw {
            let tx = x / tw;
            let lx = x % tw;
            let t_idx = ty * tiles_x + tx;
            let m = morton_64kb(lx, ly, bpe);
            let src_off = ((t_idx << shift) | m) * bpe;
            let dst_off = (y * bw + x) * bpe;
            out[dst_off..dst_off + bpe].copy_from_slice(&src[src_off..src_off + bpe]);
        }
    }
    out
}

fn compute_padded_4kb(width: u32, height: u32, info: DxgiLayoutInfo) -> usize {
    let ew = if info.is_block_compressed {
        width.div_ceil(4)
    } else {
        width
    }
    .max(1) as usize;
    let eh = if info.is_block_compressed {
        height.div_ceil(4)
    } else {
        height
    }
    .max(1) as usize;
    let (tw, th) = tile_dims_4kb(info.bytes_per_element);
    ew.div_ceil(tw) * tw * eh.div_ceil(th) * th * info.bytes_per_element
}

fn compute_padded_64kb(width: u32, height: u32, info: DxgiLayoutInfo) -> usize {
    let ew = if info.is_block_compressed {
        width.div_ceil(4)
    } else {
        width
    }
    .max(1) as usize;
    let eh = if info.is_block_compressed {
        height.div_ceil(4)
    } else {
        height
    }
    .max(1) as usize;
    let (tw, th, _) = tile_dims_64kb(info.bytes_per_element);
    ew.div_ceil(tw) * tw * eh.div_ceil(th) * th * info.bytes_per_element
}

fn tile_dims_4kb(bpe: usize) -> (usize, usize) {
    match bpe {
        16 => (16, 16),
        8 => (32, 16),
        4 => (32, 32),
        2 => (64, 32),
        _ => (64, 64),
    }
}

fn tile_dims_64kb(bpe: usize) -> (usize, usize, usize) {
    match bpe {
        16 => (64, 64, 12),
        8 => (128, 64, 13),
        4 => (128, 128, 14),
        2 => (256, 128, 15),
        _ => (256, 256, 16),
    }
}

fn morton_4kb(lx: usize, ly: usize, bpe: usize) -> usize {
    match bpe {
        16 => (ly & 3) | ((lx & 3) << 2) | (((ly >> 2) & 1) << 4) | (((lx >> 2) & 1) << 5) | (((ly >> 3) & 1) << 6) | (((lx >> 3) & 1) << 7),
        8 => (lx & 1) | ((ly & 3) << 1) | (((lx >> 1) & 3) << 3) | (((ly >> 2) & 1) << 5) | (((lx >> 3) & 1) << 6) | (((ly >> 3) & 1) << 7) | (((lx >> 4) & 1) << 8),
        4 => (lx & 3) | ((ly & 3) << 2) | (((lx >> 2) & 1) << 4) | (((ly >> 2) & 1) << 5) | (((ly >> 3) & 1) << 6) | (((lx >> 3) & 1) << 7) | (((ly >> 4) & 1) << 8) | (((lx >> 4) & 1) << 9),
        2 => (lx & 7) | ((ly & 7) << 3) | (((lx >> 3) & 1) << 6) | (((ly >> 3) & 1) << 7) | (((lx >> 4) & 1) << 8) | (((ly >> 4) & 1) << 9) | (((lx >> 5) & 1) << 10),
        _ => (ly & 7) | (((lx >> 1) & 1) << 3) | ((lx & 1) << 4) | (((lx >> 2) & 1) << 5) | (((ly >> 3) & 1) << 6) | (((lx >> 3) & 1) << 7) | (((lx >> 4) & 1) << 8) | (((ly >> 4) & 1) << 9) | (((lx >> 5) & 1) << 10) | (((ly >> 5) & 1) << 11),
    }
}

fn morton_64kb(lx: usize, ly: usize, bpe: usize) -> usize {
    match bpe {
        16 => (lx & 1) | ((ly & 1) << 1) | (((lx >> 1) & 1) << 2) | (((ly >> 1) & 1) << 3) | (((ly >> 2) & 1) << 4) | (((lx >> 2) & 1) << 5) | (((ly >> 3) & 1) << 6) | (((lx >> 3) & 1) << 7) | (((ly >> 4) & 1) << 8) | (((lx >> 4) & 1) << 9) | (((ly >> 5) & 1) << 10) | (((lx >> 5) & 1) << 11),
        8 => (lx & 1) | ((ly & 1) << 1) | (((lx >> 1) & 3) << 2) | (((ly >> 1) & 1) << 4) | (((ly >> 2) & 1) << 5) | (((lx >> 3) & 1) << 6) | (((ly >> 3) & 1) << 7) | (((lx >> 4) & 1) << 8) | (((ly >> 4) & 1) << 9) | (((lx >> 5) & 1) << 10) | (((ly >> 5) & 1) << 11) | (((lx >> 6) & 1) << 12),
        4 => (lx & 3) | ((ly & 3) << 2) | (((lx >> 2) & 1) << 4) | (((ly >> 2) & 1) << 5) | (((ly >> 3) & 1) << 6) | (((lx >> 3) & 1) << 7) | (((ly >> 4) & 1) << 8) | (((lx >> 4) & 1) << 9) | (((ly >> 5) & 1) << 10) | (((lx >> 5) & 1) << 11) | (((ly >> 6) & 1) << 12) | (((lx >> 6) & 1) << 13),
        2 => (lx & 7) | ((ly & 7) << 3) | (((lx >> 3) & 1) << 6) | (((ly >> 3) & 1) << 7) | (((lx >> 4) & 1) << 8) | (((ly >> 4) & 1) << 9) | (((lx >> 5) & 1) << 10) | (((ly >> 5) & 1) << 11) | (((lx >> 6) & 1) << 12) | (((ly >> 6) & 1) << 13) | (((lx >> 7) & 1) << 14),
        _ => (ly & 7) | (((lx >> 1) & 1) << 3) | ((lx & 1) << 4) | (((lx >> 2) & 1) << 5) | (((ly >> 3) & 1) << 6) | (((lx >> 3) & 1) << 7) | (((lx >> 4) & 1) << 8) | (((ly >> 4) & 1) << 9) | (((lx >> 5) & 1) << 10) | (((ly >> 5) & 1) << 11) | (((lx >> 6) & 1) << 12) | (((ly >> 6) & 1) << 13) | (((lx >> 7) & 1) << 14) | (((ly >> 7) & 1) << 15),
    }
}

fn normalize_linear(raw: &[u8], target_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; target_len];
    let copy_n = raw.len().min(target_len);
    out[..copy_n].copy_from_slice(&raw[..copy_n]);
    out
}

fn is_uniform_prefix(data: &[u8], count: usize) -> bool {
    let n = data.len().min(count);
    if n == 0 {
        return true;
    }
    let first = data[0];
    data[..n].iter().all(|&b| b == first)
}

fn span_chunk_stats(chunks: &[TtpfChunk], virt_offset: u64, length: u64) -> (u64, TtpfCodec) {
    if chunks.is_empty() || length == 0 {
        return (0, TtpfCodec::Raw);
    }
    let end = virt_offset + length;
    let first_idx = chunks.partition_point(|c| c.virtual_offset + c.uncompressed_size <= virt_offset);
    let mut total_comp = 0u64;
    let mut codec = TtpfCodec::Raw;
    let mut first = true;
    for c in &chunks[first_idx..] {
        if c.virtual_offset >= end {
            break;
        }
        total_comp += c.compressed_size();
        // Prefer reporting BCPack_* when a mipmapped texture mixes a Zlib mip-tail with BCPack mip-0.
        if first || (c.codec.bc_id().is_some() && codec.bc_id().is_none()) {
            codec = c.codec;
            first = false;
        }
    }
    (total_comp, codec)
}

fn is_zlib_header(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let cmf = data[0];
    let flg = data[1];
    (cmf & 0x0F) == 8 && (cmf >> 4) <= 7 && (((u16::from(cmf) << 8) | u16::from(flg)) % 31 == 0)
}

fn inflate_zlib(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if expected_size == 0 {
        return Ok(Vec::new());
    }
    let mut state = Inflate::new(is_zlib_header(compressed), 15);
    let mut out = vec![0u8; expected_size];
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;

    loop {
        let before_in = state.total_in() as usize;
        let before_out = state.total_out() as usize;
        let status = state
            .decompress(
                &compressed[in_pos..],
                &mut out[out_pos..],
                InflateFlush::NoFlush,
            )
            .map_err(|e| anyhow::anyhow!("zlib error: {e:?}"))?;
        let after_in = state.total_in() as usize;
        let after_out = state.total_out() as usize;
        in_pos = after_in;
        out_pos = after_out;

        match status {
            Status::StreamEnd => {
                out.truncate(out_pos);
                return Ok(out);
            }
            Status::Ok if after_in > before_in || after_out > before_out => {
                if out_pos >= out.len() {
                    return Ok(out);
                }
            }
            _ => bail!("RDS5 zlib stream ended prematurely ({out_pos}/{expected_size})"),
        }
    }
}

#[inline]
fn u32_le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

#[inline]
fn u64_le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtpfCompression {
    #[default]
    None,
    Zstd,
}

impl TtpfCompression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }
}

fn default_compression_none() -> String {
    "none".to_string()
}

fn default_project_name() -> String {
    crate::dxpk::PROJECT_NAME.to_string()
}

#[derive(Debug, Clone)]
pub struct TtpfBatchOptions {
    pub input_root: PathBuf,
    pub out_dir: PathBuf,
    pub max_mb: Option<u64>,
    pub resume: bool,
    pub threads: usize,
    pub compression: TtpfCompression,
    pub zstd_level: i32,
    pub min_free_gb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfArchiveProgress {
    pub rel_path: String,
    pub source_bytes: u64,
    pub total_entries: usize,
    pub exported_count: usize,
    pub skipped_existing_count: usize,
    pub failed_count: usize,
    pub output_dds_bytes: u64,
    #[serde(default = "default_compression_none")]
    pub compression: String,
    #[serde(default)]
    pub output_compressed_bytes: u64,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpfBatchReport {
    #[serde(default = "default_project_name")]
    pub project: String,
    pub input_root: String,
    pub out_dir: String,
    pub resume_enabled: bool,
    pub compression: String,
    pub zstd_level: i32,
    pub max_mb_limit: Option<u64>,
    pub min_free_gb: Option<u64>,
    pub stopped_for_min_free_gb: bool,
    pub stop_reason: Option<String>,
    pub threads: usize,
    pub archives_discovered: usize,
    pub archives_skipped_resumed: usize,
    pub archives_processed_this_run: usize,
    pub archives_completed_total: usize,
    pub total_source_bytes_processed_this_run: u64,
    pub total_textures_exported_this_run: usize,
    pub total_textures_skipped_existing_this_run: usize,
    pub total_textures_failed_this_run: usize,
    pub total_output_dds_bytes_this_run: u64,
    pub total_output_written_bytes_this_run: u64,
    pub disk_free_bytes_after: Option<u64>,
    pub archives: BTreeMap<String, TtpfArchiveProgress>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BatchCheckpoint {
    archives: BTreeMap<String, TtpfArchiveProgress>,
}

fn collect_ttpf_files(root: &Path, base: &Path, out: &mut Vec<(String, PathBuf, u64)>) -> Result<()> {
    if root.is_file() {
        let name = root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archive.ttpf")
            .to_string();
        let sz = root.metadata()?.len();
        out.push((name, root.to_path_buf(), sz));
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(root)
        .with_context(|| format!("reading directory {}", root.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_ttpf_files(&p, base, out)?;
        } else if ft.is_file()
            && p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("ttpf"))
        {
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('/', "\\");
            let sz = entry.metadata()?.len();
            out.push((rel, p, sz));
        }
    }
    Ok(())
}

fn save_checkpoint(state_path: &Path, ckpt: &BatchCheckpoint) -> Result<()> {
    let tmp = state_path.with_extension("json.tmp");
    let f = File::create(&tmp)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, ckpt)?;
    w.flush()?;
    std::fs::rename(&tmp, state_path)?;
    Ok(())
}

fn is_valid_existing_output(
    out_path: &Path,
    entry: &TtpfEntry,
    compression: TtpfCompression,
) -> Option<u64> {
    let meta = std::fs::metadata(out_path).ok()?;
    let len = meta.len();
    match compression {
        TtpfCompression::None => {
            let info = dxgi_info(entry.dxgi_format)?;
            let expected_len = (148 + compute_mip_size(entry.width, entry.height, info)) as u64;
            (len == expected_len).then_some(len)
        }
        TtpfCompression::Zstd => {
            if len < 4 {
                return None;
            }
            let mut f = File::open(out_path).ok()?;
            let mut magic = [0u8; 4];
            f.read_exact(&mut magic).ok()?;
            (magic == [0x28, 0xB5, 0x2F, 0xFD]).then_some(len)
        }
    }
}

/// Resumable, multi-threaded batch `.ttpf` -> PC DDS (DX10) converter (uncompressed convenience wrapper).
pub fn convert_ttpf_batch(
    input_root: &Path,
    out_dir: &Path,
    max_mb: Option<u64>,
    resume: bool,
    threads: usize,
) -> Result<TtpfBatchReport> {
    convert_ttpf_batch_with_options(&TtpfBatchOptions {
        input_root: input_root.to_path_buf(),
        out_dir: out_dir.to_path_buf(),
        max_mb,
        resume,
        threads,
        compression: TtpfCompression::None,
        zstd_level: 3,
        min_free_gb: None,
    })
}

/// Resumable, multi-threaded batch `.ttpf` -> PC DDS / `.dds.zst` converter with disk safety guard.
///
/// Archives are processed smallest-first to maximize early coverage under `--max-mb`,
/// with bounded RAM (per-thread 4-chunk cache), optional Zstd compression, `--min-free-gb`
/// disk space enforcement, and per-archive checkpointing for `--resume`.
pub fn convert_ttpf_batch_with_options(opts: &TtpfBatchOptions) -> Result<TtpfBatchReport> {
    std::fs::create_dir_all(&opts.out_dir)?;
    let state_path = opts.out_dir.join("ttdb_batch_state.json");
    let report_path = opts.out_dir.join("ttdb_batch_report.json");

    let mut discovered = Vec::new();
    collect_ttpf_files(&opts.input_root, &opts.input_root, &mut discovered)?;
    discovered.sort_by_key(|(rel, _, sz)| (*sz, rel.clone()));

    let mut ckpt: BatchCheckpoint = if opts.resume && state_path.is_file() {
        let raw = std::fs::read(&state_path)
            .with_context(|| format!("reading checkpoint {}", state_path.display()))?;
        serde_json::from_slice(&raw)
            .with_context(|| format!("parsing checkpoint {}", state_path.display()))?
    } else {
        BatchCheckpoint::default()
    };

    let worker_count = opts.threads.clamp(1, 12);
    let max_bytes = opts.max_mb.map(|m| m.saturating_mul(1024 * 1024));
    let min_free_bytes = opts
        .min_free_gb
        .filter(|&g| g > 0)
        .map(|g| g.saturating_mul(1024 * 1024 * 1024));
    let compress_str = opts.compression.as_str();

    let mut archives_skipped_resumed = 0usize;
    let mut archives_processed_this_run = 0usize;
    let mut run_source_bytes = 0u64;
    let mut run_exported = 0usize;
    let mut run_skipped_existing = 0usize;
    let mut run_failed = 0usize;
    let mut run_output_dds_bytes = 0u64;
    let mut run_output_written_bytes = 0u64;
    let mut stopped_for_min_free_gb = false;
    let mut stop_reason: Option<String> = None;

    for (rel_path, abs_path, file_size) in &discovered {
        if opts.resume
            && let Some(prev) = ckpt.archives.get(rel_path)
            && prev.completed
            && prev.source_bytes == *file_size
            && prev.compression == compress_str
        {
            archives_skipped_resumed += 1;
            continue;
        }

        if let Some(min_free) = min_free_bytes
            && let Some(avail) = crate::layout::query_path_free_bytes(&opts.out_dir)
            && avail < min_free
        {
            stopped_for_min_free_gb = true;
            stop_reason = Some(format!(
                "Stopped before {}: free space {:.2} GiB < --min-free-gb {} GiB",
                rel_path,
                avail as f64 / (1024.0 * 1024.0 * 1024.0),
                opts.min_free_gb.unwrap_or(0)
            ));
            break;
        }

        if let Some(limit) = max_bytes
            && run_source_bytes > 0
            && run_source_bytes.saturating_add(*file_size) > limit
        {
            break;
        }

        let archive = TtpfArchive::open(abs_path)?;
        let rel_no_ext = Path::new(rel_path).with_extension("");
        let archive_out_dir = opts.out_dir.join(rel_no_ext);
        std::fs::create_dir_all(&archive_out_dir)?;

        let total_entries = archive.entries.len();
        let active_threads = worker_count.min(total_entries.max(1));
        let slice_len = total_entries.div_ceil(active_threads).max(1);
        let abort_low_disk = AtomicBool::new(false);
        let written_counter = AtomicUsize::new(0);

        // (exported, skipped_existing, failed, raw_dds_bytes, written_bytes)
        let mut thread_stats: Vec<(usize, usize, usize, u64, u64)> =
            vec![(0, 0, 0, 0, 0); active_threads];
        std::thread::scope(|s| {
            let chunks_ref = &archive.chunks;
            let tables_ref = &archive.tables;
            let entries_ref = &archive.entries;
            let out_ref = &archive_out_dir;
            let root_out_ref = &opts.out_dir;
            let arc_file_size = archive.file_size;
            let abort_ref = &abort_low_disk;
            let counter_ref = &written_counter;
            let compression = opts.compression;
            let zstd_level = opts.zstd_level;
            let resume = opts.resume;

            for (tid, stat_slot) in thread_stats.iter_mut().enumerate() {
                let start = tid * slice_len;
                if start >= total_entries {
                    break;
                }
                let end = (start + slice_len).min(total_entries);
                s.spawn(move || {
                    let Ok(mut file) = File::open(abs_path) else {
                        stat_slot.2 += end - start;
                        return;
                    };
                    let mut cache = VecDeque::with_capacity(4);
                    for entry in &entries_ref[start..end] {
                        if abort_ref.load(Ordering::Relaxed) {
                            break;
                        }
                        let ext = match compression {
                            TtpfCompression::None => "dds",
                            TtpfCompression::Zstd => "dds.zst",
                        };
                        let fname = format!(
                            "tex_{:05}_{}x{}_{}_{}.{ext}",
                            entry.index, entry.width, entry.height, entry.dxgi_name, entry.hash_hex
                        );
                        let out_path = out_ref.join(&fname);

                        if resume
                            && let Some(existing_written) =
                                is_valid_existing_output(&out_path, entry, compression)
                        {
                            let raw_len = dxgi_info(entry.dxgi_format)
                                .map_or(existing_written, |info| {
                                    (148 + compute_mip_size(entry.width, entry.height, info)) as u64
                                });
                            stat_slot.1 += 1;
                            stat_slot.3 += raw_len;
                            stat_slot.4 += existing_written;
                            continue;
                        }

                        match export_entry_with_cache(
                            &mut file,
                            arc_file_size,
                            chunks_ref,
                            tables_ref,
                            &mut cache,
                            entry,
                        ) {
                            Ok((dds, _tile_mode)) => {
                                let raw_len = dds.len() as u64;
                                let payload = match compression {
                                    TtpfCompression::None => dds,
                                    TtpfCompression::Zstd => {
                                        match zstd::bulk::compress(&dds, zstd_level) {
                                            Ok(z) => z,
                                            Err(_) => {
                                                stat_slot.2 += 1;
                                                continue;
                                            }
                                        }
                                    }
                                };
                                let written_len = payload.len() as u64;
                                if let Ok(f) = File::create(&out_path) {
                                    let mut bw = BufWriter::new(f);
                                    if bw.write_all(&payload).is_ok() && bw.flush().is_ok() {
                                        stat_slot.0 += 1;
                                        stat_slot.3 += raw_len;
                                        stat_slot.4 += written_len;

                                        if let Some(min_free) = min_free_bytes
                                            && counter_ref.fetch_add(1, Ordering::Relaxed).is_multiple_of(64)
                                            && let Some(avail) =
                                                crate::layout::query_path_free_bytes(root_out_ref)
                                            && avail < min_free
                                        {
                                            abort_ref.store(true, Ordering::Relaxed);
                                        }
                                    } else {
                                        stat_slot.2 += 1;
                                    }
                                } else {
                                    stat_slot.2 += 1;
                                }
                            }
                            Err(_) => {
                                stat_slot.2 += 1;
                            }
                        }
                    }
                });
            }
        });

        let mut arc_exp = 0usize;
        let mut arc_skip = 0usize;
        let mut arc_fail = 0usize;
        let mut arc_dds_bytes = 0u64;
        let mut arc_written_bytes = 0u64;
        for (e, sk, fa, db, wb) in thread_stats {
            arc_exp += e;
            arc_skip += sk;
            arc_fail += fa;
            arc_dds_bytes += db;
            arc_written_bytes += wb;
        }

        let aborted = abort_low_disk.load(Ordering::Relaxed);
        archives_processed_this_run += 1;
        if !aborted {
            run_source_bytes += *file_size;
        }
        run_exported += arc_exp;
        run_skipped_existing += arc_skip;
        run_failed += arc_fail;
        run_output_dds_bytes += arc_dds_bytes;
        run_output_written_bytes += arc_written_bytes;

        ckpt.archives.insert(
            rel_path.clone(),
            TtpfArchiveProgress {
                rel_path: rel_path.clone(),
                source_bytes: *file_size,
                total_entries,
                exported_count: arc_exp,
                skipped_existing_count: arc_skip,
                failed_count: arc_fail,
                output_dds_bytes: arc_dds_bytes,
                compression: compress_str.to_string(),
                output_compressed_bytes: arc_written_bytes,
                completed: !aborted,
            },
        );
        save_checkpoint(&state_path, &ckpt)?;

        if aborted {
            stopped_for_min_free_gb = true;
            let avail_gib = crate::layout::query_path_free_bytes(&opts.out_dir)
                .map_or(0.0, |b| b as f64 / (1024.0 * 1024.0 * 1024.0));
            stop_reason = Some(format!(
                "Aborted mid-archive {}: free space {:.2} GiB < --min-free-gb {} GiB",
                rel_path,
                avail_gib,
                opts.min_free_gb.unwrap_or(0)
            ));
            break;
        }
    }

    let archives_completed_total = ckpt.archives.values().filter(|a| a.completed).count();
    let disk_free_bytes_after = crate::layout::query_path_free_bytes(&opts.out_dir);
    let report = TtpfBatchReport {
        project: crate::dxpk::PROJECT_NAME.to_string(),
        input_root: opts.input_root.display().to_string(),
        out_dir: opts.out_dir.display().to_string(),
        resume_enabled: opts.resume,
        compression: compress_str.to_string(),
        zstd_level: opts.zstd_level,
        max_mb_limit: opts.max_mb,
        min_free_gb: opts.min_free_gb,
        stopped_for_min_free_gb,
        stop_reason,
        threads: worker_count,
        archives_discovered: discovered.len(),
        archives_skipped_resumed,
        archives_processed_this_run,
        archives_completed_total,
        total_source_bytes_processed_this_run: run_source_bytes,
        total_textures_exported_this_run: run_exported,
        total_textures_skipped_existing_this_run: run_skipped_existing,
        total_textures_failed_this_run: run_failed,
        total_output_dds_bytes_this_run: run_output_dds_bytes,
        total_output_written_bytes_this_run: run_output_written_bytes,
        disk_free_bytes_after,
        archives: ckpt.archives,
    };

    let rf = File::create(&report_path)?;
    let mut rw = BufWriter::new(rf);
    serde_json::to_writer_pretty(&mut rw, &report)?;
    rw.flush()?;

    Ok(report)
}
