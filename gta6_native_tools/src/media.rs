//! Audio (`ADAT` / Opus, `RIFF`/`WEM`, `XMA2`) and Video (`KB2*` Bink2) header inspectors.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result, bail};
use memchr::memmem;
use serde::{Deserialize, Serialize};
use victory_formats::xma;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bink2Info {
    pub offset: u64,
    pub fourcc: String,
    pub container_bytes: u64,
    pub frame_count: u32,
    pub max_frame_bytes: u32,
    pub width: u32,
    pub height: u32,
    pub fps_num: u32,
    pub fps_den: u32,
    pub fps: f64,
    pub duration_sec: f64,
    pub flags: u32,
    pub audio_tracks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdatTrackInfo {
    pub index: usize,
    pub stream_id: u32,
    pub offset: usize,
    pub size: usize,
    pub sample_rate: u32,
    pub channels: u8,
    pub codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdatBankInfo {
    pub offset: u64,
    pub version: u16,
    pub header_flags: u16,
    pub stream_count: usize,
    pub header_size: usize,
    pub tracks: Vec<AdatTrackInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiffWemInfo {
    pub offset: u64,
    pub form: String,
    pub riff_size: u32,
    pub format_tag: u16,
    pub format_name: String,
    pub channels: u16,
    pub sample_rate: u32,
    pub avg_bytes_per_sec: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
    pub data_bytes: u32,
    pub xma2_packets_probed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaInspectionSummary {
    pub path: String,
    pub file_size: u64,
    pub scanned_bytes: u64,
    pub bink2_count: usize,
    pub bink2_total_bytes: u64,
    pub bink2_total_frames: u64,
    pub bink2_resolutions: BTreeMap<String, usize>,
    pub bink2_samples: Vec<Bink2Info>,
    pub adat_bank_count: usize,
    pub adat_track_count: usize,
    pub adat_sample_rates: Vec<u32>,
    pub adat_samples: Vec<AdatBankInfo>,
    pub riff_wem_samples: Vec<RiffWemInfo>,
}

pub fn parse_bink2_header(data: &[u8], offset: u64, max_remaining: u64) -> Option<Bink2Info> {
    if data.len() < 44 {
        return None;
    }
    let is_bink = (data.starts_with(b"KB2") || data.starts_with(b"BIK"))
        && data[3].is_ascii_lowercase();
    if !is_bink {
        return None;
    }
    let container_bytes = u64::from(u32_le(data, 4)) + 8;
    let frames = u32_le(data, 8);
    let max_frame = u32_le(data, 12);
    let frames2 = u32_le(data, 16);
    let w = u32_le(data, 20);
    let h = u32_le(data, 24);
    let fps_num = u32_le(data, 28);
    let fps_den = u32_le(data, 32);
    let flags = u32_le(data, 36);
    let audio_tracks = u32_le(data, 40);

    if !(1..=500_000).contains(&frames)
        || frames != frames2
        || !(16..=8192).contains(&w)
        || !(16..=8192).contains(&h)
        || fps_num == 0
        || fps_den == 0
        || container_bytes < 1024
        || container_bytes > max_remaining
    {
        return None;
    }

    let fps = f64::from(fps_num) / f64::from(fps_den);
    let duration_sec = if fps > 0.0 {
        f64::from(frames) / fps
    } else {
        0.0
    };

    Some(Bink2Info {
        offset,
        fourcc: String::from_utf8_lossy(&data[..4]).to_string(),
        container_bytes,
        frame_count: frames,
        max_frame_bytes: max_frame,
        width: w,
        height: h,
        fps_num,
        fps_den,
        fps: (fps * 100.0).round() / 100.0,
        duration_sec: (duration_sec * 100.0).round() / 100.0,
        flags,
        audio_tracks,
    })
}

pub fn parse_adat_bank(data: &[u8], abs_offset: u64) -> Result<AdatBankInfo> {
    if data.len() < 16 || &data[..4] != b"ADAT" {
        bail!("Not an ADAT bank");
    }
    let flags = u32_le(data, 4);
    let version = (flags & 0xFFFF) as u16;
    let header_flags = (flags >> 16) as u16;
    let stream_count = u32_le(data, 8) as usize;
    let header_size = u32_le(data, 12) as usize;

    if !matches!(version, 1 | 2)
        || stream_count == 0
        || stream_count > 65_536
        || header_size < 16
        || header_size > data.len()
    {
        bail!("Invalid ADAT header (version={version}, streams={stream_count}, hdr={header_size})");
    }
    let chunk_tbl_off = 16 + stream_count * 4;
    if chunk_tbl_off + 8 > header_size {
        bail!("ADAT stream table exceeds header size");
    }

    let mut stream_ids = Vec::with_capacity(stream_count);
    for i in 0..stream_count {
        stream_ids.push(u32_le(data, 16 + i * 4));
    }

    let mut raw_chunks = Vec::new();
    let mut format_rates = Vec::new();
    let mut off = chunk_tbl_off;
    while off + 8 <= header_size {
        let val = u64_le(data, off);
        let tag = (val >> 56) as u8;
        let size = ((val >> 28) & 0x0FFF_FFFF) as usize;
        let chunk_off = (val & 0x0FFF_FFFF) as usize;
        if tag == 0 && chunk_off == 0 {
            break;
        }
        if tag == 0x76 && size >= 10 && chunk_off + 10 <= data.len() {
            let sr = u32::from(u16_le(data, chunk_off + 8));
            if (8_000..=192_000).contains(&sr) {
                format_rates.push(sr);
                if let Some(last) = raw_chunks.last_mut() {
                    let (_, _, last_sr): &mut (usize, usize, u32) = last;
                    if *last_sr == 0 {
                        *last_sr = sr;
                    }
                }
            }
        } else if tag == 0x55 && size > 0 && chunk_off + size <= data.len() {
            raw_chunks.push((chunk_off, size, 0u32));
        }
        off += 8;
    }

    let default_sr = format_rates.first().copied().unwrap_or(48_000);
    let mut tracks = Vec::with_capacity(raw_chunks.len());
    for (i, (coff, csz, sr)) in raw_chunks.into_iter().enumerate() {
        let sample_rate = if sr != 0 {
            sr
        } else {
            format_rates.get(i).copied().unwrap_or(default_sr)
        };
        let stream_id = stream_ids.get(i).copied().unwrap_or(0);
        let (channels, codec) = probe_audio_payload(&data[coff..coff + csz]);
        tracks.push(AdatTrackInfo {
            index: i,
            stream_id,
            offset: coff,
            size: csz,
            sample_rate,
            channels,
            codec,
        });
    }

    if tracks.is_empty() && format_rates.is_empty() {
        bail!("ADAT bank contained no valid 0x55/0x76 chunks");
    }

    Ok(AdatBankInfo {
        offset: abs_offset,
        version,
        header_flags,
        stream_count,
        header_size,
        tracks,
    })
}

pub fn parse_riff_wem(data: &[u8], offset: u64) -> Option<RiffWemInfo> {
    if data.len() < 12 || &data[0..4] != b"RIFF" {
        return None;
    }
    let riff_size = u32_le(data, 4);
    let form = String::from_utf8_lossy(&data[8..12]).to_string();
    if form != "WAVE" && form != "XWMA" {
        return None;
    }

    let mut pos = 12usize;
    let end = data.len().min(riff_size as usize + 8);
    let mut fmt_tag = 0u16;
    let mut channels = 0u16;
    let mut sample_rate = 0u32;
    let mut avg_bps = 0u32;
    let mut block_align = 0u16;
    let mut bits_per_sample = 0u16;
    let mut data_bytes = 0u32;
    let mut xma2_packets_probed = 0usize;

    while pos + 8 <= end {
        let id = &data[pos..pos + 4];
        let csize = u32_le(data, pos + 4) as usize;
        let body_start = pos + 8;
        let body_end = body_start.saturating_add(csize).min(end);
        let body = &data[body_start..body_end];

        if id == b"fmt " && body.len() >= 16 {
            fmt_tag = u16_le(body, 0);
            channels = u16_le(body, 2);
            sample_rate = u32_le(body, 4);
            avg_bps = u32_le(body, 8);
            block_align = u16_le(body, 12);
            bits_per_sample = u16_le(body, 14);
        } else if id == b"data" {
            data_bytes = csize as u32;
            if fmt_tag == 0x0166 && body.len() >= xma::PACKET_BYTES {
                let n = body.len() / xma::PACKET_BYTES;
                for i in 0..n.min(8) {
                    if xma::packet(body, i).is_some() {
                        xma2_packets_probed += 1;
                    }
                }
            }
        }
        pos = body_start + csize + (csize & 1);
    }

    let format_name = match fmt_tag {
        0x0001 => "PCM",
        0x0003 => "IEEE_FLOAT",
        0x0166 => "XMA2",
        0xFFFF => "Wwise_Vorbis_or_Opus",
        0xFFFE => "WAVE_FORMAT_EXTENSIBLE",
        0x3039..=0x3041 => "Wwise_Opus",
        _ => "Unknown",
    }
    .to_string();

    Some(RiffWemInfo {
        offset,
        form,
        riff_size,
        format_tag: fmt_tag,
        format_name,
        channels,
        sample_rate,
        avg_bytes_per_sec: avg_bps,
        block_align,
        bits_per_sample,
        data_bytes,
        xma2_packets_probed,
    })
}

/// Scans an archive (either page-jumping Bink2 containers or bounded slice for ADAT/RIFF) read-only.
pub fn inspect_media_file(
    path: &Path,
    max_scan_mb: usize,
    sample_limit: usize,
) -> Result<MediaInspectionSummary> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let file_size = f.metadata()?.len();

    let mut bink2_count = 0usize;
    let mut bink2_total_bytes = 0u64;
    let mut bink2_total_frames = 0u64;
    let mut bink2_resolutions: BTreeMap<String, usize> = BTreeMap::new();
    let mut bink2_samples = Vec::new();

    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Fast page-jumping scan for movies.rpf (reads only 44 bytes per Bink2 container!).
    let mut scanned_bytes = 0u64;
    if fname.contains("movie") {
        let mut cur = 0u64;
        let mut hdr = [0u8; 44];
        while cur + 44 <= file_size {
            f.seek(SeekFrom::Start(cur))?;
            if f.read_exact(&mut hdr).is_err() {
                break;
            }
            if let Some(info) = parse_bink2_header(&hdr, cur, file_size - cur) {
                bink2_count += 1;
                bink2_total_bytes += info.container_bytes;
                bink2_total_frames += u64::from(info.frame_count);
                let key = format!("{}x{}@{}fps", info.width, info.height, info.fps.round() as u32);
                *bink2_resolutions.entry(key).or_default() += 1;
                if bink2_samples.len() < sample_limit {
                    bink2_samples.push(info.clone());
                }
                let jump = info.container_bytes.next_multiple_of(4096).max(4096);
                cur += jump;
                continue;
            }
            cur += 4096;
        }
        scanned_bytes = file_size;
    }

    // Bounded window scan for ADAT / RIFF-WEM / Bink2 in other files.
    let window_cap = (max_scan_mb as u64 * 1024 * 1024).min(file_size);
    let mut adat_bank_count = 0usize;
    let mut adat_track_count = 0usize;
    let mut adat_rates = std::collections::BTreeSet::new();
    let mut adat_samples = Vec::new();
    let mut riff_wem_samples = Vec::new();

    if window_cap > 0 && !fname.contains("movie") {
        let mut buf = vec![0u8; window_cap as usize];
        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut buf)?;
        scanned_bytes = window_cap;

        for pos in memmem::find_iter(&buf, b"ADAT") {
            let end = (pos + 2 * 1024 * 1024).min(buf.len());
            if let Ok(bank) = parse_adat_bank(&buf[pos..end], pos as u64) {
                adat_bank_count += 1;
                adat_track_count += bank.tracks.len();
                for t in &bank.tracks {
                    adat_rates.insert(t.sample_rate);
                }
                if adat_samples.len() < sample_limit {
                    adat_samples.push(bank);
                }
            }
        }

        for pos in memmem::find_iter(&buf, b"RIFF") {
            if let Some(wem) = parse_riff_wem(&buf[pos..], pos as u64)
                && riff_wem_samples.len() < sample_limit
            {
                riff_wem_samples.push(wem);
            }
        }

        // Also check page-aligned Bink2 in bounded slice if any
        let mut off = 0usize;
        while off + 44 <= buf.len() {
            if let Some(info) = parse_bink2_header(&buf[off..], off as u64, (buf.len() - off) as u64) {
                bink2_count += 1;
                bink2_total_bytes += info.container_bytes;
                bink2_total_frames += u64::from(info.frame_count);
                let key = format!("{}x{}@{}fps", info.width, info.height, info.fps.round() as u32);
                *bink2_resolutions.entry(key).or_default() += 1;
                if bink2_samples.len() < sample_limit {
                    bink2_samples.push(info.clone());
                }
                off += (info.container_bytes as usize).next_multiple_of(4096).max(4096);
                continue;
            }
            off += 4096;
        }
    }

    Ok(MediaInspectionSummary {
        path: path.display().to_string(),
        file_size,
        scanned_bytes,
        bink2_count,
        bink2_total_bytes,
        bink2_total_frames,
        bink2_resolutions,
        bink2_samples,
        adat_bank_count,
        adat_track_count,
        adat_sample_rates: adat_rates.into_iter().collect(),
        adat_samples,
        riff_wem_samples,
    })
}

fn probe_audio_payload(payload: &[u8]) -> (u8, String) {
    if payload.len() >= 2 {
        let toc = payload[0];
        let config = toc >> 3;
        let stereo = (toc & 0x04) != 0;
        if config <= 31 && payload.len() >= 16 {
            return (if stereo { 2 } else { 1 }, "Opus".into());
        }
    }
    if payload.len() >= 4 && &payload[..4] == b"RIFF" {
        return (2, "RIFF".into());
    }
    if payload.len() >= xma::PACKET_BYTES && xma::packet(payload, 0).is_some() {
        return (2, "XMA2".into());
    }
    (2, "PCM/Raw".into())
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
