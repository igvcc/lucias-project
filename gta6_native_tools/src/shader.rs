//! `SGD5` & `ACCC`/`FSPX` shader container inspector and offline PC SM 6.6 DXIL converter.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use memchr::memmem;
use serde::{Deserialize, Serialize};
use victory_game::sgd5;
use victory_shader::{Container, FourCC, HwStage, emit, native_programs};

use crate::dxpk::{
    DXPK_VERSION, DxpkPack, DxpkSourceKind, DxpkStage, ManifestEntry, PackShadersManifest, fnv1a64,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaderRecordReport {
    pub index: usize,
    pub name: String,
    pub source_kind: String,
    pub record_kind_hex: String,
    pub dxbc_parts: Vec<String>,
    pub stage: Option<String>,
    pub wave64: Option<bool>,
    pub vgprs: Option<u16>,
    pub user_data_dwords: Option<u32>,
    pub root_cbvs: Vec<u8>,
    pub root_srvs: Vec<u8>,
    pub root_uavs: Vec<u8>,
    pub static_samplers: usize,
    pub input_dxbc_bytes: usize,
    pub output_dxil_bytes: Option<usize>,
    pub translated_ok: bool,
    pub error: Option<String>,
    pub output_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaderBatchSummary {
    pub source_file: String,
    pub total_candidates: usize,
    pub processed: usize,
    pub translated_ok: usize,
    pub failed: usize,
    pub stage_counts: BTreeMap<String, usize>,
    pub total_input_dxbc_bytes: u64,
    pub total_output_dxil_bytes: u64,
    pub records: Vec<ShaderRecordReport>,
}

fn stage_name(s: HwStage) -> &'static str {
    match s {
        HwStage::Ls => "LS",
        HwStage::Hs => "HS",
        HwStage::Es => "ES",
        HwStage::Gs => "GS",
        HwStage::Vs => "VS",
        HwStage::Ps => "PS",
        HwStage::Ms => "MS",
        HwStage::Cs => "CS",
    }
}

/// Configures `victory_shader` for desktop Wave32 D3D12 targets (e.g., NVIDIA Ampere RTX 3070).
pub fn configure_host_wave32() {
    emit::set_host_max_wave(32);
    emit::set_host_rdna(false);
}

/// Inspects and translates a single raw DXBC container (Xbox `DXIL`/`XDAT` or `ACCC`/`FSPX`) to PC SM 6.6 DXIL.
pub fn inspect_and_translate_dxbc(
    index: usize,
    name: &str,
    source_kind: &str,
    record_kind: u8,
    dxbc_bytes: &[u8],
) -> (ShaderRecordReport, Option<Vec<u8>>) {
    configure_host_wave32();
    let parsed = Container::parse(dxbc_bytes);
    let dxbc_parts = match &parsed {
        Ok(c) => c.parts.iter().map(|p| p.fourcc.to_string()).collect(),
        Err(_) => Vec::new(),
    };

    let mut stage = None;
    let mut wave64 = None;
    let mut vgprs = None;
    if let Ok(c) = &parsed
        && let Some(part) = c.part(FourCC::DXIL).or_else(|| c.part(FourCC::ACCC))
        && let Ok(progs) = native_programs(part.data)
        && let Some(p) = progs
            .iter()
            .find(|p| matches!(p.stage, HwStage::Vs | HwStage::Ps | HwStage::Cs | HwStage::Ms))
            .or_else(|| progs.first())
    {
        stage = Some(stage_name(p.stage).to_string());
        wave64 = Some(p.wave64);
        vgprs = Some(p.vgprs);
    }

    match emit::translate(dxbc_bytes) {
        Ok(host) => {
            let report = ShaderRecordReport {
                index,
                name: name.to_string(),
                source_kind: source_kind.to_string(),
                record_kind_hex: format!("0x{record_kind:02X}"),
                dxbc_parts,
                stage: Some(stage_name(host.stage).to_string()),
                wave64,
                vgprs,
                user_data_dwords: Some(host.user_data_dwords()),
                root_cbvs: host.root_cbvs,
                root_srvs: host.root_srvs,
                root_uavs: host.root_uavs,
                static_samplers: host.static_samplers.len(),
                input_dxbc_bytes: dxbc_bytes.len(),
                output_dxil_bytes: Some(host.dxil.len()),
                translated_ok: true,
                error: None,
                output_file: None,
            };
            (report, Some(host.dxil))
        }
        Err(err) => {
            let report = ShaderRecordReport {
                index,
                name: name.to_string(),
                source_kind: source_kind.to_string(),
                record_kind_hex: format!("0x{record_kind:02X}"),
                dxbc_parts,
                stage,
                wave64,
                vgprs,
                user_data_dwords: None,
                root_cbvs: Vec::new(),
                root_srvs: Vec::new(),
                root_uavs: Vec::new(),
                static_samplers: 0,
                input_dxbc_bytes: dxbc_bytes.len(),
                output_dxil_bytes: None,
                translated_ok: false,
                error: Some(err.to_string()),
                output_file: None,
            };
            (report, None)
        }
    }
}

/// Scans `path` (e.g. `shaders.rpf` for `SGD5`, or `amd_fidelityfx_upscaler_xbox.dll` for `ACCC` DXBCs),
/// translates up to `limit` shaders into `out_dir`, and returns detailed statistics.
pub fn convert_shaders_from_file(
    path: &Path,
    out_dir: &Path,
    limit: usize,
) -> Result<ShaderBatchSummary> {
    std::fs::create_dir_all(out_dir)?;
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    let mut stage_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut records = Vec::new();
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut translated_ok = 0usize;
    let mut failed = 0usize;
    let mut total_candidates = 0usize;

    if sgd5::is_sgd5(&data) {
        for (idx, rec) in sgd5::records(&data).enumerate() {
            total_candidates += 1;
            if records.len() >= limit {
                continue;
            }
            let name = rec
                .name
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("sgd5_{idx:05}"));
            let Some(dxbc) = rec.unpack() else {
                failed += 1;
                records.push(ShaderRecordReport {
                    index: idx,
                    name,
                    source_kind: "SGD5".into(),
                    record_kind_hex: format!("0x{:02X}", rec.kind),
                    dxbc_parts: Vec::new(),
                    stage: None,
                    wave64: None,
                    vgprs: None,
                    user_data_dwords: None,
                    root_cbvs: Vec::new(),
                    root_srvs: Vec::new(),
                    root_uavs: Vec::new(),
                    static_samplers: 0,
                    input_dxbc_bytes: 0,
                    output_dxil_bytes: None,
                    translated_ok: false,
                    error: Some("SGD5 deflate unpack failed".into()),
                    output_file: None,
                });
                continue;
            };
            let (mut rep, dxil_opt) =
                inspect_and_translate_dxbc(idx, &name, "SGD5", rec.kind, &dxbc);
            if let Some(st) = &rep.stage {
                *stage_counts.entry(st.clone()).or_default() += 1;
            }
            total_in += rep.input_dxbc_bytes as u64;
            if let Some(dxil) = dxil_opt {
                let safe = sanitize_filename(&rep.name);
                let out_name = format!("{idx:05}_{safe}.dxil");
                let mut f = File::create(out_dir.join(&out_name))?;
                f.write_all(&dxil)?;
                rep.output_file = Some(out_name);
                total_out += dxil.len() as u64;
                translated_ok += 1;
            } else {
                failed += 1;
            }
            records.push(rep);
        }
    } else {
        // Standalone DXBC / ACCC containers (e.g. amd_fidelityfx_upscaler_xbox.dll).
        for (idx, off) in memmem::find_iter(&data, b"DXBC").enumerate() {
            if off + 0x20 > data.len() {
                continue;
            }
            let total_sz = u32::from_le_bytes([
                data[off + 0x18],
                data[off + 0x19],
                data[off + 0x1A],
                data[off + 0x1B],
            ]) as usize;
            if total_sz < 0x20 || off + total_sz > data.len() {
                continue;
            }
            let slice = &data[off..off + total_sz];
            let Ok(container) = Container::parse(slice) else {
                continue;
            };
            total_candidates += 1;
            if records.len() >= limit {
                continue;
            }
            let has_accc = container.part(FourCC::ACCC).is_some();
            let src_kind = if has_accc { "ACCC/FSPX" } else { "DXBC" };
            let name = format!("dxbc_{idx:03}_at_{off:06x}");
            let (mut rep, dxil_opt) =
                inspect_and_translate_dxbc(idx, &name, src_kind, 0, slice);
            if let Some(st) = &rep.stage {
                *stage_counts.entry(st.clone()).or_default() += 1;
            }
            total_in += rep.input_dxbc_bytes as u64;
            if let Some(dxil) = dxil_opt {
                let out_name = format!("{name}.dxil");
                let mut f = File::create(out_dir.join(&out_name))?;
                f.write_all(&dxil)?;
                rep.output_file = Some(out_name);
                total_out += dxil.len() as u64;
                translated_ok += 1;
            } else {
                failed += 1;
            }
            records.push(rep);
        }
    }

    let meta_path = out_dir.join("shader_metadata.json");
    let summary = ShaderBatchSummary {
        source_file: path.display().to_string(),
        total_candidates,
        processed: records.len(),
        translated_ok,
        failed,
        stage_counts,
        total_input_dxbc_bytes: total_in,
        total_output_dxil_bytes: total_out,
        records,
    };
    std::fs::write(&meta_path, serde_json::to_string_pretty(&summary)?)?;
    Ok(summary)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect()
}

struct TranslatedCandidate {
    index: usize,
    name: String,
    source_file: String,
    source_kind: DxpkSourceKind,
    stage: DxpkStage,
    dxbc_hash: u64,
    input_dxbc_bytes: usize,
    dxil: Option<Vec<u8>>,
    error: Option<String>,
}

fn translate_single_candidate(
    index: usize,
    name: String,
    source_file: String,
    source_kind: DxpkSourceKind,
    dxbc_bytes: &[u8],
) -> TranslatedCandidate {
    let dxbc_hash = fnv1a64(dxbc_bytes);
    let mut detected_stage = DxpkStage::Unknown;
    if let Ok(c) = Container::parse(dxbc_bytes)
        && let Some(part) = c.part(FourCC::DXIL).or_else(|| c.part(FourCC::ACCC))
        && let Ok(progs) = native_programs(part.data)
        && let Some(p) = progs
            .iter()
            .find(|p| matches!(p.stage, HwStage::Vs | HwStage::Ps | HwStage::Cs | HwStage::Ms))
            .or_else(|| progs.first())
    {
        detected_stage = DxpkStage::from_name(stage_name(p.stage));
    }

    match emit::translate(dxbc_bytes) {
        Ok(host) => {
            let st = DxpkStage::from_name(stage_name(host.stage));
            TranslatedCandidate {
                index,
                name,
                source_file,
                source_kind,
                stage: st,
                dxbc_hash,
                input_dxbc_bytes: dxbc_bytes.len(),
                dxil: Some(host.dxil),
                error: None,
            }
        }
        Err(err) => TranslatedCandidate {
            index,
            name,
            source_file,
            source_kind,
            stage: detected_stage,
            dxbc_hash,
            input_dxbc_bytes: dxbc_bytes.len(),
            dxil: None,
            error: Some(err.to_string()),
        },
    }
}

/// Scans all SGD5 records and/or standalone DXBC/ACCC containers across `inputs`,
/// translates them in parallel to SM 6.6 DXIL, deduplicates by FNV-1a-64 hash of
/// the input Xbox DXBC bytes, writes `out_dxpk` (DXPK v1), and writes `out_manifest`.
pub fn pack_shaders_to_dxpk(
    inputs: &[PathBuf],
    out_dxpk: &Path,
    out_manifest: &Path,
    threads: usize,
) -> Result<PackShadersManifest> {
    configure_host_wave32();
    let worker_count = threads.clamp(1, 16);
    let mut pack = DxpkPack::new();
    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut stage_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut source_kind_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut failure_reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_input_shaders = 0usize;
    let mut translated_ok = 0usize;
    let mut deduplicated = 0usize;
    let mut failed = 0usize;
    let mut total_input_dxbc_bytes = 0u64;
    let mut total_dxil_bytes = 0u64;

    for input_path in inputs {
        let data = std::fs::read(input_path)
            .with_context(|| format!("reading shader source {}", input_path.display()))?;
        let source_file = input_path.display().to_string();

        enum WorkItem<'a> {
            Sgd5(usize, sgd5::Record<'a>),
            Dxbc(usize, String, DxpkSourceKind, &'a [u8]),
        }

        let mut work: Vec<WorkItem<'_>> = Vec::new();
        if sgd5::is_sgd5(&data) {
            for (idx, rec) in sgd5::records(&data).enumerate() {
                work.push(WorkItem::Sgd5(idx, rec));
            }
        } else {
            for (idx, off) in memmem::find_iter(&data, b"DXBC").enumerate() {
                if off + 0x20 > data.len() {
                    continue;
                }
                let total_sz = u32::from_le_bytes([
                    data[off + 0x18],
                    data[off + 0x19],
                    data[off + 0x1A],
                    data[off + 0x1B],
                ]) as usize;
                if total_sz < 0x20 || off + total_sz > data.len() {
                    continue;
                }
                let slice = &data[off..off + total_sz];
                let Ok(container) = Container::parse(slice) else {
                    continue;
                };
                let kind = if container.part(FourCC::ACCC).is_some() {
                    DxpkSourceKind::AcccFspx
                } else {
                    DxpkSourceKind::Dxbc
                };
                let name = format!("dxbc_{idx:03}_at_{off:06x}");
                work.push(WorkItem::Dxbc(work.len(), name, kind, slice));
            }
        }

        let next_idx = AtomicUsize::new(0);
        let mut results: Vec<Vec<TranslatedCandidate>> =
            (0..worker_count).map(|_| Vec::new()).collect();

        std::thread::scope(|s| {
            let work_ref = &work;
            let next_ref = &next_idx;
            let src_ref = &source_file;
            for slot in &mut results {
                s.spawn(move || {
                    loop {
                        let i = next_ref.fetch_add(1, Ordering::Relaxed);
                        if i >= work_ref.len() {
                            break;
                        }
                        let cand = match &work_ref[i] {
                            WorkItem::Sgd5(idx, rec) => {
                                let name = rec
                                    .name
                                    .map(|n| n.to_string())
                                    .unwrap_or_else(|| format!("sgd5_{idx:05}"));
                                match rec.unpack() {
                                    Some(dxbc) => translate_single_candidate(
                                        *idx,
                                        name,
                                        src_ref.clone(),
                                        DxpkSourceKind::Sgd5,
                                        &dxbc,
                                    ),
                                    None => TranslatedCandidate {
                                        index: *idx,
                                        name,
                                        source_file: src_ref.clone(),
                                        source_kind: DxpkSourceKind::Sgd5,
                                        stage: DxpkStage::Unknown,
                                        dxbc_hash: 0,
                                        input_dxbc_bytes: 0,
                                        dxil: None,
                                        error: Some("SGD5 deflate unpack failed".into()),
                                    },
                                }
                            }
                            WorkItem::Dxbc(idx, name, kind, slice) => translate_single_candidate(
                                *idx,
                                name.clone(),
                                src_ref.clone(),
                                *kind,
                                slice,
                            ),
                        };
                        slot.push(cand);
                    }
                });
            }
        });

        let mut flat: Vec<TranslatedCandidate> = results.into_iter().flatten().collect();
        flat.sort_by_key(|c| c.index);

        for c in flat {
            total_input_shaders += 1;
            total_input_dxbc_bytes += c.input_dxbc_bytes as u64;
            *stage_counts
                .entry(c.stage.as_name().to_string())
                .or_default() += 1;
            *source_kind_counts
                .entry(c.source_kind.as_name().to_string())
                .or_default() += 1;

            let mut dxil_bytes = 0usize;
            let mut is_dedup = false;
            let ok = c.dxil.is_some();

            if let Some(dxil) = c.dxil {
                dxil_bytes = dxil.len();
                total_dxil_bytes += dxil_bytes as u64;
                translated_ok += 1;
                // Insert into DxpkPack using precomputed dxbc_hash? Wait: insert_with_hash hashes dxbc_bytes.
                // Since we already have dxbc_hash, let's add insert_prehashed on DxpkPack or pass dummy?
                // Even cleaner: add insert_prehashed to DxpkPack so we don't keep dxbc_bytes alive!
                let added = pack.insert_prehashed(c.dxbc_hash, dxil, c.stage, c.source_kind);
                if !added {
                    is_dedup = true;
                    deduplicated += 1;
                }
            } else {
                failed += 1;
                if let Some(err) = &c.error {
                    let key = err.chars().take(96).collect::<String>();
                    *failure_reasons.entry(key).or_default() += 1;
                }
            }

            entries.push(ManifestEntry {
                index: c.index,
                name: c.name,
                source_file: c.source_file,
                source_kind: c.source_kind.as_name().to_string(),
                stage: c.stage.as_name().to_string(),
                dxbc_hash_hex: format!("{:016x}", c.dxbc_hash),
                input_dxbc_bytes: c.input_dxbc_bytes,
                dxil_bytes,
                deduplicated: is_dedup,
                translated_ok: ok,
                error: c.error,
            });
        }
    }

    let (file_bytes, unique_dxil_bytes) = pack.write_to_file(out_dxpk)?;
    let manifest = PackShadersManifest {
        project: crate::dxpk::PROJECT_NAME.to_string(),
        dxpk_version: DXPK_VERSION,
        dxilpack_path: out_dxpk.display().to_string(),
        total_input_shaders,
        translated_ok,
        unique_packed: pack.len(),
        unique_dxil_blobs: pack.unique_blob_count(),
        deduplicated,
        failed,
        total_input_dxbc_bytes,
        total_dxil_bytes,
        unique_dxil_bytes,
        file_bytes,
        stage_counts,
        source_kind_counts,
        failure_reasons,
        entries,
    };

    if let Some(parent) = out_manifest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mf = File::create(out_manifest)
        .with_context(|| format!("creating {}", out_manifest.display()))?;
    let mut bw = BufWriter::with_capacity(512 * 1024, mf);
    serde_json::to_writer_pretty(&mut bw, &manifest)?;
    bw.flush()?;

    Ok(manifest)
}
