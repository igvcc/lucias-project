use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use gta6_native_tools::{layout, media, rpf9, shader, ttpf};
use serde::Serialize;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CompressArg {
    None,
    Zstd,
}

impl From<CompressArg> for ttpf::TtpfCompression {
    fn from(value: CompressArg) -> Self {
        match value {
            CompressArg::None => Self::None,
            CompressArg::Zstd => Self::Zstd,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "lucias-tools",
    version,
    about = "LUCIAS PROJECT — Read-only RPF9 inventory and offline PC asset/shader conversion CLI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inventory all RPF9 and TTPF archives in a build directory (strictly read-only).
    Inventory {
        #[arg(long, default_value = r"S:\gta\Gta6fordevelopersacces")]
        root: PathBuf,
        /// Also scan smaller RPFs (common.rpf, script.rpf, textures.rpf, shaders.rpf) for entry types.
        #[arg(long)]
        scan_small: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect a single RPF9 archive header and bounded stream contents.
    InspectRpf {
        path: PathBuf,
        #[arg(long, default_value_t = 32)]
        max_mb: u64,
        #[arg(long, default_value_t = 15)]
        samples: usize,
    },
    /// Inspect or extract/deswizzle TTPF (RDS5/ETPF) textures to standard PC DDS (DX10).
    ConvertTtpf {
        path: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 12)]
        limit: usize,
    },
    /// Inspect & translate SGD5 (`shaders.rpf`) or ACCC/FSPX (`amd_fidelityfx_upscaler_xbox.dll`) shaders to PC DXIL.
    ConvertShaders {
        path: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 16)]
        limit: usize,
    },
    /// Scan all SGD5 & ACCC/FSPX shaders, translate to SM 6.6 DXIL, deduplicate, and write DXPK v1 pack + manifest.
    PackShaders {
        #[arg(long, default_value = r"S:\gta\Gta6fordevelopersacces")]
        root: PathBuf,
        /// Optional explicit shader source files (defaults to shaders.rpf + amd_fidelityfx_upscaler_xbox.dll under --root).
        #[arg(long = "input")]
        inputs: Vec<PathBuf>,
        #[arg(long, default_value = r"V:\LUCIAS_PROJECT_Cache\shaders_pc.dxilpack")]
        out_pack: PathBuf,
        #[arg(long, default_value = r"V:\LUCIAS_PROJECT_Cache\shaders_manifest.json")]
        out_manifest: PathBuf,
        #[arg(long, default_value_t = 12)]
        threads: usize,
    },
    /// Resumable multi-threaded batch converter from `.ttpf` archives to PC DDS (or `.dds.zst`) files.
    ConvertTtpfBatch {
        #[arg(long, default_value = r"S:\gta\Gta6fordevelopersacces\data\ttdb")]
        input: PathBuf,
        #[arg(long, default_value = r"V:\LUCIAS_PROJECT_Cache\ttdb_pc")]
        out: PathBuf,
        #[arg(long)]
        max_mb: Option<u64>,
        #[arg(long)]
        resume: bool,
        #[arg(long, default_value_t = 8)]
        threads: usize,
        #[arg(long, value_enum, default_value_t = CompressArg::Zstd)]
        compress: CompressArg,
        #[arg(long, default_value_t = 3)]
        zstd_level: i32,
        #[arg(long, default_value_t = 15)]
        min_free_gb: u64,
    },
    /// Inspect Bink2 (`KB2*`), ADAT audio banks, and RIFF/WEM/XMA2 headers read-only.
    InspectMedia {
        path: PathBuf,
        #[arg(long, default_value_t = 32)]
        max_mb: usize,
        #[arg(long, default_value_t = 10)]
        samples: usize,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run the full read-only pipeline + sample conversions + dual-SSD (E: + V:) layout report.
    RunPipeline {
        #[arg(long, default_value = r"S:\gta\Gta6fordevelopersacces")]
        root: PathBuf,
        #[arg(long, default_value = r"c:\pulpit\xx\gta6_native_tools\samples_out")]
        out: PathBuf,
        #[arg(long, default_value_t = 12)]
        tex_limit: usize,
        #[arg(long, default_value_t = 16)]
        shader_limit: usize,
    },
}

#[derive(Serialize)]
struct PipelineReport {
    project: String,
    build_inventory: rpf9::BuildInventory,
    rpf_scans: Vec<rpf9::Rpf9InventoryReport>,
    ttpf_reports: Vec<ttpf::TtpfInspectReport>,
    ttpf_exports: Vec<ttpf::TtpfExportSummary>,
    shader_exports: Vec<shader::ShaderBatchSummary>,
    media_inspections: Vec<media::MediaInspectionSummary>,
    dual_ssd_layout: layout::DualSsdLayoutPlan,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Inventory {
            root,
            scan_small,
            out,
        } => {
            let inv = rpf9::inventory_build_directory(&root)?;
            let mut rpf_scans = Vec::new();
            if scan_small {
                for rel in [
                    "common.rpf",
                    "script.rpf",
                    "textures.rpf",
                    "shaders.rpf",
                    "anim.rpf",
                    "navmeshes.rpf",
                    "packs.rpf",
                ] {
                    let p = root.join(rel);
                    if p.is_file() {
                        rpf_scans.push(rpf9::inventory_rpf9_file(&p, Some(16 * 1024 * 1024), 8)?);
                    }
                }
            }
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "project": gta6_native_tools::dxpk::PROJECT_NAME,
                "inventory": inv,
                "rpf_scans": rpf_scans,
            }))?;
            if let Some(out_path) = out {
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, &json)?;
                println!("Wrote inventory to {}", out_path.display());
            } else {
                println!("{json}");
            }
        }
        Command::InspectRpf {
            path,
            max_mb,
            samples,
        } => {
            let rep = rpf9::inventory_rpf9_file(&path, Some(max_mb * 1024 * 1024), samples)?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        Command::ConvertTtpf { path, out, limit } => {
            let summary = ttpf::convert_ttpf_samples(&path, &out, limit)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::ConvertShaders { path, out, limit } => {
            let summary = shader::convert_shaders_from_file(&path, &out, limit)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::PackShaders {
            root,
            inputs,
            out_pack,
            out_manifest,
            threads,
        } => {
            let sources = if inputs.is_empty() {
                let mut s = vec![
                    root.join("shaders.rpf"),
                    root.join("amd_fidelityfx_upscaler_xbox.dll"),
                ];
                let exe = root.join("game_scarlett_master.exe");
                if exe.exists() {
                    s.push(exe);
                }
                s
            } else {
                inputs
            };
            eprintln!("[LUCIAS PROJECT] Packing SGD5 + ACCC/FSPX shaders -> {}", out_pack.display());
            let manifest =
                shader::pack_shaders_to_dxpk(&sources, &out_pack, &out_manifest, threads)?;
            // Print concise summary without dumping all 26k entries to stdout.
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": manifest.project,
                    "dxpk_version": manifest.dxpk_version,
                    "dxilpack_path": manifest.dxilpack_path,
                    "manifest_path": out_manifest,
                    "total_input_shaders": manifest.total_input_shaders,
                    "translated_ok": manifest.translated_ok,
                    "unique_packed": manifest.unique_packed,
                    "unique_dxil_blobs": manifest.unique_dxil_blobs,
                    "deduplicated": manifest.deduplicated,
                    "failed": manifest.failed,
                    "total_input_dxbc_bytes": manifest.total_input_dxbc_bytes,
                    "total_dxil_bytes": manifest.total_dxil_bytes,
                    "unique_dxil_bytes": manifest.unique_dxil_bytes,
                    "file_bytes": manifest.file_bytes,
                    "stage_counts": manifest.stage_counts,
                    "source_kind_counts": manifest.source_kind_counts,
                    "failure_reasons": manifest.failure_reasons,
                }))?
            );
        }
        Command::ConvertTtpfBatch {
            input,
            out,
            max_mb,
            resume,
            threads,
            compress,
            zstd_level,
            min_free_gb,
        } => {
            eprintln!("[LUCIAS PROJECT] Converting TTPF batch ({}) -> {}", input.display(), out.display());
            let report = ttpf::convert_ttpf_batch_with_options(&ttpf::TtpfBatchOptions {
                input_root: input,
                out_dir: out,
                max_mb,
                resume,
                threads,
                compression: compress.into(),
                zstd_level,
                min_free_gb: (min_free_gb > 0).then_some(min_free_gb),
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": report.project,
                    "input_root": report.input_root,
                    "out_dir": report.out_dir,
                    "resume_enabled": report.resume_enabled,
                    "compression": report.compression,
                    "zstd_level": report.zstd_level,
                    "max_mb_limit": report.max_mb_limit,
                    "min_free_gb": report.min_free_gb,
                    "stopped_for_min_free_gb": report.stopped_for_min_free_gb,
                    "stop_reason": report.stop_reason,
                    "threads": report.threads,
                    "archives_discovered": report.archives_discovered,
                    "archives_skipped_resumed": report.archives_skipped_resumed,
                    "archives_processed_this_run": report.archives_processed_this_run,
                    "archives_completed_total": report.archives_completed_total,
                    "total_source_bytes_processed_this_run": report.total_source_bytes_processed_this_run,
                    "total_textures_exported_this_run": report.total_textures_exported_this_run,
                    "total_textures_skipped_existing_this_run": report.total_textures_skipped_existing_this_run,
                    "total_textures_failed_this_run": report.total_textures_failed_this_run,
                    "total_output_dds_bytes_this_run": report.total_output_dds_bytes_this_run,
                    "total_output_written_bytes_this_run": report.total_output_written_bytes_this_run,
                    "disk_free_bytes_after": report.disk_free_bytes_after,
                }))?
            );
        }
        Command::InspectMedia {
            path,
            max_mb,
            samples,
            out,
        } => {
            let summary = media::inspect_media_file(&path, max_mb, samples)?;
            let json = serde_json::to_string_pretty(&summary)?;
            if let Some(p) = out {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&p, &json)?;
            }
            println!("{json}");
        }
        Command::RunPipeline {
            root,
            out,
            tex_limit,
            shader_limit,
        } => {
            std::fs::create_dir_all(&out)?;
            let report = run_full_pipeline(&root, &out, tex_limit, shader_limit)?;
            let out_json = out.join("pipeline_report.json");
            std::fs::write(&out_json, serde_json::to_string_pretty(&report)?)?;
            println!(
                "[LUCIAS PROJECT] Pipeline complete. Report: {} | RPFs: {} ({:.2} GiB) | TTPFs: {} ({:.2} GiB) | Dual-SSD fits: {}",
                out_json.display(),
                report.build_inventory.rpf_count,
                report.build_inventory.rpf_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                report.build_inventory.ttpf_count,
                report.build_inventory.ttpf_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                report.dual_ssd_layout.fits_within_dual_ssd
            );
        }
    }
    Ok(())
}

fn run_full_pipeline(
    root: &Path,
    out: &Path,
    tex_limit: usize,
    shader_limit: usize,
) -> Result<PipelineReport> {
    let build_inventory = rpf9::inventory_build_directory(root)?;

    // 1. Bounded read-only scan of smaller & representative RPF9 archives (never touching E:\gta_mirror\levels.rpf).
    let mut rpf_scans = Vec::new();
    let mut total_comp = 0u64;
    let mut total_decomp = 0u64;
    for (rel, max_mb) in [
        ("common.rpf", 16u64),
        ("script.rpf", 16),
        ("textures.rpf", 16),
        ("shaders.rpf", 16),
        ("anim.rpf", 16),
        ("navmeshes.rpf", 32),
        ("packs.rpf", 16),
    ] {
        let p = root.join(rel);
        if p.is_file() {
            let rep = rpf9::inventory_rpf9_file(&p, Some(max_mb * 1024 * 1024), 6)?;
            total_comp += rep.total_compressed_bytes;
            total_decomp += rep.total_decompressed_bytes;
            rpf_scans.push(rep);
        }
    }
    let zlib_ratio = if total_comp > 0 {
        Some(total_decomp as f64 / total_comp as f64)
    } else {
        None
    };

    // 2. TTPF inspection & sample BCPack/Zlib -> DDS conversions.
    let mut ttpf_reports = Vec::new();
    let mut ttpf_exports = Vec::new();
    for (rel, subdir) in [
        (r"pack\core_restofworld001\data\ttdb\ui\ttdb_ui.ttpf", "dds_ui_small"),
        (r"data\ttdb\ui\platform.ttpf", "dds_platform"),
        (r"pack\core_restofworld\data\ttdb\vfx\ttdb_vfx.ttpf", "dds_vfx_bcpack"),
    ] {
        let p = root.join(rel);
        if p.is_file() {
            let arc = ttpf::TtpfArchive::open(&p)?;
            ttpf_reports.push(arc.inspect_report(&p));
            drop(arc);
            ttpf_exports.push(ttpf::convert_ttpf_samples(
                &p,
                &out.join(subdir),
                tex_limit,
            )?);
        }
    }

    // Aggregate TTPF export summary for ratio estimation.
    let mut agg_ttpf = ttpf::TtpfExportSummary {
        source_archive: "aggregate".into(),
        total_entries_in_archive: ttpf_exports.iter().map(|s| s.total_entries_in_archive).sum(),
        exported_count: ttpf_exports.iter().map(|s| s.exported_count).sum(),
        failed_count: ttpf_exports.iter().map(|s| s.failed_count).sum(),
        total_input_compressed_bytes: ttpf_exports.iter().map(|s| s.total_input_compressed_bytes).sum(),
        total_input_virtual_bytes: ttpf_exports.iter().map(|s| s.total_input_virtual_bytes).sum(),
        total_output_dds_bytes: ttpf_exports.iter().map(|s| s.total_output_dds_bytes).sum(),
        items: Vec::new(),
    };
    if agg_ttpf.exported_count == 0 {
        agg_ttpf.total_input_compressed_bytes = 0;
    }

    // 3. SGD5 (`shaders.rpf`) + ACCC/FSPX (`amd_fidelityfx_upscaler_xbox.dll`) shader translations.
    let mut shader_exports = Vec::new();
    for (rel, subdir) in [
        ("shaders.rpf", "shaders_sgd5"),
        ("amd_fidelityfx_upscaler_xbox.dll", "shaders_accc"),
    ] {
        let p = root.join(rel);
        if p.is_file() {
            shader_exports.push(shader::convert_shaders_from_file(
                &p,
                &out.join(subdir),
                shader_limit,
            )?);
        }
    }

    let agg_shader = shader::ShaderBatchSummary {
        source_file: "aggregate".into(),
        total_candidates: shader_exports.iter().map(|s| s.total_candidates).sum(),
        processed: shader_exports.iter().map(|s| s.processed).sum(),
        translated_ok: shader_exports.iter().map(|s| s.translated_ok).sum(),
        failed: shader_exports.iter().map(|s| s.failed).sum(),
        stage_counts: Default::default(),
        total_input_dxbc_bytes: shader_exports.iter().map(|s| s.total_input_dxbc_bytes).sum(),
        total_output_dxil_bytes: shader_exports.iter().map(|s| s.total_output_dxil_bytes).sum(),
        records: Vec::new(),
    };

    // 4. Media header inspection (movies.rpf full page-jump scan + audio.rpf bounded 32MB scan).
    let mut media_inspections = Vec::new();
    for (rel, mb) in [("movies.rpf", 0usize), ("audio.rpf", 32usize)] {
        let p = root.join(rel);
        if p.is_file() {
            media_inspections.push(media::inspect_media_file(&p, mb, 10)?);
        }
    }

    // 5. Dual-SSD layout estimation.
    let dual_ssd_layout = layout::estimate_dual_ssd_layout(
        &build_inventory,
        Some(&agg_ttpf),
        Some(&agg_shader),
        zlib_ratio,
        None,
    )?;

    Ok(PipelineReport {
        project: gta6_native_tools::dxpk::PROJECT_NAME.to_string(),
        build_inventory,
        rpf_scans,
        ttpf_reports,
        ttpf_exports,
        shader_exports,
        media_inspections,
        dual_ssd_layout,
    })
}
