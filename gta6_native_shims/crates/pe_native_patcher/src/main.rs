use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pe_native_patcher::{analyze_file, patch_file, verify_files, PatchConfig};

#[derive(Parser)]
#[command(
    name = "pe_native_patcher",
    about = "LUCIAS PROJECT — Non-destructive PE32+ Xbox-to-PC IAT/subsystem/VFS patcher"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a PE32+ image and print imports, sections, and console DLL stats as JSON.
    Analyze {
        #[arg(long)]
        input: PathBuf,
    },
    /// Patch (or dry-run validate) a PE32+ image without modifying the source file.
    Patch {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        keep_gameinput: bool,
        #[arg(long)]
        hook_vfs: bool,
    },
    /// Verify a patched PE32+ image against the original source binary.
    Verify {
        #[arg(long)]
        original: PathBuf,
        #[arg(long)]
        patched: PathBuf,
        #[arg(long)]
        keep_gameinput: bool,
        #[arg(long)]
        hook_vfs: bool,
    },
}

fn build_config(keep_gameinput: bool, hook_vfs: bool) -> PatchConfig {
    let mut cfg = PatchConfig::default();
    if keep_gameinput {
        cfg.dll_remap.remove("gameinput.dll");
    }
    cfg.hook_vfs = hook_vfs;
    cfg
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Analyze { input } => {
            let analysis = analyze_file(&input)?;
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
        Command::Patch {
            input,
            output,
            dry_run,
            keep_gameinput,
            hook_vfs,
        } => {
            if !dry_run && output.is_none() {
                return Err("specify either --output <path> or --dry-run".into());
            }
            let cfg = build_config(keep_gameinput, hook_vfs);
            let out_ref = if dry_run { None } else { output.as_deref() };
            let report = patch_file(&input, out_ref, &cfg)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Verify {
            original,
            patched,
            keep_gameinput,
            hook_vfs,
        } => {
            let cfg = build_config(keep_gameinput, hook_vfs);
            let analysis = verify_files(&original, &patched, &cfg)?;
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
    }
    Ok(())
}
