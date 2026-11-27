//! Cross-DLL process-local shared telemetry and live JSON writer for `LUCIAS PROJECT`.
//!
//! Backed by a process-scoped named Win32 file mapping (`Local\LuciasTelemetry_v1_<pid>`)
//! so all 14 shim DLLs (each statically linking `shim_common`) share a single telemetry block,
//! shader error counters, and warning feed with zero circular DLL dependencies.

use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

static TEST_JSON_OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_ALL_ACCESS, MapViewOfFile, PAGE_READWRITE,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryPerformanceCounter(lp_performance_count: *mut i64) -> i32;
    fn QueryPerformanceFrequency(lp_frequency: *mut i64) -> i32;
}

pub const PROJECT_NAME: &str = "LUCIAS PROJECT";
pub const HARDWARE_BANNER: &str = "RTX 3070 8GB | R9 5900X | 16GB DDR4";
pub const DEFAULT_VRAM_BUDGET_MIB: u32 = 7200;
pub const DEFAULT_RAM_BUDGET_MIB: u32 = 12288;
pub const DEFAULT_TARGET_WIDTH: u32 = 1920;
pub const DEFAULT_TARGET_HEIGHT: u32 = 1080;
pub const CONSOLE_MODE_SERIES_S: u32 = 0x60;
pub const CONSOLE_MODE_SERIES_X: u32 = 0x64;

/// Returns the active Xbox Scarlett console mode (`0x60` = Series S / 1080p VRAM-saving default,
/// `0x64` = Series X / 4K) from `LUCIAS_CONSOLE_MODE`.
pub fn configured_console_mode() -> (u32, &'static str) {
    if let Ok(val) = std::env::var("LUCIAS_CONSOLE_MODE") {
        let lower = val.trim().to_ascii_lowercase();
        if matches!(lower.as_str(), "seriesx" | "series_x" | "4k" | "0x64" | "100") {
            return (CONSOLE_MODE_SERIES_X, "SeriesX-4K");
        }
    }
    (CONSOLE_MODE_SERIES_S, "SeriesS-1080p")
}

pub fn console_profile_name(mode: u32) -> &'static str {
    if mode == CONSOLE_MODE_SERIES_X {
        "SeriesX-4K"
    } else {
        "SeriesS-1080p"
    }
}

/// Returns the active display/render resolution target from `LUCIAS_RES` (e.g. `1920x1080`),
/// defaulting to 1080p (`1920x1080`) for the 8GB RTX 3070 VRAM-saving profile.
pub fn configured_resolution() -> (u32, u32) {
    if let Ok(val) = std::env::var("LUCIAS_RES") {
        let trimmed = val.trim();
        if let Some((w_s, h_s)) = trimmed.split_once(['x', 'X']) {
            if let (Ok(w), Ok(h)) = (w_s.trim().parse::<u32>(), h_s.trim().parse::<u32>()) {
                if w >= 640 && h >= 480 {
                    return (w, h);
                }
            }
        }
    }
    (DEFAULT_TARGET_WIDTH, DEFAULT_TARGET_HEIGHT)
}
pub const TELEMETRY_MAGIC: u32 = 0x4C55_4349; // "LUCI"
pub const TELEMETRY_VERSION: u32 = 1;
pub const WARN_RING_LEN: usize = 8;
pub const WARN_LINE_BYTES: usize = 128;

#[repr(C)]
pub struct SharedTelemetry {
    pub magic: u32,
    pub version: u32,
    pub visible: AtomicU32,
    pub target_hwnd: AtomicU64,
    pub frame_count: AtomicU64,
    pub fps_x100: AtomicU32,
    pub frame_time_us: AtomicU32,
    pub cpu_time_us: AtomicU32,
    pub gpu_time_us: AtomicU32,
    pub vram_used_mib: AtomicU32,
    pub vram_budget_mib: AtomicU32,
    pub ram_commit_mib: AtomicU32,
    pub ram_budget_mib: AtomicU32,
    pub dxpk_hits: AtomicU64,
    pub dxpk_misses: AtomicU64,
    pub shaders_compiled: AtomicU64,
    pub shader_errors: AtomicU64,
    pub last_failed_shader_hash: AtomicU64,
    pub last_failed_stage: [AtomicU8; 16],
    pub last_frame_qpc: AtomicU64,
    pub last_submit_qpc: AtomicU64,
    pub qpc_freq: AtomicU64,
    pub warn_seq: AtomicU32,
    pub warn_lock: AtomicU32,
    pub warnings: [[u8; WARN_LINE_BYTES]; WARN_RING_LEN],
    pub last_json_write_ms: AtomicU64,
    pub vram_warn_sent: AtomicU32,
    pub ram_warn_sent: AtomicU32,
    pub console_mode: AtomicU32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    pub visible: bool,
    pub target_hwnd: usize,
    pub console_profile: String,
    pub frame_count: u64,
    pub fps_x100: u32,
    pub frame_time_us: u32,
    pub cpu_time_us: u32,
    pub gpu_time_us: u32,
    pub vram_used_mib: u32,
    pub vram_budget_mib: u32,
    pub ram_commit_mib: u32,
    pub ram_budget_mib: u32,
    pub dxpk_hits: u64,
    pub dxpk_misses: u64,
    pub shaders_compiled: u64,
    pub shader_errors: u64,
    pub last_failed_shader_hash: u64,
    pub last_failed_stage: String,
    pub warnings: Vec<String>,
}

static SHARED_PTR: OnceLock<usize> = OnceLock::new();

#[inline]
pub fn qpc_now() -> u64 {
    let mut c = 0i64;
    unsafe {
        QueryPerformanceCounter(&mut c);
    }
    c.max(0) as u64
}

#[inline]
pub fn qpc_freq() -> u64 {
    let mut f = 0i64;
    unsafe {
        QueryPerformanceFrequency(&mut f);
    }
    f.max(1) as u64
}

fn init_shared_struct(ptr: *mut SharedTelemetry) {
    unsafe {
        std::ptr::write_bytes(ptr, 0, 1);
        (*ptr).magic = TELEMETRY_MAGIC;
        (*ptr).version = TELEMETRY_VERSION;
        (*ptr).visible.store(1, Ordering::Relaxed);
        (*ptr).vram_budget_mib.store(DEFAULT_VRAM_BUDGET_MIB, Ordering::Relaxed);
        (*ptr).ram_budget_mib.store(DEFAULT_RAM_BUDGET_MIB, Ordering::Relaxed);
        (*ptr).qpc_freq.store(qpc_freq(), Ordering::Relaxed);
        (*ptr)
            .console_mode
            .store(configured_console_mode().0, Ordering::Relaxed);
    }
}

pub fn shared() -> &'static SharedTelemetry {
    let addr = *SHARED_PTR.get_or_init(|| unsafe {
        let pid = GetCurrentProcessId();
        let name: Vec<u16> = format!("Local\\LuciasTelemetry_v1_{pid}\0")
            .encode_utf16()
            .collect();
        let h_map = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            size_of::<SharedTelemetry>() as u32,
            name.as_ptr(),
        );
        if !h_map.is_null() {
            let already_exists = windows_sys::Win32::Foundation::GetLastError()
                == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
            let view = MapViewOfFile(
                h_map,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                size_of::<SharedTelemetry>(),
            );
            if !view.Value.is_null() {
                let ptr = view.Value.cast::<SharedTelemetry>();
                // Leak h_map intentionally for process lifetime so mapping remains alive
                // even if an auxiliary DLL unloads.
                if !already_exists || (*ptr).magic != TELEMETRY_MAGIC {
                    init_shared_struct(ptr);
                }
                return ptr as usize;
            }
            CloseHandle(h_map);
        }
        // Fallback: heap allocation if CreateFileMappingW is restricted.
        let layout = std::alloc::Layout::new::<SharedTelemetry>();
        let ptr = std::alloc::alloc_zeroed(layout).cast::<SharedTelemetry>();
        init_shared_struct(ptr);
        ptr as usize
    });
    unsafe { &*(addr as *const SharedTelemetry) }
}

pub fn use_temp_telemetry_json_for_tests() {
    let cell = TEST_JSON_OVERRIDE.get_or_init(|| Mutex::new(None));
    let mut g = cell.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        let pid = unsafe { GetCurrentProcessId() };
        *g = Some(std::env::temp_dir().join(format!("lucias_test_telemetry_{pid}.json")));
    }
}

pub fn reset_for_tests() {
    use_temp_telemetry_json_for_tests();
    let s = shared();
    let ptr = (s as *const SharedTelemetry).cast_mut();
    init_shared_struct(ptr);
}

#[inline]
pub fn is_overlay_visible() -> bool {
    shared().visible.load(Ordering::Relaxed) != 0
}

#[inline]
pub fn set_overlay_visible(visible: bool) {
    shared()
        .visible
        .store(u32::from(visible), Ordering::Release);
}

#[inline]
pub fn toggle_overlay_visible() -> bool {
    let s = shared();
    loop {
        let cur = s.visible.load(Ordering::Acquire);
        let next = if cur == 0 { 1 } else { 0 };
        if s.visible
            .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return next != 0;
        }
    }
}

#[inline]
pub fn set_target_hwnd(hwnd: usize) {
    if hwnd != 0 {
        shared().target_hwnd.store(hwnd as u64, Ordering::Relaxed);
    }
}

#[inline]
pub fn target_hwnd() -> usize {
    shared().target_hwnd.load(Ordering::Relaxed) as usize
}

#[inline]
pub fn record_console_mode(mode: u32) {
    shared().console_mode.store(mode, Ordering::Relaxed);
}

/// Pushes a structured warning/error string into the fixed 8-entry HUD ring buffer.
pub fn record_warning(module: &str, msg: &str) {
    let s = shared();
    let line = if module.is_empty() {
        msg.to_string()
    } else {
        format!("[{module}] {msg}")
    };
    let mut buf = [0u8; WARN_LINE_BYTES];
    let bytes = line.as_bytes();
    let copy_len = bytes.len().min(WARN_LINE_BYTES - 1);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

    // Bounded spin so a wedged caller never stalls the render thread.
    let mut locked = false;
    for _ in 0..2048 {
        if s.warn_lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            locked = true;
            break;
        }
        std::hint::spin_loop();
    }
    if !locked {
        return;
    }

    let seq = s.warn_seq.load(Ordering::Relaxed);
    let slot = (seq as usize) % WARN_RING_LEN;
    let ring_ptr = s.warnings.as_ptr().cast_mut();
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), (*ring_ptr.add(slot)).as_mut_ptr(), WARN_LINE_BYTES);
    }
    s.warn_seq.store(seq.wrapping_add(1), Ordering::Release);
    s.warn_lock.store(0, Ordering::Release);
}

#[inline]
pub fn record_dxpk_hit() {
    shared().dxpk_hits.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_dxpk_miss(hash: u64, stage: &str) {
    let s = shared();
    s.dxpk_misses.fetch_add(1, Ordering::Relaxed);
    record_warning(
        "dxpk",
        &format!("miss hash={hash:#018x} stage={stage}"),
    );
}

#[inline]
pub fn record_shader_compiled() {
    shared().shaders_compiled.fetch_add(1, Ordering::Relaxed);
}

pub fn record_shader_error(hash: u64, stage: &str, hr: i32) {
    let s = shared();
    s.shader_errors.fetch_add(1, Ordering::Relaxed);
    s.last_failed_shader_hash.store(hash, Ordering::Relaxed);
    let bytes = stage.as_bytes();
    for (i, slot) in s.last_failed_stage.iter().enumerate() {
        let b = if i < bytes.len() && i + 1 < 16 {
            bytes[i]
        } else {
            0
        };
        slot.store(b, Ordering::Relaxed);
    }
    record_warning(
        "shader",
        &format!("ERR {stage} hash={hash:#018x} hr={:#010x}", hr as u32),
    );
}

#[inline]
pub fn record_submit_start() {
    shared().last_submit_qpc.store(qpc_now(), Ordering::Relaxed);
}

#[inline]
pub fn record_gpu_duration_us(gpu_us: u32) {
    shared().gpu_time_us.store(gpu_us, Ordering::Relaxed);
}

pub fn set_vram_usage_mib(used_mib: u32, budget_mib: u32) {
    let s = shared();
    s.vram_used_mib.store(used_mib, Ordering::Relaxed);
    let effective_budget = if budget_mib > 0 {
        budget_mib.min(DEFAULT_VRAM_BUDGET_MIB)
    } else {
        DEFAULT_VRAM_BUDGET_MIB
    };
    s.vram_budget_mib.store(effective_budget, Ordering::Relaxed);
    if used_mib >= effective_budget
        && s.vram_warn_sent
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        record_warning(
            "vram",
            &format!("VRAM {used_mib}/{effective_budget} MiB threshold"),
        );
    } else if used_mib + 256 < effective_budget {
        s.vram_warn_sent.store(0, Ordering::Relaxed);
    }
}

pub fn sample_process_ram_mib() -> u32 {
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };
    let mib = if ok != 0 {
        (pmc.PagefileUsage / (1024 * 1024)) as u32
    } else {
        0
    };
    let s = shared();
    s.ram_commit_mib.store(mib, Ordering::Relaxed);
    let budget = s.ram_budget_mib.load(Ordering::Relaxed);
    if budget > 0
        && mib >= budget
        && s.ram_warn_sent
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        record_warning("ram", &format!("RAM commit {mib}/{budget} MiB threshold"));
    } else if mib + 512 < budget {
        s.ram_warn_sent.store(0, Ordering::Relaxed);
    }
    mib
}

/// Records a completed frame / Present event, updating FPS, frame time, CPU time, and RAM commit.
pub fn record_frame_present() {
    let s = shared();
    let now = qpc_now();
    let mut freq = s.qpc_freq.load(Ordering::Relaxed);
    if freq == 0 {
        freq = qpc_freq();
        s.qpc_freq.store(freq, Ordering::Relaxed);
    }

    let prev = s.last_frame_qpc.swap(now, Ordering::Relaxed);
    let frame_num = s.frame_count.fetch_add(1, Ordering::Relaxed) + 1;
    if prev > 0 && now > prev {
        let delta_ticks = now - prev;
        let frame_us = ((delta_ticks as u128 * 1_000_000) / freq as u128).min(5_000_000) as u32;
        if frame_us > 0 {
            let old_us = s.frame_time_us.load(Ordering::Relaxed);
            // Light EMA smoothing for readable HUD cadence while staying responsive.
            let smooth_us = if old_us == 0 {
                frame_us
            } else {
                (old_us * 3 + frame_us) / 4
            };
            s.frame_time_us.store(smooth_us, Ordering::Relaxed);
            let fps_x100 = (100_000_000u64 / u64::from(smooth_us.max(1))) as u32;
            s.fps_x100.store(fps_x100, Ordering::Relaxed);

            let last_sub = s.last_submit_qpc.load(Ordering::Relaxed);
            let cpu_us = if last_sub >= prev && last_sub <= now {
                ((last_sub - prev) as u128 * 1_000_000 / freq as u128).min(frame_us as u128) as u32
            } else {
                frame_us
            };
            s.cpu_time_us.store(cpu_us, Ordering::Relaxed);
        }
    }

    if frame_num == 1 || frame_num.is_multiple_of(8) {
        sample_process_ram_mib();
    }
}

pub fn snapshot() -> TelemetrySnapshot {
    let s = shared();
    let mut stage_bytes = Vec::with_capacity(16);
    for slot in &s.last_failed_stage {
        let b = slot.load(Ordering::Relaxed);
        if b == 0 {
            break;
        }
        stage_bytes.push(b);
    }
    let last_failed_stage = String::from_utf8_lossy(&stage_bytes).into_owned();

    let mut warnings = Vec::new();
    let mut locked = false;
    for _ in 0..1024 {
        if s.warn_lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            locked = true;
            break;
        }
        std::hint::spin_loop();
    }
    if locked {
        let seq = s.warn_seq.load(Ordering::Acquire);
        let count = (seq as usize).min(WARN_RING_LEN);
        let start = seq.saturating_sub(count as u32) as usize;
        for i in 0..count {
            let slot = (start + i) % WARN_RING_LEN;
            let raw = &s.warnings[slot];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(WARN_LINE_BYTES);
            if end > 0 {
                warnings.push(String::from_utf8_lossy(&raw[..end]).into_owned());
            }
        }
        s.warn_lock.store(0, Ordering::Release);
    }

    let mode_val = s.console_mode.load(Ordering::Relaxed);
    let console_profile = if mode_val == 0 {
        configured_console_mode().1.to_string()
    } else {
        console_profile_name(mode_val).to_string()
    };

    TelemetrySnapshot {
        visible: s.visible.load(Ordering::Relaxed) != 0,
        target_hwnd: s.target_hwnd.load(Ordering::Relaxed) as usize,
        console_profile,
        frame_count: s.frame_count.load(Ordering::Relaxed),
        fps_x100: s.fps_x100.load(Ordering::Relaxed),
        frame_time_us: s.frame_time_us.load(Ordering::Relaxed),
        cpu_time_us: s.cpu_time_us.load(Ordering::Relaxed),
        gpu_time_us: s.gpu_time_us.load(Ordering::Relaxed),
        vram_used_mib: s.vram_used_mib.load(Ordering::Relaxed),
        vram_budget_mib: s.vram_budget_mib.load(Ordering::Relaxed),
        ram_commit_mib: s.ram_commit_mib.load(Ordering::Relaxed),
        ram_budget_mib: s.ram_budget_mib.load(Ordering::Relaxed),
        dxpk_hits: s.dxpk_hits.load(Ordering::Relaxed),
        dxpk_misses: s.dxpk_misses.load(Ordering::Relaxed),
        shaders_compiled: s.shaders_compiled.load(Ordering::Relaxed),
        shader_errors: s.shader_errors.load(Ordering::Relaxed),
        last_failed_shader_hash: s.last_failed_shader_hash.load(Ordering::Relaxed),
        last_failed_stage,
        warnings,
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

pub fn format_json(snap: &TelemetrySnapshot) -> String {
    let fps = f64::from(snap.fps_x100) / 100.0;
    let frame_ms = f64::from(snap.frame_time_us) / 1000.0;
    let cpu_ms = f64::from(snap.cpu_time_us) / 1000.0;
    let gpu_ms = f64::from(snap.gpu_time_us) / 1000.0;
    let warnings_json: Vec<String> = snap
        .warnings
        .iter()
        .map(|w| format!("\"{}\"", json_escape(w)))
        .collect();
    let (res_w, res_h) = configured_resolution();
    format!(
        concat!(
            "{{\n",
            "  \"project\": \"{project}\",\n",
            "  \"hardware\": \"{hw}\",\n",
            "  \"profile\": \"1080p-vram-save\",\n",
            "  \"console_profile\": \"{cp}\",\n",
            "  \"target_resolution\": \"{rw}x{rh}\",\n",
            "  \"overlay_visible\": {vis},\n",
            "  \"frame_count\": {fc},\n",
            "  \"fps\": {fps:.2},\n",
            "  \"frame_time_ms\": {fms:.3},\n",
            "  \"cpu_ms\": {cms:.3},\n",
            "  \"gpu_ms\": {gms:.3},\n",
            "  \"vram_used_mib\": {vu},\n",
            "  \"vram_budget_mib\": {vb},\n",
            "  \"ram_commit_mib\": {ru},\n",
            "  \"ram_budget_mib\": {rb},\n",
            "  \"dxpk_hits\": {dh},\n",
            "  \"dxpk_misses\": {dm},\n",
            "  \"shaders_compiled\": {sc},\n",
            "  \"shader_errors\": {se},\n",
            "  \"last_failed_shader_hash\": \"{sfh:#018x}\",\n",
            "  \"last_failed_stage\": \"{sfs}\",\n",
            "  \"warnings\": [{warns}]\n",
            "}}\n"
        ),
        project = PROJECT_NAME,
        hw = HARDWARE_BANNER,
        cp = json_escape(&snap.console_profile),
        rw = res_w,
        rh = res_h,
        vis = snap.visible,
        fc = snap.frame_count,
        fps = fps,
        fms = frame_ms,
        cms = cpu_ms,
        gms = gpu_ms,
        vu = snap.vram_used_mib,
        vb = snap.vram_budget_mib,
        ru = snap.ram_commit_mib,
        rb = snap.ram_budget_mib,
        dh = snap.dxpk_hits,
        dm = snap.dxpk_misses,
        sc = snap.shaders_compiled,
        se = snap.shader_errors,
        sfh = snap.last_failed_shader_hash,
        sfs = json_escape(&snap.last_failed_stage),
        warns = warnings_json.join(", "),
    )
}

pub fn default_telemetry_json_path() -> PathBuf {
    if let Some(cell) = TEST_JSON_OVERRIDE.get() {
        if let Some(ref p) = *cell.lock().unwrap_or_else(|e| e.into_inner()) {
            return p.clone();
        }
    }
    if let Ok(p) = std::env::var("LUCIAS_TELEMETRY_JSON") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    for key in ["LUCIAS_SHIM_LOG", "GTA6_SHIM_LOG"] {
        if let Ok(log_p) = std::env::var(key) {
            let t = log_p.trim();
            if !t.is_empty()
                && t != "1"
                && t != "0"
                && !t.eq_ignore_ascii_case("true")
                && !t.eq_ignore_ascii_case("false")
            {
                if let Some(parent) = Path::new(t).parent() {
                    return parent.join("telemetry_latest.json");
                }
            }
        }
    }
    let mut exe_buf = [0u16; 512];
    let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), exe_buf.as_mut_ptr(), exe_buf.len() as u32) };
    if n > 0 {
        let exe_s = String::from_utf16_lossy(&exe_buf[..n as usize]);
        let p = PathBuf::from(exe_s);
        if let Some(dir) = p.parent() {
            let logs = dir.join("logs");
            if logs.exists() {
                return logs.join("telemetry_latest.json");
            }
        }
    }
    PathBuf::from(r"E:\LUCIAS_PROJECT\logs\telemetry_latest.json")
}

pub fn write_telemetry_json_to(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = format_json(&snapshot());
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(json.as_bytes())
}

pub fn flush_telemetry_json_if_due(force: bool) {
    let s = shared();
    let now_ticks = qpc_now();
    let freq = s.qpc_freq.load(Ordering::Relaxed).max(1);
    let now_ms = ((now_ticks as u128 * 1000) / freq as u128) as u64;
    let last = s.last_json_write_ms.load(Ordering::Relaxed);
    if !force && now_ms.saturating_sub(last) < 250 {
        return;
    }
    if !force
        && s.last_json_write_ms
            .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    if force {
        s.last_json_write_ms.store(now_ms, Ordering::Relaxed);
    }
    let path = default_telemetry_json_path();
    if force || path.parent().is_some_and(Path::exists) {
        let _ = write_telemetry_json_to(&path);
    }
}

/// Pure pointer wrapper to prevent dead-code warnings when unused from FFI tests.
pub fn shared_addr() -> usize {
    (shared() as *const SharedTelemetry) as usize
}

pub fn unused_cvoid_marker(_p: *const c_void) {}
