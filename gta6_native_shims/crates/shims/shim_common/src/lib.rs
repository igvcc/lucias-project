#![allow(non_snake_case)]

use std::collections::HashMap;
pub mod telemetry;

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;

pub type HRESULT = i32;
pub type BOOL = i32;

pub const S_OK: HRESULT = 0;
pub const E_NOTIMPL: HRESULT = 0x8000_4001_u32 as i32;
pub const E_NOINTERFACE: HRESULT = 0x8000_4002_u32 as i32;
pub const E_POINTER: HRESULT = 0x8000_4003_u32 as i32;
pub const E_FAIL: HRESULT = 0x8000_4005_u32 as i32;
pub const E_INVALIDARG: HRESULT = 0x8007_0057_u32 as i32;
pub const E_OUTOFMEMORY: HRESULT = 0x8007_000E_u32 as i32;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    pub fn format_guid(&self) -> String {
        let d = self.data4;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

/// Shared virtual-drive mount table (`G:` / `T:` -> host paths).
static DRIVE_MOUNTS: LazyLock<Mutex<HashMap<u8, PathBuf>>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    if let Ok(g) = std::env::var("LUCIAS_VFS_G").or_else(|_| std::env::var("GTA6_VFS_G")) {
        if !g.trim().is_empty() {
            m.insert(b'G', PathBuf::from(g));
        }
    }
    if let Ok(t) = std::env::var("LUCIAS_VFS_T").or_else(|_| std::env::var("GTA6_VFS_T")) {
        if !t.trim().is_empty() {
            m.insert(b'T', PathBuf::from(t));
        }
    }
    Mutex::new(m)
});

pub fn mount_virtual_drive(letter: char, root: PathBuf) -> bool {
    let upper = letter.to_ascii_uppercase();
    if !upper.is_ascii_alphabetic() {
        return false;
    }
    let mut guard = DRIVE_MOUNTS.lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(upper as u8, root);
    true
}

pub fn unmount_virtual_drives() {
    let mut guard = DRIVE_MOUNTS.lock().unwrap_or_else(|e| e.into_inner());
    guard.clear();
}

pub fn translate_virtual_path_str(input: &str) -> Option<String> {
    let stripped = input.strip_prefix(r"\\?\").unwrap_or(input);
    let bytes = stripped.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    let letter = bytes[0].to_ascii_uppercase();
    let guard = DRIVE_MOUNTS.lock().unwrap_or_else(|e| e.into_inner());
    let root = guard.get(&letter)?;
    let tail = &stripped[2..];
    let clean_tail = tail.trim_start_matches(['\\', '/']);
    let mut joined = root.clone();
    if !clean_tail.is_empty() {
        joined.push(clean_tail.replace('/', "\\"));
    }
    Some(joined.to_string_lossy().into_owned())
}

/// Read a NUL-terminated UTF-16 string safely (returns None on null).
///
/// # Safety
/// Caller must ensure `ptr` is null or points to a NUL-terminated UTF-16 buffer.
pub unsafe fn read_wide_str(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > 32768 {
            break;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

#[repr(C)]
pub struct VtableHeader<const N: usize>(pub [*const c_void; N]);

unsafe impl<const N: usize> Sync for VtableHeader<N> {}

pub const DEFAULT_SHIM_LOG_PATH: &str = r"E:\LUCIAS_PROJECT\logs\shim_trace.log";

static TRACE_START: LazyLock<Instant> = LazyLock::new(Instant::now);
static TRACE_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn resolve_trace_path() -> Option<PathBuf> {
    let val = std::env::var("LUCIAS_SHIM_LOG")
        .or_else(|_| std::env::var("GTA6_SHIM_LOG"))
        .ok()?;
    let trimmed = val.trim();
    if trimmed.is_empty() || trimmed == "0" || trimmed.eq_ignore_ascii_case("false") {
        return None;
    }
    if trimmed == "1" || trimmed.eq_ignore_ascii_case("true") {
        Some(PathBuf::from(DEFAULT_SHIM_LOG_PATH))
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn trace_sink() -> Option<&'static Mutex<File>> {
    TRACE_FILE
        .get_or_init(|| {
            let path = resolve_trace_path()?;
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()?;
            Some(Mutex::new(file))
        })
        .as_ref()
}

fn is_warning_stage(symbol: &str, detail: &str) -> bool {
    let s = symbol.to_ascii_uppercase();
    let d = detail.to_ascii_uppercase();
    s.contains("UNIMPL")
        || s.contains("WARN")
        || s.contains("ERR")
        || s.contains("FAIL")
        || s.contains("MISSING")
        || s.contains("VEH")
        || d.contains("WARN")
        || d.contains("ERR")
        || d.contains("E_NOINTERFACE")
}

/// Writes an immediate-flushed structured line when `LUCIAS_SHIM_LOG` (or `GTA6_SHIM_LOG`) is enabled,
/// and forwards warning/error stages into `telemetry::record_warning`.
#[inline]
pub fn boot_trace(module: &str, symbol: &str, detail: &str) {
    if is_warning_stage(symbol, detail) {
        telemetry::record_warning(module, &format!("{symbol} {detail}"));
    }
    let Some(sink) = trace_sink() else {
        return;
    };
    let ms = TRACE_START.elapsed().as_millis();
    let tid = std::thread::current().id();
    let mut file = sink.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(file, "[+{ms}ms] [{tid:?}] {module}!{symbol} {detail}");
    let _ = file.flush();
}

/// Logs an export invocation together with its `HRESULT`.
#[inline]
pub fn boot_trace_hr(module: &str, symbol: &str, hr: HRESULT, detail: &str) {
    if hr < 0 || is_warning_stage(symbol, detail) {
        telemetry::record_warning(
            module,
            &format!("{symbol} hr={:#010x} {detail}", hr as u32),
        );
    }
    let Some(sink) = trace_sink() else {
        return;
    };
    let ms = TRACE_START.elapsed().as_millis();
    let tid = std::thread::current().id();
    let mut file = sink.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(
        file,
        "[+{ms}ms] [{tid:?}] {module}!{symbol} -> hr={:#010x} {detail}",
        hr as u32
    );
    let _ = file.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_records_metrics_shader_errors_warnings_and_json() {
        telemetry::reset_for_tests();
        assert!(telemetry::is_overlay_visible());
        assert!(!telemetry::toggle_overlay_visible());
        assert!(telemetry::toggle_overlay_visible());

        telemetry::record_dxpk_hit();
        telemetry::record_dxpk_hit();
        telemetry::record_dxpk_miss(0x1122_3344_5566_7788, "PS");
        telemetry::record_shader_compiled();
        telemetry::record_shader_error(0xDEAD_BEEF_CAFE_0001, "VS", E_FAIL);
        telemetry::set_vram_usage_mib(5120, 7200);
        telemetry::record_gpu_duration_us(4_250);
        telemetry::record_submit_start();
        std::thread::sleep(std::time::Duration::from_millis(2));
        telemetry::record_frame_present();

        let snap = telemetry::snapshot();
        assert_eq!(snap.dxpk_hits, 2);
        assert_eq!(snap.dxpk_misses, 1);
        assert_eq!(snap.shaders_compiled, 1);
        assert_eq!(snap.shader_errors, 1);
        assert_eq!(snap.last_failed_shader_hash, 0xDEAD_BEEF_CAFE_0001);
        assert_eq!(snap.last_failed_stage, "VS");
        assert_eq!(snap.gpu_time_us, 4_250);
        assert_eq!(snap.vram_used_mib, 5120);
        assert!(snap.warnings.len() >= 2);

        let tmp = std::env::temp_dir().join("lucias_shim_common_telemetry_test.json");
        telemetry::write_telemetry_json_to(&tmp).unwrap();
        let body = std::fs::read_to_string(&tmp).unwrap();
        assert!(body.contains("\"project\": \"LUCIAS PROJECT\""));
        assert!(body.contains("\"shader_errors\": 1"));
        assert!(body.contains("0xdeadbeefcafe0001"));
        let _ = std::fs::remove_file(&tmp);
    }
}
