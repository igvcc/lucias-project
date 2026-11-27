#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, c_char, c_void};
use std::path::PathBuf;
use std::sync::OnceLock;

use shim_common::{
    BOOL, boot_trace, mount_virtual_drive, read_wide_str, translate_virtual_path_str,
    unmount_virtual_drives,
};
use windows_sys::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FindFirstFileW, GetDiskFreeSpaceExW,
    GetFileAttributesA, GetFileAttributesExW, GetFileAttributesW, MoveFileExW, RemoveDirectoryW,
    SetFileAttributesW, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, LoadLibraryW,
};

fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn translate_wide_ptr(path: *const u16) -> Option<Vec<u16>> {
    let raw = unsafe { read_wide_str(path) }?;
    let mapped = translate_virtual_path_str(&raw)?;
    Some(to_wide_nul(&mapped))
}

fn translate_ansi_ptr(path: *const c_char) -> Option<Vec<u16>> {
    if path.is_null() {
        return None;
    }
    let raw = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    let mapped = translate_virtual_path_str(&raw)?;
    Some(to_wide_nul(&mapped))
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsMountDriveW(drive_letter: u16, host_root: *const u16) -> BOOL {
    let Some(ch) = char::from_u32(drive_letter as u32) else {
        return 0;
    };
    let Some(root) = (unsafe { read_wide_str(host_root) }) else {
        return 0;
    };
    let ok = mount_virtual_drive(ch, PathBuf::from(&root));
    shim_common::boot_trace("vfs_pc", "VfsMountDriveW", &format!("{ch}: -> {root} ok={ok}"));
    ok as BOOL
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsUnmountAll() {
    unmount_virtual_drives();
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsTranslatePathW(
    input: *const u16,
    out_buf: *mut u16,
    out_cap: u32,
) -> u32 {
    let Some(raw) = (unsafe { read_wide_str(input) }) else {
        return 0;
    };
    let resolved = translate_virtual_path_str(&raw).unwrap_or(raw);
    let wide = to_wide_nul(&resolved);
    if out_buf.is_null() || out_cap == 0 {
        return wide.len() as u32;
    }
    let n = wide.len().min(out_cap as usize);
    unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), out_buf, n) };
    if n == wide.len() {
        (n - 1) as u32
    } else {
        wide.len() as u32
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsTranslatePathA(
    input: *const c_char,
    out_buf: *mut c_char,
    out_cap: u32,
) -> u32 {
    if input.is_null() {
        return 0;
    }
    let raw = unsafe { CStr::from_ptr(input) }.to_string_lossy();
    let resolved = translate_virtual_path_str(&raw).unwrap_or_else(|| raw.into_owned());
    let bytes = resolved.as_bytes();
    if out_buf.is_null() || out_cap == 0 {
        return (bytes.len() + 1) as u32;
    }
    let room = (out_cap as usize).saturating_sub(1);
    let n = bytes.len().min(room);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.cast::<u8>(), n);
        *out_buf.add(n) = 0;
    }
    n as u32
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsCreateFileW(
    file_name: *const u16,
    desired_access: u32,
    share_mode: u32,
    security_attrs: *const c_void,
    creation_disposition: u32,
    flags_and_attrs: u32,
    template_file: HANDLE,
) -> HANDLE {
    let translated = translate_wide_ptr(file_name);
    let target = translated.as_ref().map_or(file_name, |v| v.as_ptr());
    unsafe {
        CreateFileW(
            target,
            desired_access,
            share_mode,
            security_attrs.cast(),
            creation_disposition,
            flags_and_attrs,
            template_file,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsCreateDirectoryW(
    path_name: *const u16,
    security_attrs: *const c_void,
) -> BOOL {
    let translated = translate_wide_ptr(path_name);
    let target = translated.as_ref().map_or(path_name, |v| v.as_ptr());
    unsafe { CreateDirectoryW(target, security_attrs.cast()) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsRemoveDirectoryW(path_name: *const u16) -> BOOL {
    let translated = translate_wide_ptr(path_name);
    let target = translated.as_ref().map_or(path_name, |v| v.as_ptr());
    unsafe { RemoveDirectoryW(target) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsDeleteFileW(file_name: *const u16) -> BOOL {
    let translated = translate_wide_ptr(file_name);
    let target = translated.as_ref().map_or(file_name, |v| v.as_ptr());
    unsafe { DeleteFileW(target) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsGetFileAttributesW(file_name: *const u16) -> u32 {
    let translated = translate_wide_ptr(file_name);
    let target = translated.as_ref().map_or(file_name, |v| v.as_ptr());
    unsafe { GetFileAttributesW(target) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsGetFileAttributesA(file_name: *const c_char) -> u32 {
    if let Some(wide) = translate_ansi_ptr(file_name) {
        return unsafe { GetFileAttributesW(wide.as_ptr()) };
    }
    unsafe { GetFileAttributesA(file_name.cast()) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsGetFileAttributesExW(
    file_name: *const u16,
    info_level_id: i32,
    file_info: *mut c_void,
) -> BOOL {
    let translated = translate_wide_ptr(file_name);
    let target = translated.as_ref().map_or(file_name, |v| v.as_ptr());
    unsafe { GetFileAttributesExW(target, info_level_id, file_info) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsSetFileAttributesW(file_name: *const u16, file_attrs: u32) -> BOOL {
    let translated = translate_wide_ptr(file_name);
    let target = translated.as_ref().map_or(file_name, |v| v.as_ptr());
    unsafe { SetFileAttributesW(target, file_attrs) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsFindFirstFileW(
    file_name: *const u16,
    find_data: *mut WIN32_FIND_DATAW,
) -> HANDLE {
    let translated = translate_wide_ptr(file_name);
    let target = translated.as_ref().map_or(file_name, |v| v.as_ptr());
    let h = unsafe { FindFirstFileW(target, find_data) };
    if h.is_null() { INVALID_HANDLE_VALUE } else { h }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsGetDiskFreeSpaceExW(
    dir_name: *const u16,
    free_avail: *mut u64,
    total_bytes: *mut u64,
    total_free: *mut u64,
) -> BOOL {
    let translated = translate_wide_ptr(dir_name);
    let target = translated.as_ref().map_or(dir_name, |v| v.as_ptr());
    unsafe { GetDiskFreeSpaceExW(target, free_avail, total_bytes, total_free) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsMoveFileExW(
    existing_file: *const u16,
    new_file: *const u16,
    flags: u32,
) -> BOOL {
    let t_old = translate_wide_ptr(existing_file);
    let t_new = translate_wide_ptr(new_file);
    let src = t_old.as_ref().map_or(existing_file, |v| v.as_ptr());
    let dst = t_new.as_ref().map_or(new_file, |v| v.as_ptr());
    unsafe { MoveFileExW(src, dst, flags) }
}

fn exe_dir() -> Option<PathBuf> {
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || (n as usize) >= buf.len() {
        return None;
    }
    let path = PathBuf::from(String::from_utf16_lossy(&buf[..n as usize]));
    path.parent().map(PathBuf::from)
}

fn redirect_dll_name(raw: &str) -> Option<(String, bool)> {
    let file_part = raw.rsplit(['\\', '/']).next().unwrap_or(raw);
    let lower = file_part.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "xgameruntime.dll" => "xgameruntime.dll",
        "xmem.dll" => "xmem_pc.dll",
        "d3d12_xs.dll" => "dx12xs_pc.dll",
        "xg_xs.dll" => "xg_pc.dll",
        "xcrdapi.dll" => "xcrd_pc.dll",
        "chad.dll" => "chad_pc.dll",
        "xboxbvhbuilder.dll" => "xbvh_pc.dll",
        "amd_fidelityfx_loader_xbox.dll" => "ffx_pc.dll",
        "bink2scarlett.dll" => "bink2_pc.dll",
        "xapu.dll" | "acphal.dll" => "audio_pc.dll",
        "libhttpclient.gdk.dll" => "hc_pc.dll",
        "gameinput.dll" => "gi_pc.dll",
        _ => return None,
    };
    let is_xgr = lower == "xgameruntime.dll";
    if let Some(dir) = exe_dir() {
        let cand = dir.join(mapped);
        if cand.exists() {
            return Some((cand.to_string_lossy().into_owned(), is_xgr));
        }
    }
    Some((mapped.to_string(), is_xgr))
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsLoadLibraryExW(
    lib_file_name: *const u16,
    file: HANDLE,
    flags: u32,
) -> HMODULE {
    let Some(raw) = (unsafe { read_wide_str(lib_file_name) }) else {
        return std::ptr::null_mut();
    };
    if let Some((target, is_xgr)) = redirect_dll_name(&raw) {
        let stripped_flags = if is_xgr {
            flags & !LOAD_LIBRARY_SEARCH_SYSTEM32
        } else {
            flags
        };
        let wide = to_wide_nul(&target);
        let h = unsafe { LoadLibraryExW(wide.as_ptr(), file, stripped_flags) };
        boot_trace(
            "vfs_pc",
            "LoadLibraryExW",
            &format!("raw={raw} -> target={target} flags={flags:#x}->{stripped_flags:#x} h={h:?}"),
        );
        if !h.is_null() {
            return h;
        }
    }
    let translated = translate_virtual_path_str(&raw);
    if let Some(ref mapped) = translated {
        let wide = to_wide_nul(mapped);
        return unsafe { LoadLibraryExW(wide.as_ptr(), file, flags) };
    }
    unsafe { LoadLibraryExW(lib_file_name, file, flags) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsLoadLibraryExA(
    lib_file_name: *const c_char,
    file: HANDLE,
    flags: u32,
) -> HMODULE {
    if lib_file_name.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { CStr::from_ptr(lib_file_name) }.to_string_lossy();
    let wide = to_wide_nul(&raw);
    VfsLoadLibraryExW(wide.as_ptr(), file, flags)
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsLoadLibraryW(lib_file_name: *const u16) -> HMODULE {
    VfsLoadLibraryExW(lib_file_name, std::ptr::null_mut(), 0)
}

// ============================================================================
// Virtual Registry Hook (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\OEM\ConsoleMode`)
// Returns `0x60` (Series S / 1080p VRAM-saving pools) by default, or `0x64` (Series X)
// when `LUCIAS_CONSOLE_MODE=seriesx|4k`. All other keys/values forward to real `advapi32.dll`.
// ============================================================================

type RegKey = *mut c_void;

const HKEY_LOCAL_MACHINE: RegKey = 0xffff_ffff_8000_0002_u64 as RegKey;
const OEM_SUBKEY: &str = r"Software\Microsoft\Windows NT\CurrentVersion\OEM";
const CONSOLE_MODE_VALUE: &str = "ConsoleMode";
const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MORE_DATA: u32 = 234;
const REG_DWORD: u32 = 4;

/// Sentinel address standing for our virtual OEM key; never collides with a host HKEY.
static VIRTUAL_OEM_KEY: u8 = 0;

#[inline]
fn virtual_oem_key() -> RegKey {
    (&raw const VIRTUAL_OEM_KEY).cast_mut().cast()
}

static HOST_ADVAPI32: OnceLock<usize> = OnceLock::new();

fn host_advapi32() -> HMODULE {
    let addr = *HOST_ADVAPI32.get_or_init(|| {
        let name = to_wide_nul("advapi32.dll");
        let h = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        let h = if h.is_null() {
            unsafe { LoadLibraryW(name.as_ptr()) }
        } else {
            h
        };
        h as usize
    });
    addr as HMODULE
}

fn wide_eq_ignore_ascii_case(ptr: *const u16, expected: &str) -> bool {
    let Some(text) = (unsafe { read_wide_str(ptr) }) else {
        return false;
    };
    text.eq_ignore_ascii_case(expected)
}

fn try_open_virtual_oem(root: RegKey, sub: *const u16, out: *mut RegKey, api: &str) -> Option<u32> {
    if root == virtual_oem_key() {
        return Some(ERROR_FILE_NOT_FOUND);
    }
    if root == HKEY_LOCAL_MACHINE && wide_eq_ignore_ascii_case(sub, OEM_SUBKEY) && !out.is_null() {
        unsafe { out.write(virtual_oem_key()) };
        boot_trace("vfs_pc", api, "opened virtual HKLM\\...\\OEM handle");
        return Some(ERROR_SUCCESS);
    }
    None
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsRegOpenKeyW(
    root: RegKey,
    sub_key: *const u16,
    result_out: *mut RegKey,
) -> u32 {
    if let Some(status) = try_open_virtual_oem(root, sub_key, result_out, "RegOpenKeyW") {
        return status;
    }
    let h = host_advapi32();
    if h.is_null() {
        return ERROR_FILE_NOT_FOUND;
    }
    let Some(proc_fn) = (unsafe { GetProcAddress(h, c"RegOpenKeyW".as_ptr().cast()) }) else {
        return ERROR_FILE_NOT_FOUND;
    };
    type FnTy = unsafe extern "system" fn(RegKey, *const u16, *mut RegKey) -> u32;
    let f: FnTy = unsafe { std::mem::transmute(proc_fn) };
    unsafe { f(root, sub_key, result_out) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsRegOpenKeyExW(
    root: RegKey,
    sub_key: *const u16,
    options: u32,
    sam_desired: u32,
    result_out: *mut RegKey,
) -> u32 {
    if let Some(status) = try_open_virtual_oem(root, sub_key, result_out, "RegOpenKeyExW") {
        return status;
    }
    let h = host_advapi32();
    if h.is_null() {
        return ERROR_FILE_NOT_FOUND;
    }
    let Some(proc_fn) = (unsafe { GetProcAddress(h, c"RegOpenKeyExW".as_ptr().cast()) }) else {
        return ERROR_FILE_NOT_FOUND;
    };
    type FnTy = unsafe extern "system" fn(RegKey, *const u16, u32, u32, *mut RegKey) -> u32;
    let f: FnTy = unsafe { std::mem::transmute(proc_fn) };
    unsafe { f(root, sub_key, options, sam_desired, result_out) }
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsRegQueryValueExW(
    key: RegKey,
    value_name: *const u16,
    reserved: *mut u32,
    value_type: *mut u32,
    data: *mut u8,
    data_size: *mut u32,
) -> u32 {
    if key != virtual_oem_key() {
        let h = host_advapi32();
        if h.is_null() {
            return ERROR_FILE_NOT_FOUND;
        }
        let Some(proc_fn) = (unsafe { GetProcAddress(h, c"RegQueryValueExW".as_ptr().cast()) })
        else {
            return ERROR_FILE_NOT_FOUND;
        };
        type FnTy = unsafe extern "system" fn(
            RegKey,
            *const u16,
            *mut u32,
            *mut u32,
            *mut u8,
            *mut u32,
        ) -> u32;
        let f: FnTy = unsafe { std::mem::transmute(proc_fn) };
        return unsafe { f(key, value_name, reserved, value_type, data, data_size) };
    }

    if !wide_eq_ignore_ascii_case(value_name, CONSOLE_MODE_VALUE) {
        return ERROR_FILE_NOT_FOUND;
    }
    if !data.is_null() && data_size.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let (mode, profile) = shim_common::telemetry::configured_console_mode();
    unsafe {
        if !value_type.is_null() {
            value_type.write(REG_DWORD);
        }
        if data_size.is_null() {
            return ERROR_SUCCESS;
        }
        let room = data_size.read();
        data_size.write(4);
        if data.is_null() {
            return ERROR_SUCCESS;
        }
        if room < 4 {
            return ERROR_MORE_DATA;
        }
        data.cast::<u32>().write_unaligned(mode);
    }
    shim_common::telemetry::record_console_mode(mode);
    boot_trace(
        "vfs_pc",
        "RegQueryValueExW(ConsoleMode)",
        &format!("mode={mode:#x} profile={profile}"),
    );
    ERROR_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "system" fn VfsRegCloseKey(key: RegKey) -> u32 {
    if key == virtual_oem_key() {
        return ERROR_SUCCESS;
    }
    let h = host_advapi32();
    if h.is_null() {
        return ERROR_SUCCESS;
    }
    let Some(proc_fn) = (unsafe { GetProcAddress(h, c"RegCloseKey".as_ptr().cast()) }) else {
        return ERROR_SUCCESS;
    };
    type FnTy = unsafe extern "system" fn(RegKey) -> u32;
    let f: FnTy = unsafe { std::mem::transmute(proc_fn) };
    unsafe { f(key) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };

    #[test]
    fn redirects_g_and_t_drives_to_host_roots() {
        let g_dir = tempfile::tempdir().unwrap();
        let t_dir = tempfile::tempdir().unwrap();
        std::fs::write(g_dir.path().join("common.rpf"), b"RPF9").unwrap();
        std::fs::write(t_dir.path().join("scratch.bin"), b"TEMP").unwrap();

        let g_wide = to_wide_nul(&g_dir.path().to_string_lossy());
        let t_wide = to_wide_nul(&t_dir.path().to_string_lossy());
        assert_eq!(VfsMountDriveW(b'G' as u16, g_wide.as_ptr()), 1);
        assert_eq!(VfsMountDriveW(b'T' as u16, t_wide.as_ptr()), 1);

        let g_req = to_wide_nul(r"G:\common.rpf");
        let h = VfsCreateFileW(
            g_req.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        assert_ne!(h, INVALID_HANDLE_VALUE);
        unsafe { CloseHandle(h) };

        let mut out = [0u16; 260];
        let t_req = to_wide_nul(r"T:/scratch.bin");
        let len = VfsTranslatePathW(t_req.as_ptr(), out.as_mut_ptr(), out.len() as u32);
        let translated = String::from_utf16_lossy(&out[..len as usize]);
        assert!(translated.ends_with("scratch.bin"));
        assert!(!translated.starts_with("T:"));

        VfsUnmountAll();
    }

    #[test]
    fn virtual_registry_returns_series_s_console_mode_and_passes_through_real_hklm() {
        // Ensure default Series S (0x60) mode when LUCIAS_CONSOLE_MODE is unset.
        unsafe { std::env::remove_var("LUCIAS_CONSOLE_MODE") };
        shim_common::telemetry::reset_for_tests();

        let oem_path = to_wide_nul(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\OEM");
        let val_name = to_wide_nul("ConsoleMode");
        let missing_val = to_wide_nul("DoesNotExist");

        // 1. Open via RegOpenKeyExW and query ConsoleMode
        let mut hkey: RegKey = std::ptr::null_mut();
        assert_eq!(
            VfsRegOpenKeyExW(HKEY_LOCAL_MACHINE, oem_path.as_ptr(), 0, 0x20019, &mut hkey),
            ERROR_SUCCESS
        );
        assert_eq!(hkey, virtual_oem_key());

        // Size-only query
        let mut kind = 0u32;
        let mut size = 0u32;
        assert_eq!(
            VfsRegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(kind, REG_DWORD);
        assert_eq!(size, 4);

        // Too-small buffer -> ERROR_MORE_DATA
        let mut small_buf = [0u8; 2];
        let mut small_sz = 2u32;
        assert_eq!(
            VfsRegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                small_buf.as_mut_ptr(),
                &mut small_sz,
            ),
            ERROR_MORE_DATA
        );
        assert_eq!(small_sz, 4);

        // Full read -> 0x60 (Series S)
        let mut mode = 0u32;
        let mut mode_sz = 4u32;
        assert_eq!(
            VfsRegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                (&raw mut mode).cast(),
                &mut mode_sz,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(kind, REG_DWORD);
        assert_eq!(mode_sz, 4);
        assert_eq!(mode, 0x60);
        assert_eq!(shim_common::telemetry::snapshot().console_profile, "SeriesS-1080p");

        // Unknown value under OEM -> ERROR_FILE_NOT_FOUND
        assert_eq!(
            VfsRegQueryValueExW(
                hkey,
                missing_val.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut mode_sz,
            ),
            ERROR_FILE_NOT_FOUND
        );

        // LUCIAS_CONSOLE_MODE=seriesx -> 0x64 (Series X)
        unsafe { std::env::set_var("LUCIAS_CONSOLE_MODE", "seriesx") };
        mode = 0;
        mode_sz = 4;
        assert_eq!(
            VfsRegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                (&raw mut mode).cast(),
                &mut mode_sz,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(mode, 0x64);
        assert_eq!(shim_common::telemetry::snapshot().console_profile, "SeriesX-4K");
        unsafe { std::env::remove_var("LUCIAS_CONSOLE_MODE") };

        // Close virtual key
        assert_eq!(VfsRegCloseKey(hkey), ERROR_SUCCESS);

        // 2. Also verify RegOpenKeyW opens the virtual OEM key
        let mut hkey2: RegKey = std::ptr::null_mut();
        assert_eq!(
            VfsRegOpenKeyW(HKEY_LOCAL_MACHINE, oem_path.as_ptr(), &mut hkey2),
            ERROR_SUCCESS
        );
        assert_eq!(hkey2, virtual_oem_key());
        assert_eq!(VfsRegCloseKey(hkey2), ERROR_SUCCESS);

        // 3. Passthrough to a real HKLM key (`Software\Microsoft\Windows NT\CurrentVersion`)
        let real_path = to_wide_nul(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        let prod_name = to_wide_nul("ProductName");
        let mut real_hkey: RegKey = std::ptr::null_mut();
        assert_eq!(
            VfsRegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                real_path.as_ptr(),
                0,
                0x20019,
                &mut real_hkey,
            ),
            ERROR_SUCCESS
        );
        assert!(!real_hkey.is_null());
        assert_ne!(real_hkey, virtual_oem_key());

        let mut buf = [0u8; 256];
        let mut buf_sz = buf.len() as u32;
        let mut real_kind = 0u32;
        assert_eq!(
            VfsRegQueryValueExW(
                real_hkey,
                prod_name.as_ptr(),
                std::ptr::null_mut(),
                &mut real_kind,
                buf.as_mut_ptr(),
                &mut buf_sz,
            ),
            ERROR_SUCCESS
        );
        assert!(buf_sz > 2);
        assert_eq!(VfsRegCloseKey(real_hkey), ERROR_SUCCESS);
    }
}
