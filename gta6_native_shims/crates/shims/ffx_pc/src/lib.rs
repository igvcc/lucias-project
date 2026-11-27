#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

pub type FfxReturnCode = u32;
pub const FFX_API_RETURN_OK: FfxReturnCode = 0;
pub const FFX_API_RETURN_ERROR_PARAMETER: FfxReturnCode = 1;
pub const FFX_API_RETURN_ERROR_RUNTIME: FfxReturnCode = 2;

pub const FFX_API_EFFECT_ID_UPSCALE: u64 = 0x0001_0000;
pub const FFX_API_QUERY_DESC_TYPE_GET_VERSIONS: u64 = 4;

#[repr(C)]
pub struct FfxApiHeader {
    pub type_id: u64,
    pub p_next: *mut FfxApiHeader,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcUpscalerBackend {
    DlssStreamline = 1,
    Fsr3Pc = 2,
    NativeFallback = 3,
}

#[derive(Debug, Clone)]
pub struct FfxContextState {
    pub id: u64,
    pub backend: PcUpscalerBackend,
    pub dispatch_count: u64,
    pub last_header_type: u64,
}

static NEXT_CTX_ID: AtomicU64 = AtomicU64::new(0xFF00_0001);
static CONTEXTS: LazyLock<Mutex<HashMap<u64, FfxContextState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn probe_pc_upscaler_backend() -> PcUpscalerBackend {
    // Check optional PC Streamline / DLSS or FidelityFX PC DLLs without failing if absent.
    for name in ["sl.interposer.dll\0", "nvngx_dlss.dll\0"] {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let h = unsafe { LoadLibraryW(wide.as_ptr()) };
        if !h.is_null() {
            return PcUpscalerBackend::DlssStreamline;
        }
    }
    let ffx_wide: Vec<u16> = "amd_fidelityfx_dx12.dll\0".encode_utf16().collect();
    if unsafe { !LoadLibraryW(ffx_wide.as_ptr()).is_null() } {
        return PcUpscalerBackend::Fsr3Pc;
    }
    PcUpscalerBackend::NativeFallback
}

#[unsafe(no_mangle)]
pub extern "C" fn ffxCreateContext(
    context: *mut *mut c_void,
    desc: *const FfxApiHeader,
    _mem_cb: *const c_void,
) -> FfxReturnCode {
    if context.is_null() {
        return FFX_API_RETURN_ERROR_PARAMETER;
    }
    let header_type = unsafe { desc.as_ref() }.map_or(0, |h| h.type_id);
    let backend = probe_pc_upscaler_backend();
    let id = NEXT_CTX_ID.fetch_add(1, Ordering::Relaxed);
    let state = FfxContextState {
        id,
        backend,
        dispatch_count: 0,
        last_header_type: header_type,
    };
    CONTEXTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, state);
    unsafe { *context = id as *mut c_void };
    shim_common::boot_trace("ffx_pc", "ffxCreateContext", &format!("id={id:#x} header_type={header_type:#x}"));
    FFX_API_RETURN_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn ffxDestroyContext(
    context: *mut *mut c_void,
    _mem_cb: *const c_void,
) -> FfxReturnCode {
    if context.is_null() {
        return FFX_API_RETURN_ERROR_PARAMETER;
    }
    let id = unsafe { *context } as u64;
    if id == 0 {
        return FFX_API_RETURN_ERROR_PARAMETER;
    }
    let removed = CONTEXTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
        .is_some();
    unsafe { *context = std::ptr::null_mut() };
    if removed {
        FFX_API_RETURN_OK
    } else {
        FFX_API_RETURN_ERROR_RUNTIME
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ffxDispatch(
    context: *mut *mut c_void,
    desc: *const FfxApiHeader,
) -> FfxReturnCode {
    if context.is_null() || desc.is_null() {
        return FFX_API_RETURN_ERROR_PARAMETER;
    }
    let id = unsafe { *context } as u64;
    let header_type = unsafe { &*desc }.type_id;
    let mut map = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(ctx) = map.get_mut(&id) else {
        return FFX_API_RETURN_ERROR_RUNTIME;
    };
    ctx.dispatch_count += 1;
    ctx.last_header_type = header_type;
    FFX_API_RETURN_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn ffxQuery(
    context: *mut *mut c_void,
    desc: *mut FfxApiHeader,
) -> FfxReturnCode {
    if desc.is_null() {
        return FFX_API_RETURN_ERROR_PARAMETER;
    }
    if !context.is_null() {
        let id = unsafe { *context } as u64;
        if id != 0 && !CONTEXTS.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&id) {
            return FFX_API_RETURN_ERROR_RUNTIME;
        }
    }
    // Report valid query completion for RTX 3070 DLSS/FSR capability probe.
    let _header_type = unsafe { &*desc }.type_id;
    FFX_API_RETURN_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffx_context_lifecycle_and_dispatch() {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        let hdr = FfxApiHeader {
            type_id: FFX_API_EFFECT_ID_UPSCALE,
            p_next: std::ptr::null_mut(),
        };
        assert_eq!(
            ffxCreateContext(&mut ctx, &hdr, std::ptr::null()),
            FFX_API_RETURN_OK
        );
        assert!(!ctx.is_null());

        let mut q = FfxApiHeader {
            type_id: FFX_API_QUERY_DESC_TYPE_GET_VERSIONS,
            p_next: std::ptr::null_mut(),
        };
        assert_eq!(ffxQuery(&mut ctx, &mut q), FFX_API_RETURN_OK);
        assert_eq!(ffxDispatch(&mut ctx, &hdr), FFX_API_RETURN_OK);

        let id = ctx as u64;
        assert_eq!(
            CONTEXTS.lock().unwrap().get(&id).unwrap().dispatch_count,
            1
        );

        assert_eq!(ffxDestroyContext(&mut ctx, std::ptr::null()), FFX_API_RETURN_OK);
        assert!(ctx.is_null());
        assert_eq!(
            ffxDestroyContext(&mut ctx, std::ptr::null()),
            FFX_API_RETURN_ERROR_PARAMETER
        );
    }
}
