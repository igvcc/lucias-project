#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use shim_common::{E_INVALIDARG, E_POINTER, HRESULT, S_OK};

const E_HC_NO_NETWORK: HRESULT = 0x8007_2EFD_u32 as i32; // WINHTTP_ERROR_CANNOT_CONNECT

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static TRACE_LEVEL: AtomicU32 = AtomicU32::new(0);
static PERFORMED_CALLS: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
pub struct XAsyncBlock {
    pub queue: *const c_void,
    pub context: *mut c_void,
    pub callback: Option<extern "system" fn(*mut XAsyncBlock)>,
    pub internal: [u64; 4],
}

#[repr(C)]
pub struct HcCall {
    refs: AtomicU32,
    inner: Mutex<HcCallState>,
}

struct HcCallState {
    method: CString,
    url: CString,
    headers: Vec<(CString, CString)>,
    req_body: Vec<u8>,
    retry_allowed: bool,
    retry_cache_id: u32,
    retry_delay_sec: u32,
    timeout_sec: u32,
    timeout_window_sec: u32,
    tracing_enabled: bool,
    performed: bool,
    resp_status: u32,
    resp_net_err: HRESULT,
    resp_headers: Vec<(CString, CString)>,
    resp_body: Vec<u8>,
    resp_str: CString,
}

fn cstr_lossy(p: *const c_char) -> CString {
    if p.is_null() {
        CString::default()
    } else {
        unsafe { CStr::from_ptr(p) }.to_owned()
    }
}

pub fn performed_call_count() -> u32 {
    PERFORMED_CALLS.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn HCInitialize(_args: *const c_void) -> HRESULT {
    INITIALIZED.store(true, Ordering::Release);
    shim_common::boot_trace_hr("hc_pc", "HCInitialize", S_OK, "");
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCCleanupAsync(async_block: *mut c_void) -> HRESULT {
    INITIALIZED.store(false, Ordering::Release);
    if !async_block.is_null() {
        let blk = unsafe { &mut *async_block.cast::<XAsyncBlock>() };
        blk.internal[0] = 1;
        blk.internal[1] = S_OK as u64;
        if let Some(cb) = blk.callback {
            cb(blk);
        }
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallCreate(call: *mut *mut HcCall) -> HRESULT {
    if call.is_null() {
        return E_POINTER;
    }
    let obj = Box::new(HcCall {
        refs: AtomicU32::new(1),
        inner: Mutex::new(HcCallState {
            method: CString::new("GET").unwrap(),
            url: CString::default(),
            headers: Vec::new(),
            req_body: Vec::new(),
            retry_allowed: false,
            retry_cache_id: 0,
            retry_delay_sec: 2,
            timeout_sec: 30,
            timeout_window_sec: 20,
            tracing_enabled: false,
            performed: false,
            resp_status: 0,
            resp_net_err: E_HC_NO_NETWORK,
            resp_headers: Vec::new(),
            resp_body: Vec::new(),
            resp_str: CString::default(),
        }),
    });
    unsafe { *call = Box::into_raw(obj) };
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallDuplicateHandle(call: *mut HcCall) -> *mut HcCall {
    if !call.is_null() {
        unsafe { &*call }.refs.fetch_add(1, Ordering::Relaxed);
    }
    call
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallCloseHandle(call: *mut HcCall) -> HRESULT {
    if call.is_null() {
        return E_INVALIDARG;
    }
    let left = unsafe { &*call }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(call) });
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetUrl(
    call: *mut HcCall,
    method: *const c_char,
    url: *const c_char,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let mut g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    g.method = cstr_lossy(method);
    g.url = cstr_lossy(url);
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetUrl(
    call: *mut HcCall,
    method: *mut *const c_char,
    url: *mut *const c_char,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    if !method.is_null() {
        unsafe { *method = g.method.as_ptr() };
    }
    if !url.is_null() {
        unsafe { *url = g.url.as_ptr() };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallGetRequestUrl(call: *mut HcCall, url: *mut *const c_char) -> HRESULT {
    HCHttpCallRequestGetUrl(call, std::ptr::null_mut(), url)
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetHeader(
    call: *mut HcCall,
    name: *const c_char,
    value: *const c_char,
    _allow_tracing: bool,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let mut g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    g.headers.push((cstr_lossy(name), cstr_lossy(value)));
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetNumHeaders(call: *mut HcCall, num: *mut u32) -> HRESULT {
    let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { num.as_mut() }) else {
        return E_INVALIDARG;
    };
    *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).headers.len() as u32;
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetHeaderAtIndex(
    call: *mut HcCall,
    index: u32,
    name: *mut *const c_char,
    value: *mut *const c_char,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    let Some((k, v)) = g.headers.get(index as usize) else {
        return E_INVALIDARG;
    };
    if !name.is_null() {
        unsafe { *name = k.as_ptr() };
    }
    if !value.is_null() {
        unsafe { *value = v.as_ptr() };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetRequestBodyBytes(
    call: *mut HcCall,
    body: *const u8,
    size: u32,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let mut g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    g.req_body = if body.is_null() || size == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(body, size as usize) }.to_vec()
    };
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetRequestBodyString(
    call: *mut HcCall,
    body: *const c_char,
) -> HRESULT {
    let bytes = if body.is_null() {
        &[][..]
    } else {
        unsafe { CStr::from_ptr(body) }.to_bytes()
    };
    HCHttpCallRequestSetRequestBodyBytes(call, bytes.as_ptr(), bytes.len() as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetRequestBodyBytes(
    call: *mut HcCall,
    body: *mut *const u8,
    size: *mut u32,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    if !body.is_null() {
        unsafe { *body = g.req_body.as_ptr() };
    }
    if !size.is_null() {
        unsafe { *size = g.req_body.len() as u32 };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetRetryAllowed(call: *mut HcCall, retry: bool) -> HRESULT {
    if let Some(c) = unsafe { call.as_ref() } {
        c.inner.lock().unwrap_or_else(|e| e.into_inner()).retry_allowed = retry;
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetRetryAllowed(call: *mut HcCall, retry: *mut bool) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { retry.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).retry_allowed;
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetRetryCacheId(call: *mut HcCall, id: u32) -> HRESULT {
    if let Some(c) = unsafe { call.as_ref() } {
        c.inner.lock().unwrap_or_else(|e| e.into_inner()).retry_cache_id = id;
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetRetryCacheId(call: *mut HcCall, id: *mut u32) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { id.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).retry_cache_id;
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetRetryDelay(call: *mut HcCall, delay: u32) -> HRESULT {
    if let Some(c) = unsafe { call.as_ref() } {
        c.inner.lock().unwrap_or_else(|e| e.into_inner()).retry_delay_sec = delay;
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetRetryDelay(call: *mut HcCall, delay: *mut u32) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { delay.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).retry_delay_sec;
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetTimeout(call: *mut HcCall, timeout: u32) -> HRESULT {
    if let Some(c) = unsafe { call.as_ref() } {
        c.inner.lock().unwrap_or_else(|e| e.into_inner()).timeout_sec = timeout;
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetTimeout(call: *mut HcCall, timeout: *mut u32) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { timeout.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).timeout_sec;
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestSetTimeoutWindow(call: *mut HcCall, window: u32) -> HRESULT {
    if let Some(c) = unsafe { call.as_ref() } {
        c.inner.lock().unwrap_or_else(|e| e.into_inner()).timeout_window_sec = window;
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallRequestGetTimeoutWindow(call: *mut HcCall, window: *mut u32) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { window.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).timeout_window_sec;
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallPerformAsync(call: *mut HcCall, async_block: *mut c_void) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    {
        let mut g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.performed = true;
        g.resp_status = 0;
        g.resp_net_err = E_HC_NO_NETWORK;
        g.resp_body.clear();
        g.resp_str = CString::default();
    }
    PERFORMED_CALLS.fetch_add(1, Ordering::Relaxed);

    if async_block.is_null() {
        return E_HC_NO_NETWORK;
    }
    let blk = unsafe { &mut *async_block.cast::<XAsyncBlock>() };
    blk.internal[0] = 1;
    blk.internal[1] = S_OK as u64;
    if let Some(cb) = blk.callback {
        cb(blk);
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetStatusCode(call: *mut HcCall, status: *mut u32) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { status.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).resp_status;
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetNetworkErrorCode(
    call: *mut HcCall,
    network_err: *mut HRESULT,
    platform_err: *mut u32,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    if !network_err.is_null() {
        unsafe { *network_err = g.resp_net_err };
    }
    if !platform_err.is_null() {
        unsafe { *platform_err = 0x2EFD };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetPlatformNetworkErrorMessage(
    _call: *mut HcCall,
    msg: *mut *const c_char,
) -> HRESULT {
    static MSG: &[u8] = b"Offline PC Shim\0";
    if !msg.is_null() {
        unsafe { *msg = MSG.as_ptr().cast() };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetResponseString(
    call: *mut HcCall,
    resp: *mut *const c_char,
) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { resp.as_mut() }) {
        let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
        *out = g.resp_str.as_ptr();
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetResponseBodyBytesSize(
    call: *mut HcCall,
    size: *mut usize,
) -> HRESULT {
    if let (Some(c), Some(out)) = (unsafe { call.as_ref() }, unsafe { size.as_mut() }) {
        *out = c.inner.lock().unwrap_or_else(|e| e.into_inner()).resp_body.len();
        return S_OK;
    }
    E_INVALIDARG
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetResponseBodyBytes(
    call: *mut HcCall,
    buf_size: usize,
    buf: *mut u8,
    written: *mut usize,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    let n = g.resp_body.len().min(buf_size);
    if !buf.is_null() && n > 0 {
        unsafe { std::ptr::copy_nonoverlapping(g.resp_body.as_ptr(), buf, n) };
    }
    if !written.is_null() {
        unsafe { *written = n };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetHeader(
    call: *mut HcCall,
    name: *const c_char,
    value: *mut *const c_char,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    if !value.is_null() {
        unsafe { *value = std::ptr::null() };
        if !name.is_null() {
            let target = unsafe { CStr::from_ptr(name) }.to_string_lossy();
            let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, v)) = g
                .resp_headers
                .iter()
                .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(&target))
            {
                unsafe { *value = v.as_ptr() };
            }
        }
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetNumHeaders(call: *mut HcCall, num: *mut u32) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    if !num.is_null() {
        unsafe { *num = c.inner.lock().unwrap_or_else(|e| e.into_inner()).resp_headers.len() as u32 };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallResponseGetHeaderAtIndex(
    call: *mut HcCall,
    idx: u32,
    name: *mut *const c_char,
    value: *mut *const c_char,
) -> HRESULT {
    let Some(c) = (unsafe { call.as_ref() }) else {
        return E_INVALIDARG;
    };
    let g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
    let Some((k, v)) = g.resp_headers.get(idx as usize) else {
        if !name.is_null() {
            unsafe { *name = std::ptr::null() };
        }
        if !value.is_null() {
            unsafe { *value = std::ptr::null() };
        }
        return E_INVALIDARG;
    };
    if !name.is_null() {
        unsafe { *name = k.as_ptr() };
    }
    if !value.is_null() {
        unsafe { *value = v.as_ptr() };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCHttpCallSetTracing(call: *mut HcCall, trace: bool) -> HRESULT {
    if let Some(c) = unsafe { call.as_ref() } {
        c.inner.lock().unwrap_or_else(|e| e.into_inner()).tracing_enabled = trace;
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCSettingsGetTraceLevel(level: *mut u32) -> HRESULT {
    if !level.is_null() {
        unsafe { *level = TRACE_LEVEL.load(Ordering::Relaxed) };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn HCTraceImplMessage(
    _area: *const c_char,
    _level: u32,
    _fmt: *const c_char,
) {
}

#[unsafe(no_mangle)]
pub extern "C" fn HCTraceSetEtwEnabled(_enabled: bool) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_call_lifecycle_and_offline_async_completion_work() {
        assert_eq!(HCInitialize(std::ptr::null()), S_OK);
        let mut call = std::ptr::null_mut();
        assert_eq!(HCHttpCallCreate(&mut call), S_OK);
        assert_eq!(
            HCHttpCallRequestSetUrl(call, c"POST".as_ptr(), c"https://ros.rockstargames.com/".as_ptr()),
            S_OK
        );
        assert_eq!(
            HCHttpCallRequestSetHeader(call, c"Accept".as_ptr(), c"application/json".as_ptr(), true),
            S_OK
        );
        let mut num_headers = 0u32;
        assert_eq!(HCHttpCallRequestGetNumHeaders(call, &mut num_headers), S_OK);
        assert_eq!(num_headers, 1);

        static CALLBACK_RAN: AtomicBool = AtomicBool::new(false);
        extern "system" fn on_done(_blk: *mut XAsyncBlock) {
            CALLBACK_RAN.store(true, Ordering::Release);
        }
        let mut blk = XAsyncBlock {
            queue: std::ptr::null(),
            context: std::ptr::null_mut(),
            callback: Some(on_done),
            internal: [0; 4],
        };
        assert_eq!(
            HCHttpCallPerformAsync(call, (&raw mut blk).cast()),
            S_OK
        );
        assert!(CALLBACK_RAN.load(Ordering::Acquire));

        let mut net_err = 0;
        let mut plat_err = 0;
        assert_eq!(
            HCHttpCallResponseGetNetworkErrorCode(call, &mut net_err, &mut plat_err),
            S_OK
        );
        assert_eq!(net_err, E_HC_NO_NETWORK);
        assert_eq!(HCHttpCallCloseHandle(call), S_OK);
        assert_eq!(HCCleanupAsync(std::ptr::null_mut()), S_OK);
    }
}
