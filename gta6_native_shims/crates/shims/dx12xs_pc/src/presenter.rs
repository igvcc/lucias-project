//! Lazy Win32 window + `IDXGISwapChain3` presenter for `QueueX::PresentX`.
//!
//! Xbox Scarlett titles present directly via `PresentX(planes)` without creating a Win32 HWND
//! or DXGI swapchain. When no `target_hwnd` is registered yet, this module spawns a clean
//! Win32 message-pump window (`"LUCIAS PROJECT - DirectX 12"`), creates a `FLIP_DISCARD`
//! `IDXGISwapChain3` on the game's real `ID3D12CommandQueue`, copies `planes[0]` into the
//! current backbuffer via `CopyTextureRegion`, and calls `Present(0, 0)`.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use shim_common::{E_FAIL, Guid, HRESULT, S_OK, boot_trace, boot_trace_hr};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use crate::com_proxy::{ResourceDescRaw, map_xbox_dxgi_format};

/// `LUCIAS_DUMP_FRAME=1` enables periodic backbuffer readback + PPM dump (`25s` then every `15s`, max `20`, plus `DrawIndexed`/`Dispatch` start).
static DUMP_FRAME: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("LUCIAS_DUMP_FRAME").is_ok_and(|v| v.trim() == "1")
});
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);
const DUMP_DIR: &str = r"E:\LUCIAS_PROJECT\logs";

pub(crate) fn should_dump_frame(
    enabled: bool,
    elapsed_s: f64,
    since_last_s: Option<f64>,
    dump_count: u32,
    draws: (u64, u64, u64, u64),
    dumped_3d_start: bool,
) -> (bool, bool) {
    if !enabled || dump_count >= 20 {
        return (false, false);
    }
    let trigger_3d = !dumped_3d_start && (draws.1 > 0 || draws.2 > 0);
    if trigger_3d {
        return (true, true);
    }
    let due = match since_last_s {
        None => elapsed_s >= 25.0,
        Some(dt) => dt >= 15.0,
    };
    (due, false)
}

fn f16_to_u8(bits: u16) -> u8 {
    let sign = (bits >> 15) & 1;
    let exp = ((bits >> 10) & 0x1F) as i32;
    let frac = (bits & 0x3FF) as f32;
    if sign != 0 || exp == 0 && frac == 0.0 {
        return 0;
    }
    let val = if exp == 0 {
        (frac / 1024.0) * 2.0f32.powi(-14)
    } else if exp == 31 {
        1.0
    } else {
        (1.0 + frac / 1024.0) * 2.0f32.powi(exp - 15)
    };
    (val.clamp(0.0, 1.0) * 255.0).round() as u8
}

/// Converts a mapped readback image (32-bpp or RGBA16F) to RGBA stats + a 4x downsampled binary PPM (`P6`).
/// Returns `(nonzero_rgb_pixels, center_rgba, quarter_rgba, ppm_bytes)`.
pub(crate) fn analyze_frame_pixels(
    data: &[u8],
    w: u32,
    h: u32,
    row_pitch: u32,
    fmt: u32,
) -> (u64, [u8; 4], [u8; 4], Vec<u8>) {
    let bpp = if fmt == 10 { 8usize } else { 4usize };
    let to_rgba = |off: usize| -> [u8; 4] {
        if fmt == 10 {
            if off + 8 <= data.len() {
                [
                    f16_to_u8(u16::from_le_bytes([data[off], data[off + 1]])),
                    f16_to_u8(u16::from_le_bytes([data[off + 2], data[off + 3]])),
                    f16_to_u8(u16::from_le_bytes([data[off + 4], data[off + 5]])),
                    f16_to_u8(u16::from_le_bytes([data[off + 6], data[off + 7]])),
                ]
            } else {
                [0; 4]
            }
        } else if off + 4 <= data.len() {
            let px = [data[off], data[off + 1], data[off + 2], data[off + 3]];
            match fmt {
                87 | 90 | 91 => [px[2], px[1], px[0], px[3]],
                23 | 24 => {
                    let v = u32::from_le_bytes(px);
                    [
                        ((v & 0x3FF) >> 2) as u8,
                        (((v >> 10) & 0x3FF) >> 2) as u8,
                        (((v >> 20) & 0x3FF) >> 2) as u8,
                        (((v >> 30) & 0x3) * 85) as u8,
                    ]
                }
                _ => px,
            }
        } else {
            [0; 4]
        }
    };
    let read_px = |x: u32, y: u32| -> [u8; 4] {
        let off = y as usize * row_pitch as usize + x as usize * bpp;
        to_rgba(off)
    };
    if w == 0 || h == 0 {
        return (0, [0; 4], [0; 4], Vec::new());
    }
    let mut nonzero = 0u64;
    for y in 0..h {
        for x in 0..w {
            let p = read_px(x, y);
            if (p[0] | p[1] | p[2]) != 0 {
                nonzero += 1;
            }
        }
    }
    let center = read_px(w / 2, h / 2);
    let quarter = read_px(w / 4, h / 4);
    let dw = (w / 4).max(1);
    let dh = (h / 4).max(1);
    let mut ppm = format!("P6\n{dw} {dh}\n255\n").into_bytes();
    ppm.reserve(dw as usize * dh as usize * 3);
    for y in 0..dh {
        for x in 0..dw {
            let p = read_px((x * 4).min(w - 1), (y * 4).min(h - 1));
            ppm.extend_from_slice(&p[..3]);
        }
    }
    (nonzero, center, quarter, ppm)
}

unsafe fn create_readback_buffer(device: *mut c_void, bytes: u64) -> *mut c_void {
    if device.is_null() || bytes == 0 {
        return std::ptr::null_mut();
    }
    let heap_props = [3u32, 0, 0, 0, 0]; // D3D12_HEAP_TYPE_READBACK
    let desc = ResourceDescRaw {
        dimension: 1, // BUFFER
        alignment: 0,
        width: bytes,
        height: 1,
        depth_or_array: 1,
        mip_levels: 1,
        format: 0,
        sample_count: 1,
        sample_quality: 0,
        layout: 1, // ROW_MAJOR
        flags: 0,
    };
    let mut res: *mut c_void = std::ptr::null_mut();
    type CreateCommittedFn = unsafe extern "system" fn(
        *mut c_void,
        *const [u32; 5],
        u32,
        *const ResourceDescRaw,
        u32,
        *const c_void,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let hr = unsafe {
        com_slot::<CreateCommittedFn>(device, 27)(
            device,
            &heap_props,
            0,
            &desc,
            D3D12_RESOURCE_STATE_COPY_DEST,
            std::ptr::null(),
            &IID_ID3D12RESOURCE,
            &mut res,
        )
    };
    if hr < 0 {
        boot_trace_hr("dx12xs_pc", "PresentContext::readback_alloc", hr, &format!("bytes={bytes:#x}"));
        return std::ptr::null_mut();
    }
    res
}

struct ReadbackJob {
    rb: *mut c_void,
    w: u32,
    h: u32,
    fmt: u32,
    row_pitch: u32,
    tag: &'static str,
    write_ppm: bool,
}

#[repr(C)]
struct PresentBarrierRaw {
    ty: u32,
    flags: u32,
    u: [u64; 3],
}

#[repr(C)]
struct PresentCopyLocationRaw {
    resource: *mut c_void,
    ty: u32,
    _pad: u32,
    payload: [u64; 4],
}

const DXGI_MWA_NO_ALT_ENTER: u32 = 0x2;
const DXGI_USAGE_RENDER_TARGET_OUTPUT: u32 = 0x20;
const DXGI_SCALING_STRETCH: u32 = 0;
const DXGI_SWAP_EFFECT_FLIP_DISCARD: u32 = 4;
const DXGI_ALPHA_MODE_UNSPECIFIED: u32 = 0;
const INFINITE: u32 = 0xFFFF_FFFF;

const D3D12_RESOURCE_STATE_PRESENT: u32 = 0;
const D3D12_RESOURCE_STATE_COPY_DEST: u32 = 0x400;
const D3D12_RESOURCE_STATE_COPY_SOURCE: u32 = 0x800;

const IID_IDXGIFACTORY2: Guid = Guid::new(
    0x50c8_3a1c,
    0xe072,
    0x4c48,
    [0x87, 0xb0, 0x36, 0x30, 0xfa, 0x36, 0xa6, 0xd0],
);
const IID_IDXGISWAPCHAIN3: Guid = Guid::new(
    0x94d9_9bdb,
    0xf1f8,
    0x4ab0,
    [0xb2, 0x36, 0x7d, 0xa0, 0x17, 0x0e, 0xda, 0xb1],
);
const IID_ID3D12RESOURCE: Guid = Guid::new(
    0x6964_42be,
    0xa72e,
    0x4059,
    [0xbc, 0x79, 0x5b, 0x5c, 0x98, 0x04, 0x0f, 0xad],
);
const IID_ID3D12COMMAND_ALLOCATOR: Guid = Guid::new(
    0x6102_dee4,
    0xaf59,
    0x4b09,
    [0xb9, 0x99, 0xb4, 0x4d, 0x73, 0xf0, 0x9b, 0x24],
);
const IID_ID3D12GRAPHICS_COMMAND_LIST: Guid = Guid::new(
    0x5b16_0d0f,
    0xac1b,
    0x4185,
    [0x8b, 0xa8, 0xb3, 0xae, 0x42, 0xa5, 0xa4, 0x55],
);
const IID_ID3D12COMMAND_QUEUE: Guid = Guid::new(
    0x0ec8_70a6,
    0x5d7e,
    0x4c22,
    [0x8c, 0xfc, 0x5b, 0xaa, 0xe0, 0x76, 0x16, 0xed],
);
const IID_ID3D12FENCE: Guid = Guid::new(
    0x0a75_3dcf,
    0xc4d8,
    0x4b91,
    [0xad, 0xf6, 0xbe, 0x5a, 0x60, 0xd9, 0x5a, 0x76],
);

#[repr(C)]
struct QueueDescRaw {
    ty: u32,
    priority: i32,
    flags: u32,
    node_mask: u32,
}

#[repr(C)]
struct DxgiSwapChainDesc1 {
    width: u32,
    height: u32,
    format: u32,
    stereo: i32,
    sample_count: u32,
    sample_quality: u32,
    buffer_usage: u32,
    buffer_count: u32,
    scaling: u32,
    swap_effect: u32,
    alpha_mode: u32,
    flags: u32,
}

const _: () = assert!(size_of::<DxgiSwapChainDesc1>() == 48);

struct DxgiD3d12Handles {
    present_queue: *mut c_void,
    swapchain3: *mut c_void,
    buffers: [*mut c_void; 2],
    copy_alloc: *mut c_void,
    copy_list: *mut c_void,
    copy_fence: *mut c_void,
    fence_event: *mut c_void,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(h_object: *mut c_void) -> i32;
}

unsafe extern "system" fn present_wnd_proc(
    hwnd: isize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    unsafe { crate::overlay::default_wnd_proc(hwnd, msg, w_param, l_param) }
}

fn utf16_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[inline]
unsafe fn com_slot<F: Copy>(obj: *mut c_void, slot: usize) -> F {
    let vtbl = unsafe { *obj.cast::<*const *const c_void>() };
    unsafe { std::mem::transmute_copy(&*vtbl.add(slot)) }
}

unsafe fn real_release(obj: *mut c_void) {
    if !obj.is_null() {
        type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let _ = unsafe { com_slot::<RelFn>(obj, 2)(obj) };
    }
}

/// Maps Xbox / PC texture format to a `FLIP_DISCARD`-compatible swapchain format (`28`, `87`, `24`).
pub(crate) fn swapchain_format_for_plane(raw_fmt: u32) -> u32 {
    match map_xbox_dxgi_format(raw_fmt) {
        87 | 90 | 91 => 87, // B8G8R8A8_UNORM
        23 | 24 => 24,      // R10G10B10A2_UNORM
        _ => 28,            // R8G8B8A8_UNORM
    }
}

fn is_format_copy_compatible(src_raw_fmt: u32, dst_sc_fmt: u32) -> bool {
    let f = map_xbox_dxgi_format(src_raw_fmt);
    match dst_sc_fmt {
        28 => matches!(f, 27..=29),
        87 => matches!(f, 87 | 90 | 91),
        24 => matches!(f, 23 | 24),
        _ => f == dst_sc_fmt,
    }
}

pub(crate) struct PresentContext {
    hwnd: isize,
    stop_flag: Arc<AtomicBool>,
    pump_thread: Option<JoinHandle<()>>,
    real_device: *mut c_void,
    info_queue: *mut c_void,
    present_queue: *mut c_void,
    swapchain3: *mut c_void,
    buffers: [*mut c_void; 2],
    buf_w: u32,
    buf_h: u32,
    buf_fmt: u32,
    copy_alloc: *mut c_void,
    copy_list: *mut c_void,
    copy_fence: *mut c_void,
    fence_event: *mut c_void,
    fence_val: u64,
    logged_skip: bool,
    last_dump_at: Option<Instant>,
    dump_count: u32,
    dumped_3d_start: bool,
}

unsafe impl Send for PresentContext {}

impl PresentContext {
    pub(crate) fn new(
        real_device: *mut c_void,
        info_queue: *mut c_void,
        req_w: u32,
        req_h: u32,
        req_fmt: u32,
    ) -> Option<Self> {
        if real_device.is_null() {
            return None;
        }
        let client_w = req_w.clamp(640, 1920);
        let client_h = req_h.clamp(360, 1080);
        let sc_fmt = swapchain_format_for_plane(req_fmt);

        let ready = Arc::new((Mutex::new(Option::<isize>::None), Condvar::new()));
        let ready_bg = Arc::clone(&ready);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop_flag);
        let actual_hwnd = Arc::new(AtomicU64::new(0));
        let actual_hwnd_bg = Arc::clone(&actual_hwnd);

        let pump_thread = std::thread::Builder::new()
            .name("lucias-present-window".into())
            .spawn(move || {
                let class_name = utf16_null("LuciasProjectGameWindowClass");
                let title = utf16_null("LUCIAS PROJECT - DirectX 12");
                let hwnd = unsafe {
                    crate::overlay::create_simple_window(
                        class_name.as_ptr(),
                        title.as_ptr(),
                        present_wnd_proc,
                        client_w as i32,
                        client_h as i32,
                    )
                };

                if hwnd != 0 {
                    actual_hwnd_bg.store(hwnd as u64, Ordering::Release);
                    shim_common::telemetry::set_target_hwnd(hwnd as usize);
                } else {
                    let err = unsafe { GetLastError() };
                    boot_trace("dx12xs_pc", "PresentContext::CreateWindowExW", &format!("failed gle={err}"));
                }
                {
                    let (lock, cv) = &*ready_bg;
                    if let Ok(mut g) = lock.lock() {
                        *g = Some(hwnd);
                        cv.notify_all();
                    }
                }
                if hwnd == 0 {
                    return;
                }

                while !stop_bg.load(Ordering::Acquire) {
                    if crate::overlay::drain_window_messages(hwnd) {
                        stop_bg.store(true, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(8));
                }
                if shim_common::telemetry::target_hwnd() == hwnd as usize {
                    shim_common::telemetry::set_target_hwnd(0);
                }
                unsafe {
                    crate::overlay::destroy_simple_window(hwnd);
                }
            })
            .ok()?;

        let hwnd = {
            let (lock, cv) = &*ready;
            let mut g = lock.lock().ok()?;
            if g.is_none() {
                let (ng, _) = cv.wait_timeout(g, Duration::from_secs(2)).ok()?;
                g = ng;
            }
            g.unwrap_or(0)
        };
        if hwnd == 0 {
            stop_flag.store(true, Ordering::Release);
            let _ = pump_thread.join();
            return None;
        }

        let sc_res = unsafe { Self::create_dxgi_and_d3d12_objects(real_device, hwnd, client_w, client_h, sc_fmt) };
        let Ok(h) = sc_res else {
            stop_flag.store(true, Ordering::Release);
            unsafe { crate::overlay::post_null_message(hwnd) };
            let _ = pump_thread.join();
            return None;
        };

        boot_trace_hr(
            "dx12xs_pc",
            "PresentContext::init",
            S_OK,
            &format!(
                "hwnd={hwnd:#x} size={client_w}x{client_h} fmt={sc_fmt} pq={:?} sc3={:?}",
                h.present_queue, h.swapchain3
            ),
        );

        Some(Self {
            hwnd,
            stop_flag,
            pump_thread: Some(pump_thread),
            real_device,
            info_queue,
            present_queue: h.present_queue,
            swapchain3: h.swapchain3,
            buffers: h.buffers,
            buf_w: client_w,
            buf_h: client_h,
            buf_fmt: sc_fmt,
            copy_alloc: h.copy_alloc,
            copy_list: h.copy_list,
            copy_fence: h.copy_fence,
            fence_event: h.fence_event,
            fence_val: 0,
            logged_skip: false,
            last_dump_at: None,
            dump_count: 0,
            dumped_3d_start: false,
        })
    }

    unsafe fn create_dxgi_and_d3d12_objects(
        real_device: *mut c_void,
        hwnd: isize,
        w: u32,
        h: u32,
        fmt: u32,
    ) -> Result<DxgiD3d12Handles, HRESULT> {
        let mut present_queue: *mut c_void = std::ptr::null_mut();
        type CreateQueueFn = unsafe extern "system" fn(
            *mut c_void,
            *const QueueDescRaw,
            *const Guid,
            *mut *mut c_void,
        ) -> HRESULT;
        let q_desc = QueueDescRaw {
            ty: 0,
            priority: 0,
            flags: 0,
            node_mask: 0,
        };
        let hr_pq = unsafe {
            com_slot::<CreateQueueFn>(real_device, 8)(
                real_device,
                &q_desc,
                &IID_ID3D12COMMAND_QUEUE,
                &mut present_queue,
            )
        };
        if hr_pq < 0 || present_queue.is_null() {
            boot_trace_hr("dx12xs_pc", "PresentContext::CreateCommandQueue", hr_pq, "");
            return Err(hr_pq);
        }

        let dxgi_name = utf16_null("dxgi.dll");
        let dxgi = unsafe { LoadLibraryW(dxgi_name.as_ptr()) };
        if dxgi.is_null() {
            unsafe { real_release(present_queue) };
            return Err(E_FAIL);
        }
        let Some(create_fac1_fn) = (unsafe { GetProcAddress(dxgi, c"CreateDXGIFactory1".as_ptr().cast()) }) else {
            unsafe { real_release(present_queue) };
            return Err(E_FAIL);
        };
        type CreateFacFn = unsafe extern "system" fn(*const Guid, *mut *mut c_void) -> HRESULT;
        let create_fac: CreateFacFn = unsafe { std::mem::transmute(create_fac1_fn) };
        let mut fac2: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { create_fac(&IID_IDXGIFACTORY2, &mut fac2) };
        if hr < 0 || fac2.is_null() {
            unsafe { real_release(present_queue) };
            boot_trace_hr("dx12xs_pc", "PresentContext::CreateDXGIFactory1", hr, "");
            return Err(hr);
        }
        type MakeWinAssocFn = unsafe extern "system" fn(*mut c_void, isize, u32) -> HRESULT;
        let _ = unsafe { com_slot::<MakeWinAssocFn>(fac2, 8)(fac2, hwnd, DXGI_MWA_NO_ALT_ENTER) };

        let desc = DxgiSwapChainDesc1 {
            width: w,
            height: h,
            format: fmt,
            stereo: 0,
            sample_count: 1,
            sample_quality: 0,
            buffer_usage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            buffer_count: 2,
            scaling: DXGI_SCALING_STRETCH,
            swap_effect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
            alpha_mode: DXGI_ALPHA_MODE_UNSPECIFIED,
            flags: 0,
        };
        let mut sc1: *mut c_void = std::ptr::null_mut();
        type CreateScFn = unsafe extern "system" fn(
            *mut c_void,
            *mut c_void,
            isize,
            *const DxgiSwapChainDesc1,
            *const c_void,
            *mut c_void,
            *mut *mut c_void,
        ) -> HRESULT;
        let hr_sc = unsafe {
            com_slot::<CreateScFn>(fac2, 15)(
                fac2,
                present_queue,
                hwnd,
                &desc,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut sc1,
            )
        };
        unsafe { real_release(fac2) };
        if hr_sc < 0 || sc1.is_null() {
            unsafe { real_release(present_queue) };
            boot_trace_hr("dx12xs_pc", "PresentContext::CreateSwapChainForHwnd", hr_sc, &format!("{w}x{h} fmt={fmt}"));
            return Err(hr_sc);
        }

        let mut sc3: *mut c_void = std::ptr::null_mut();
        type QiFn = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> HRESULT;
        let hr_qi = unsafe { com_slot::<QiFn>(sc1, 0)(sc1, &IID_IDXGISWAPCHAIN3, &mut sc3) };
        unsafe { real_release(sc1) };
        if hr_qi < 0 || sc3.is_null() {
            unsafe { real_release(present_queue) };
            boot_trace_hr("dx12xs_pc", "PresentContext::QI(IDXGISwapChain3)", hr_qi, "");
            return Err(hr_qi);
        }

        let mut buffers = [std::ptr::null_mut(); 2];
        type GetBufFn = unsafe extern "system" fn(*mut c_void, u32, *const Guid, *mut *mut c_void) -> HRESULT;
        for (i, slot) in buffers.iter_mut().enumerate() {
            let hr_b = unsafe { com_slot::<GetBufFn>(sc3, 9)(sc3, i as u32, &IID_ID3D12RESOURCE, slot) };
            if hr_b < 0 || slot.is_null() {
                for b in buffers {
                    unsafe { real_release(b) };
                }
                unsafe {
                    real_release(sc3);
                    real_release(present_queue);
                }
                boot_trace_hr("dx12xs_pc", "PresentContext::GetBuffer", hr_b, &format!("buf={i}"));
                return Err(hr_b);
            }
        }

        let mut copy_alloc: *mut c_void = std::ptr::null_mut();
        type CreateAllocFn = unsafe extern "system" fn(*mut c_void, u32, *const Guid, *mut *mut c_void) -> HRESULT;
        let hr_a = unsafe { com_slot::<CreateAllocFn>(real_device, 9)(real_device, 0, &IID_ID3D12COMMAND_ALLOCATOR, &mut copy_alloc) };
        if hr_a < 0 || copy_alloc.is_null() {
            for b in buffers {
                unsafe { real_release(b) };
            }
            unsafe {
                real_release(sc3);
                real_release(present_queue);
            }
            return Err(hr_a);
        }

        let mut copy_list: *mut c_void = std::ptr::null_mut();
        type CreateListFn = unsafe extern "system" fn(*mut c_void, u32, u32, *mut c_void, *mut c_void, *const Guid, *mut *mut c_void) -> HRESULT;
        let hr_l = unsafe {
            com_slot::<CreateListFn>(real_device, 12)(
                real_device,
                0,
                0,
                copy_alloc,
                std::ptr::null_mut(),
                &IID_ID3D12GRAPHICS_COMMAND_LIST,
                &mut copy_list,
            )
        };
        if hr_l < 0 || copy_list.is_null() {
            unsafe { real_release(copy_alloc) };
            for b in buffers {
                unsafe { real_release(b) };
            }
            unsafe {
                real_release(sc3);
                real_release(present_queue);
            }
            return Err(hr_l);
        }
        type CloseFn = unsafe extern "system" fn(*mut c_void) -> HRESULT;
        let _ = unsafe { com_slot::<CloseFn>(copy_list, 9)(copy_list) };

        let mut copy_fence: *mut c_void = std::ptr::null_mut();
        type CreateFenceFn = unsafe extern "system" fn(*mut c_void, u64, u32, *const Guid, *mut *mut c_void) -> HRESULT;
        let hr_f = unsafe { com_slot::<CreateFenceFn>(real_device, 36)(real_device, 0, 0, &IID_ID3D12FENCE, &mut copy_fence) };
        if hr_f < 0 || copy_fence.is_null() {
            unsafe {
                real_release(copy_list);
                real_release(copy_alloc);
            }
            for b in buffers {
                unsafe { real_release(b) };
            }
            unsafe {
                real_release(sc3);
                real_release(present_queue);
            }
            return Err(hr_f);
        }
        let fence_event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if fence_event.is_null() {
            unsafe {
                real_release(copy_fence);
                real_release(copy_list);
                real_release(copy_alloc);
            }
            for b in buffers {
                unsafe { real_release(b) };
            }
            unsafe {
                real_release(sc3);
                real_release(present_queue);
            }
            return Err(E_FAIL);
        }

        Ok(DxgiD3d12Handles {
            present_queue,
            swapchain3: sc3,
            buffers,
            copy_alloc,
            copy_list,
            copy_fence,
            fence_event,
        })
    }

    fn wait_fence_idle(&self) {
        if self.fence_val == 0 || self.copy_fence.is_null() {
            return;
        }
        type GetCompletedFn = unsafe extern "system" fn(*mut c_void) -> u64;
        type SetEventFn = unsafe extern "system" fn(*mut c_void, u64, *mut c_void) -> HRESULT;
        let completed = unsafe { com_slot::<GetCompletedFn>(self.copy_fence, 8)(self.copy_fence) };
        if completed < self.fence_val {
            let hr = unsafe { com_slot::<SetEventFn>(self.copy_fence, 9)(self.copy_fence, self.fence_val, self.fence_event) };
            if hr >= 0 && !self.fence_event.is_null() {
                unsafe { WaitForSingleObject(self.fence_event, INFINITE) };
            }
        }
    }

    pub(crate) fn present_plane(
        &mut self,
        real_queue: *mut c_void,
        src_real_res: *mut c_void,
        src_desc: Option<&ResourceDescRaw>,
        src_cur_state: u32,
        alt_dump: Option<(*mut c_void, ResourceDescRaw, u32)>,
        tick: u64,
    ) -> (HRESULT, bool) {
        self.wait_fence_idle();

        type GetCurBbFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let bb_idx = (unsafe { com_slot::<GetCurBbFn>(self.swapchain3, 36)(self.swapchain3) } as usize) % 2;
        let dst_bb = self.buffers[bb_idx];

        let pre_reason = crate::com_proxy::query_real_removed_reason(self.real_device);
        let mut did_copy = false;
        let (want_dump, trigger_3d) = should_dump_frame(
            *DUMP_FRAME,
            PROCESS_START.elapsed().as_secs_f64(),
            self.last_dump_at.map(|t| t.elapsed().as_secs_f64()),
            self.dump_count,
            crate::com_proxy::gpu_draw_totals(),
            self.dumped_3d_start,
        );
        let mut readbacks: Vec<ReadbackJob> = Vec::new();
        if let Some(d) = src_desc {
            if tick <= 4 {
                boot_trace(
                    "dx12xs_pc",
                    "PresentContext::plane0",
                    &format!(
                        "tick={tick} dim={} size={}x{} fmt={} mips={} arr={} sc={} flags={:#x} cur_state={:#x} pre_reason={:#010x}",
                        d.dimension,
                        d.width,
                        d.height,
                        d.format,
                        d.mip_levels,
                        d.depth_or_array,
                        d.sample_count,
                        d.flags,
                        src_cur_state,
                        pre_reason as u32
                    ),
                );
            }
            let compatible = !src_real_res.is_null()
                && !dst_bb.is_null()
                && d.dimension == 3
                && d.width > 0
                && d.height > 0
                && d.sample_count <= 1
                && is_format_copy_compatible(d.format, self.buf_fmt);
            if compatible || (want_dump && !src_real_res.is_null() && d.dimension == 3 && d.sample_count <= 1) {
                type ResetAllocFn = unsafe extern "system" fn(*mut c_void) -> HRESULT;
                type ResetListFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> HRESULT;
                type CloseFn = unsafe extern "system" fn(*mut c_void) -> HRESULT;
                type BarrierFn = unsafe extern "system" fn(*mut c_void, u32, *const PresentBarrierRaw);
                type CopyTexRegFn = unsafe extern "system" fn(
                    *mut c_void,
                    *const PresentCopyLocationRaw,
                    u32,
                    u32,
                    u32,
                    *const PresentCopyLocationRaw,
                    *const [u32; 6],
                );
                type ExecFn = unsafe extern "system" fn(*mut c_void, u32, *const *mut c_void);

                let hr_ra = unsafe { com_slot::<ResetAllocFn>(self.copy_alloc, 8)(self.copy_alloc) };
                let hr_rl = if hr_ra >= 0 {
                    unsafe { com_slot::<ResetListFn>(self.copy_list, 10)(self.copy_list, self.copy_alloc, std::ptr::null_mut()) }
                } else {
                    hr_ra
                };
                if hr_rl >= 0 {
                    let mut pre = Vec::with_capacity(3);
                    if compatible {
                        pre.push(PresentBarrierRaw {
                            ty: 0,
                            flags: 0,
                            u: [
                                dst_bb as u64,
                                ((u64::from(D3D12_RESOURCE_STATE_PRESENT)) << 32) | 0xFFFF_FFFF,
                                u64::from(D3D12_RESOURCE_STATE_COPY_DEST),
                            ],
                        });
                    }
                    if !src_real_res.is_null() && src_cur_state != D3D12_RESOURCE_STATE_COPY_SOURCE {
                        pre.push(PresentBarrierRaw {
                            ty: 0,
                            flags: 0,
                            u: [
                                src_real_res as u64,
                                ((u64::from(src_cur_state)) << 32) | 0xFFFF_FFFF,
                                u64::from(D3D12_RESOURCE_STATE_COPY_SOURCE),
                            ],
                        });
                    }
                    let alt_valid = alt_dump.filter(|(ar, ad, _)| {
                        want_dump
                            && !ar.is_null()
                            && *ar != src_real_res
                            && ad.dimension == 3
                            && ad.sample_count <= 1
                            && ad.width > 0
                            && ad.height > 0
                    });
                    if let Some((alt_res, _, alt_state)) = alt_valid {
                        if alt_state != D3D12_RESOURCE_STATE_COPY_SOURCE {
                            pre.push(PresentBarrierRaw {
                                ty: 0,
                                flags: 0,
                                u: [
                                    alt_res as u64,
                                    ((u64::from(alt_state)) << 32) | 0xFFFF_FFFF,
                                    u64::from(D3D12_RESOURCE_STATE_COPY_SOURCE),
                                ],
                            });
                        }
                    }
                    if !pre.is_empty() {
                        unsafe { com_slot::<BarrierFn>(self.copy_list, 26)(self.copy_list, pre.len() as u32, pre.as_ptr()) };
                    }

                    if compatible {
                        let dst_loc = PresentCopyLocationRaw {
                            resource: dst_bb,
                            ty: 0,
                            _pad: 0,
                            payload: [0; 4],
                        };
                        let src_loc = PresentCopyLocationRaw {
                            resource: src_real_res,
                            ty: 0,
                            _pad: 0,
                            payload: [0; 4],
                        };
                        let cw = (d.width as u32).min(self.buf_w);
                        let ch = d.height.min(self.buf_h);
                        let src_box = [0u32, 0u32, 0u32, cw, ch, 1u32];
                        unsafe {
                            com_slot::<CopyTexRegFn>(self.copy_list, 16)(
                                self.copy_list,
                                &dst_loc,
                                0,
                                0,
                                0,
                                &src_loc,
                                &src_box,
                            );
                        }
                    }

                    if want_dump {
                        let mut enqueue_rb = |res: *mut c_void, rd: &ResourceDescRaw, tag: &'static str, write_ppm: bool| {
                            let clean_fmt = map_xbox_dxgi_format(rd.format);
                            let bpp = if clean_fmt == 10 { 8u32 } else { 4u32 };
                            let rw = (rd.width as u32).clamp(1, 3840);
                            let rh = rd.height.clamp(1, 2160);
                            let row_pitch = (rw * bpp).next_multiple_of(256);
                            let rb = unsafe {
                                create_readback_buffer(self.real_device, u64::from(row_pitch) * u64::from(rh))
                            };
                            if !rb.is_null() {
                                let rb_dst = PresentCopyLocationRaw {
                                    resource: rb,
                                    ty: 1,
                                    _pad: 0,
                                    payload: [
                                        0,
                                        u64::from(clean_fmt) | (u64::from(rw) << 32),
                                        u64::from(rh) | (1u64 << 32),
                                        u64::from(row_pitch),
                                    ],
                                };
                                let src_loc = PresentCopyLocationRaw {
                                    resource: res,
                                    ty: 0,
                                    _pad: 0,
                                    payload: [0; 4],
                                };
                                let src_box = [0u32, 0u32, 0u32, rw, rh, 1u32];
                                unsafe {
                                    com_slot::<CopyTexRegFn>(self.copy_list, 16)(
                                        self.copy_list,
                                        &rb_dst,
                                        0,
                                        0,
                                        0,
                                        &src_loc,
                                        &src_box,
                                    );
                                }
                                readbacks.push(ReadbackJob {
                                    rb,
                                    w: rw,
                                    h: rh,
                                    fmt: clean_fmt,
                                    row_pitch,
                                    tag,
                                    write_ppm,
                                });
                            }
                        };
                        enqueue_rb(src_real_res, d, "primary", true);
                        if let Some((alt_res, ref alt_desc, _)) = alt_valid {
                            enqueue_rb(alt_res, alt_desc, "secondary", false);
                        }
                    }

                    let mut post = Vec::with_capacity(3);
                    if !src_real_res.is_null() && src_cur_state != D3D12_RESOURCE_STATE_COPY_SOURCE {
                        post.push(PresentBarrierRaw {
                            ty: 0,
                            flags: 0,
                            u: [
                                src_real_res as u64,
                                ((u64::from(D3D12_RESOURCE_STATE_COPY_SOURCE)) << 32) | 0xFFFF_FFFF,
                                u64::from(src_cur_state),
                            ],
                        });
                    }
                    if let Some((alt_res, _, alt_state)) = alt_valid {
                        if alt_state != D3D12_RESOURCE_STATE_COPY_SOURCE {
                            post.push(PresentBarrierRaw {
                                ty: 0,
                                flags: 0,
                                u: [
                                    alt_res as u64,
                                    ((u64::from(D3D12_RESOURCE_STATE_COPY_SOURCE)) << 32) | 0xFFFF_FFFF,
                                    u64::from(alt_state),
                                ],
                            });
                        }
                    }
                    if compatible {
                        post.push(PresentBarrierRaw {
                            ty: 0,
                            flags: 0,
                            u: [
                                dst_bb as u64,
                                ((u64::from(D3D12_RESOURCE_STATE_COPY_DEST)) << 32) | 0xFFFF_FFFF,
                                u64::from(D3D12_RESOURCE_STATE_PRESENT),
                            ],
                        });
                    }
                    if !post.is_empty() {
                        unsafe { com_slot::<BarrierFn>(self.copy_list, 26)(self.copy_list, post.len() as u32, post.as_ptr()) };
                    }

                    if unsafe { com_slot::<CloseFn>(self.copy_list, 9)(self.copy_list) } >= 0 {
                        if !real_queue.is_null() {
                            self.fence_val += 1;
                            type SignalFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
                            let hr_sig = unsafe {
                                com_slot::<SignalFn>(real_queue, 14)(real_queue, self.copy_fence, self.fence_val)
                            };
                            if hr_sig >= 0 {
                                type WaitFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
                                let _ = unsafe {
                                    com_slot::<WaitFn>(self.present_queue, 15)(self.present_queue, self.copy_fence, self.fence_val)
                                };
                            }
                        }
                        unsafe { com_slot::<ExecFn>(self.present_queue, 10)(self.present_queue, 1, &self.copy_list) };
                        did_copy = compatible;
                        crate::com_proxy::drain_info_queue(self.info_queue, "PresentContext::Copy");
                    }
                }
            } else if !self.logged_skip {
                self.logged_skip = true;
                boot_trace(
                    "dx12xs_pc",
                    "PresentContext::copy_skipped",
                    &format!(
                        "dim={} size={}x{} fmt={} sc={} sc_fmt={} real_r0={src_real_res:?}",
                        d.dimension, d.width, d.height, d.format, d.sample_count, self.buf_fmt
                    ),
                );
            }
        }

        type PresentFn = unsafe extern "system" fn(*mut c_void, u32, u32) -> HRESULT;
        let hr = unsafe { com_slot::<PresentFn>(self.swapchain3, 8)(self.swapchain3, 0, 0) };
        crate::com_proxy::drain_info_queue(self.info_queue, "PresentContext::Present");
        if hr < 0 {
            let post_reason = crate::com_proxy::query_real_removed_reason(self.real_device);
            boot_trace_hr(
                "dx12xs_pc",
                "PresentContext::Present_err",
                hr,
                &format!("tick={tick} post_reason={:#010x}", post_reason as u32),
            );
        }

        if did_copy || !readbacks.is_empty() {
            self.fence_val += 1;
            type SignalFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
            let _ = unsafe { com_slot::<SignalFn>(self.present_queue, 14)(self.present_queue, self.copy_fence, self.fence_val) };
            if tick <= 4 || !readbacks.is_empty() {
                self.wait_fence_idle();
                if tick <= 4 {
                    let copy_reason = crate::com_proxy::query_real_removed_reason(self.real_device);
                    boot_trace_hr(
                        "dx12xs_pc",
                        "PresentContext::after_copy",
                        copy_reason,
                        &format!("tick={tick}"),
                    );
                }
            }
        }
        if !readbacks.is_empty() {
            self.last_dump_at = Some(Instant::now());
            self.dump_count += 1;
            if trigger_3d {
                self.dumped_3d_start = true;
            }
        }
        for job in readbacks {
            Self::dump_readback(&job, tick, hr);
            unsafe { real_release(job.rb) };
        }
        (hr, did_copy)
    }

    fn dump_readback(job: &ReadbackJob, tick: u64, sc_hr: HRESULT) {
        let (rb, w, h, fmt, row_pitch, tag, write_ppm) =
            (job.rb, job.w, job.h, job.fmt, job.row_pitch, job.tag, job.write_ppm);
        let draws = crate::com_proxy::gpu_draw_totals();
        let app_state = crate::read_app_state();
        let elapsed_s = PROCESS_START.elapsed().as_secs_f64();
        if app_state == Some(3) && elapsed_s >= 75.0 {
            crate::maybe_diag_advance_boot_stage();
        }
        type MapFn = unsafe extern "system" fn(*mut c_void, u32, *const [usize; 2], *mut *mut c_void) -> HRESULT;
        type UnmapFn = unsafe extern "system" fn(*mut c_void, u32, *const [usize; 2]);
        let total = row_pitch as usize * h as usize;
        let read_range = [0usize, total];
        let mut mapped: *mut c_void = std::ptr::null_mut();
        let hr_map = unsafe { com_slot::<MapFn>(rb, 8)(rb, 0, &read_range, &mut mapped) };
        if hr_map < 0 || mapped.is_null() {
            boot_trace_hr(
                "dx12xs_pc",
                "PresentContext::frame_stats",
                hr_map,
                &format!("tick={tick} elapsed_s={elapsed_s:.1}s tag={tag} draws={draws:?} sc_hr={sc_hr:#010x} map_failed"),
            );
            return;
        }
        let data = unsafe { std::slice::from_raw_parts(mapped.cast::<u8>(), total) };
        let (nz, center, quarter, ppm) = analyze_frame_pixels(data, w, h, row_pitch, fmt);
        let empty_range = [0usize, 0usize];
        unsafe { com_slot::<UnmapFn>(rb, 9)(rb, 0, &empty_range) };
        let mut written_info = String::new();
        if write_ppm {
            let _ = std::fs::create_dir_all(DUMP_DIR);
            let path = std::path::Path::new(DUMP_DIR).join(format!("frame_{tick}.ppm"));
            let write_ok = std::fs::write(&path, &ppm).is_ok();
            written_info = format!(" ppm={} written={write_ok}", path.display());
        }
        boot_trace(
            "dx12xs_pc",
            "PresentContext::frame_stats",
            &format!(
                "tick={tick} elapsed_s={elapsed_s:.1}s tag={tag} app_state={app_state:?} w={w} h={h} fmt={fmt} nonzero_px={nz} draws={draws:?} sc_hr={sc_hr:#010x} sample_rgba=[center={center:?} quarter={quarter:?}]{written_info}"
            ),
        );
    }

    #[cfg(test)]
    pub(crate) fn hwnd(&self) -> isize {
        self.hwnd
    }
}

impl Drop for PresentContext {
    fn drop(&mut self) {
        self.wait_fence_idle();
        unsafe {
            if !self.fence_event.is_null() {
                CloseHandle(self.fence_event);
            }
            real_release(self.copy_fence);
            real_release(self.copy_list);
            real_release(self.copy_alloc);
            for b in self.buffers {
                real_release(b);
            }
            real_release(self.swapchain3);
            real_release(self.present_queue);
        }
        self.stop_flag.store(true, Ordering::Release);
        unsafe { crate::overlay::post_null_message(self.hwnd) };
        if let Some(t) = self.pump_thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod frame_dump_tests {
    use super::{analyze_frame_pixels, should_dump_frame};

    #[test]
    fn should_dump_frame_honors_timers_3d_start_and_cap() {
        assert_eq!(should_dump_frame(false, 30.0, None, 0, (1, 1, 0, 0), false), (false, false));
        assert_eq!(should_dump_frame(true, 20.0, None, 0, (10, 0, 0, 0), false), (false, false));
        assert_eq!(should_dump_frame(true, 25.0, None, 0, (10, 0, 0, 0), false), (true, false));
        assert_eq!(should_dump_frame(true, 39.0, Some(14.0), 1, (10, 0, 0, 0), false), (false, false));
        assert_eq!(should_dump_frame(true, 40.0, Some(15.0), 1, (10, 0, 0, 0), false), (true, false));
        assert_eq!(should_dump_frame(true, 28.0, Some(3.0), 1, (10, 1, 0, 0), false), (true, true));
        assert_eq!(should_dump_frame(true, 29.0, Some(1.0), 2, (10, 2, 0, 0), true), (false, false));
        assert_eq!(should_dump_frame(true, 180.0, Some(20.0), 19, (10, 0, 0, 0), false), (true, false));
        assert_eq!(should_dump_frame(true, 320.0, Some(20.0), 20, (10, 2, 1, 0), false), (false, false));
    }

    #[test]
    fn analyze_frame_pixels_counts_nonzero_and_writes_downsampled_ppm() {
        let (w, h, row_pitch) = (8u32, 8u32, 256u32);
        let mut data = vec![0u8; (row_pitch * h) as usize];
        // BGRA (fmt=87) pixel at (4,4) = blue-ish: B=200, G=10, R=20, A=255.
        let off = (4 * row_pitch + 4 * 4) as usize;
        data[off..off + 4].copy_from_slice(&[200, 10, 20, 255]);
        // Pixel at (0,0) = pure red in BGRA.
        data[0..4].copy_from_slice(&[0, 0, 255, 255]);
        let (nz, center, _quarter, ppm) = analyze_frame_pixels(&data, w, h, row_pitch, 87);
        assert_eq!(nz, 2);
        assert_eq!(center, [20, 10, 200, 255]);
        let header = b"P6\n2 2\n255\n";
        assert!(ppm.starts_with(header));
        assert_eq!(ppm.len(), header.len() + 2 * 2 * 3);
        assert_eq!(&ppm[header.len()..header.len() + 3], &[255, 0, 0]);
        assert_eq!(&ppm[header.len() + 9..header.len() + 12], &[20, 10, 200]);
        assert_eq!(analyze_frame_pixels(&[], 0, 0, 0, 28).0, 0);
    }
}
