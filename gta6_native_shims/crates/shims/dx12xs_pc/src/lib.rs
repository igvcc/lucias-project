#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod com_proxy;
pub mod dxpk;
pub mod overlay;
pub mod presenter;

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex, Once, OnceLock};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use shim_common::{E_FAIL, E_INVALIDARG, E_POINTER, Guid, HRESULT, S_OK, boot_trace, boot_trace_hr};

static PANIC_HOOK_INIT: Once = Once::new();
static DEV_ASSERT_VEH_INIT: Once = Once::new();
static MAIN_EXE_BASE: AtomicUsize = AtomicUsize::new(0);

const EXCEPTION_BREAKPOINT_CODE: u32 = 0x8000_0003;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const X64_CONTEXT_RSP_OFFSET: usize = 0x98;
const X64_CONTEXT_RIP_OFFSET: usize = 0xF8;
const MAIN_EXE_IMAGE_SPAN: usize = 0x0B06_D000;
const NONFATAL_DEV_ASSERT_RVAS: &[usize] = &[0x04DC_BC9D];

#[repr(C)]
struct ExceptionRecordRaw {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut c_void,
    exception_address: *mut c_void,
}

#[repr(C)]
struct ExceptionPointersRaw {
    exception_record: *mut ExceptionRecordRaw,
    context_record: *mut u8,
}

#[cfg(windows)]
extern "system" {
    fn AddVectoredExceptionHandler(
        first: u32,
        handler: Option<unsafe extern "system" fn(*mut ExceptionPointersRaw) -> i32>,
    ) -> *mut c_void;
}

pub(crate) fn is_allowlisted_dev_assert_rva(rva: usize) -> bool {
    NONFATAL_DEV_ASSERT_RVAS.contains(&rva)
}

fn scan_stack_rvas(rsp: usize, base: usize) -> Vec<usize> {
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQuery};
    if rsp == 0 || base == 0 {
        return Vec::new();
    }
    let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    let q = unsafe { VirtualQuery(rsp as *const c_void, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
    if q == 0 || mbi.State != MEM_COMMIT {
        return Vec::new();
    }
    let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
    let max_end = rsp.saturating_add(96 * 8).min(region_end);
    let image_end = base.saturating_add(MAIN_EXE_IMAGE_SPAN);
    let mut rvas = Vec::with_capacity(10);
    let mut cur = rsp;
    let mut prev = usize::MAX;
    while cur.saturating_add(8) <= max_end && rvas.len() < 10 {
        let val = unsafe { (cur as *const usize).read_unaligned() };
        if val >= base && val < image_end {
            let rva = val - base;
            if rva != prev && !rvas.contains(&rva) {
                rvas.push(rva);
                prev = rva;
            }
        }
        cur += 8;
    }
    rvas
}

unsafe extern "system" fn dev_assert_veh(info: *mut ExceptionPointersRaw) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = unsafe { (*info).exception_record };
    let ctx = unsafe { (*info).context_record };
    if rec.is_null() || ctx.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if unsafe { (*rec).exception_code } != EXCEPTION_BREAKPOINT_CODE {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let addr = unsafe { (*rec).exception_address } as usize;
    let base = MAIN_EXE_BASE.load(Ordering::Relaxed);
    if base == 0 || addr <= base {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rva = addr - base;
    if is_allowlisted_dev_assert_rva(rva) && unsafe { *(addr as *const u8) } == 0xCC {
        unsafe {
            ctx.add(X64_CONTEXT_RIP_OFFSET)
                .cast::<u64>()
                .write_unaligned((addr + 1) as u64);
        }
        static SKIP_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = SKIP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 4 || n == 16 || n == 64 || n == 128 || n == 256 || n.is_multiple_of(200) {
            let mut msg = format!("#{n} rva={rva:#x} rip->{:#x}", addr + 1);
            if matches!(n, 1 | 2 | 16 | 64 | 200) {
                let rsp = unsafe { ctx.add(X64_CONTEXT_RSP_OFFSET).cast::<u64>().read_unaligned() } as usize;
                let rvas = scan_stack_rvas(rsp, base);
                let joined = rvas
                    .iter()
                    .map(|r| format!("{r:#x}"))
                    .collect::<Vec<_>>()
                    .join(",");
                use std::fmt::Write;
                let _ = write!(&mut msg, " stack_rvas=[{joined}]");
            }
            boot_trace("dx12xs_pc", "DevAssert::skip", &msg);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

pub(crate) fn install_dev_assert_veh() {
    DEV_ASSERT_VEH_INIT.call_once(|| {
        let base = unsafe { GetModuleHandleW(std::ptr::null()) as usize };
        MAIN_EXE_BASE.store(base, Ordering::Relaxed);
        #[cfg(windows)]
        unsafe {
            AddVectoredExceptionHandler(1, Some(dev_assert_veh));
        }
    });
}

pub(crate) fn install_panic_hook() {
    install_dev_assert_veh();
    PANIC_HOOK_INIT.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let loc = info
                .location()
                .map_or_else(|| "unknown".to_string(), |l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic>");
            boot_trace("dx12xs_pc", "PANIC", &format!("loc={loc} msg={payload}"));
            prev(info);
        }));
    });
}
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, LoadLibraryW,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

/// `ID3D12Device` GUID `{189819f1-1db6-4b57-be54-1821339b85f7}`.
pub const IID_ID3D12DEVICE: Guid = Guid::new(
    0x1898_19f1,
    0x1db6,
    0x4b57,
    [0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7],
);

/// `ID3D12Device11` GUID `{5405c344-d457-444e-b4dd-2366e45aee39}`.
pub const IID_ID3D12DEVICE11: Guid = Guid::new(
    0x5405_c344,
    0xd457,
    0x444e,
    [0xb4, 0xdd, 0x23, 0x66, 0xe4, 0x5a, 0xee, 0x39],
);

/// D3D_FEATURE_LEVEL_12_0 = 0xC000
const D3D_FEATURE_LEVEL_12_0: u32 = 0xC000;
/// Xbox Scarlett console-only root signature flags occupy bits 24..=31.
const XBOX_ROOT_SIGNATURE_FLAGS_MASK: u32 = 0xFF00_0000;

/// Console `D3D12XBOX_CREATE_DEVICE_PARAMETERS` (`0x50` bytes per RVA analysis:
/// `version=0x20004`, `scratch=0x100000`, `flags@0x3c=0x20`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct D3D12XboxCreateDeviceParams {
    pub version: u32,
    pub device_flags: u32,
    pub p_scratch_buffer: *mut c_void,
    pub scratch_buffer_size: usize,
    pub ring_buffer_size: u64,
    pub command_allocator_size: u64,
    pub reserved_28: [u64; 2],
    pub reserved_38: u32,
    pub flags_3c: u32,
    pub reserved_40: [u64; 2],
}

const _: () = assert!(size_of::<D3D12XboxCreateDeviceParams>() == 0x50);

/// Console `D3D12XBOX_VIRTUAL_MEMORY_CONFIGURATION` (`0x20` bytes per binary analysis).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12XboxVirtualMemoryConfig {
    pub flags: u32,
    pub reserved: u32,
    pub title_va_size: u64,
    pub system_va_size: u64,
    pub extra: u64,
}

const _: () = assert!(size_of::<D3D12XboxVirtualMemoryConfig>() == 0x20);

/// PC `D3D12_ROOT_SIGNATURE_DESC` / `D3D12_ROOT_SIGNATURE_DESC1` header layout on Win64.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct D3D12RootSigDescCommon {
    pub(crate) num_parameters: u32,
    pub(crate) _pad0: u32,
    pub(crate) parameters: *const c_void,
    pub(crate) num_static_samplers: u32,
    pub(crate) _pad1: u32,
    pub(crate) static_samplers: *const c_void,
    pub(crate) flags: u32,
    pub(crate) _pad2: u32,
}

/// PC `D3D12_VERSIONED_ROOT_SIGNATURE_DESC` layout on Win64 (`0x30` bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct D3D12VersionedRootSigDesc {
    pub(crate) version: u32,
    pub(crate) _pad: u32,
    pub(crate) desc: D3D12RootSigDescCommon,
}

const _: () = assert!(size_of::<D3D12VersionedRootSigDesc>() == 0x30);

static LAST_VM_FLAGS: AtomicU32 = AtomicU32::new(0);
static LAST_VM_TITLE_BYTES: AtomicU64 = AtomicU64::new(0);
static LAST_VM_SYSTEM_BYTES: AtomicU64 = AtomicU64::new(0);
static LAST_VM_EXTRA: AtomicU64 = AtomicU64::new(0);

static LAST_DEV_VERSION: AtomicU32 = AtomicU32::new(0);
static LAST_DEV_SCRATCH_BYTES: AtomicU64 = AtomicU64::new(0);
static LAST_DEV_FLAGS_3C: AtomicU32 = AtomicU32::new(0);

static D3D12_MODULE: OnceLock<usize> = OnceLock::new();

const IID_ID3D12DEBUG: Guid = Guid::new(
    0x3444_88b7,
    0x6846,
    0x474b,
    [0xb9, 0x89, 0xf0, 0x27, 0x44, 0x82, 0x45, 0xe0],
);

fn d3d12_debug_enabled() -> bool {
    std::env::var("LUCIAS_D3D12_DEBUG")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn maybe_enable_debug_layer(d3d12: HMODULE) {
    if !d3d12_debug_enabled() {
        return;
    }
    let Some(proc_fn) = (unsafe { GetProcAddress(d3d12, c"D3D12GetDebugInterface".as_ptr().cast()) })
    else {
        boot_trace_hr("dx12xs_pc", "D3D12GetDebugInterface", E_FAIL, "missing export");
        return;
    };
    type GetDebugFn = unsafe extern "system" fn(*const Guid, *mut *mut c_void) -> HRESULT;
    let get_debug: GetDebugFn = unsafe { std::mem::transmute(proc_fn) };
    let mut dbg: *mut c_void = std::ptr::null_mut();
    let hr = unsafe { get_debug(&IID_ID3D12DEBUG, &mut dbg) };
    if hr >= 0 && !dbg.is_null() {
        let vtbl = unsafe { *dbg.cast::<*const *const c_void>() };
        type EnableFn = unsafe extern "system" fn(*mut c_void);
        type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let enable: EnableFn = unsafe { std::mem::transmute(*vtbl.add(3)) };
        let release: RelFn = unsafe { std::mem::transmute(*vtbl.add(2)) };
        unsafe {
            enable(dbg);
            release(dbg);
        }
        boot_trace_hr("dx12xs_pc", "D3D12GetDebugInterface", S_OK, "EnableDebugLayer active");
    } else {
        boot_trace_hr("dx12xs_pc", "D3D12GetDebugInterface", hr, "debug layer unavailable");
    }
}

fn host_d3d12() -> HMODULE {
    let addr = *D3D12_MODULE.get_or_init(|| {
        let name: Vec<u16> = "d3d12.dll\0".encode_utf16().collect();
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

pub fn recorded_vm_config() -> D3D12XboxVirtualMemoryConfig {
    D3D12XboxVirtualMemoryConfig {
        flags: LAST_VM_FLAGS.load(Ordering::Relaxed),
        reserved: 0,
        title_va_size: LAST_VM_TITLE_BYTES.load(Ordering::Relaxed),
        system_va_size: LAST_VM_SYSTEM_BYTES.load(Ordering::Relaxed),
        extra: LAST_VM_EXTRA.load(Ordering::Relaxed),
    }
}

pub fn recorded_device_params() -> (u32, u64, u32) {
    (
        LAST_DEV_VERSION.load(Ordering::Relaxed),
        LAST_DEV_SCRATCH_BYTES.load(Ordering::Relaxed),
        LAST_DEV_FLAGS_3C.load(Ordering::Relaxed),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn D3D12ConfigureVirtualMemoryX(
    config: *mut D3D12XboxVirtualMemoryConfig,
) -> HRESULT {
    install_panic_hook();
    let Some(cfg) = (unsafe { config.as_mut() }) else {
        return E_INVALIDARG;
    };
    LAST_VM_FLAGS.store(cfg.flags, Ordering::Relaxed);
    LAST_VM_TITLE_BYTES.store(cfg.title_va_size, Ordering::Relaxed);
    LAST_VM_SYSTEM_BYTES.store(cfg.system_va_size, Ordering::Relaxed);
    LAST_VM_EXTRA.store(cfg.extra, Ordering::Relaxed);
    // On Scarlett (`D3D12XBOX_VIRTUAL_MEMORY_CONFIGURATION`), offsets +0x10 and +0x18
    // (`system_va_size` / `extra` in our 0x20-byte struct) are OUT lowest/highest user VA bounds.
    if cfg.system_va_size == 0 && cfg.extra == 0 {
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        cfg.system_va_size = info.lpMinimumApplicationAddress as u64;
        cfg.extra = info.lpMaximumApplicationAddress as u64;
    }
    boot_trace_hr(
        "dx12xs_pc",
        "D3D12ConfigureVirtualMemoryX",
        S_OK,
        &format!(
            "flags={:#x} pages_or_va={:#x} low={:#x} high={:#x}",
            cfg.flags, cfg.title_va_size, cfg.system_va_size, cfg.extra
        ),
    );
    S_OK
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SyntheticRootSlots {
    pub b0_slot: Option<u32>,
    pub t255_s1_slot: Option<u32>,
}

static SYNTHETIC_RS_BLOBS: LazyLock<Mutex<HashMap<(usize, usize), SyntheticRootSlots>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LOGGED_UNIQUE_RS: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub(crate) fn take_synthetic_slots_for_blob(
    ptr: *const c_void,
    len: usize,
) -> Option<SyntheticRootSlots> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    SYNTHETIC_RS_BLOBS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(ptr as usize, len))
}

struct RootSigSummary {
    summary: String,
    has_b0_space0: bool,
    has_t255_space1: bool,
    present_s0_7_mask: u8,
    dword_cost: u32,
}

fn summarize_root_sig(raw_desc: &D3D12VersionedRootSigDesc) -> RootSigSummary {
    let mut summary = String::new();
    let mut has_b0_space0 = false;
    let mut has_t255_space1 = false;
    let mut present_s0_7_mask = 0u8;
    let mut dword_cost = 0u32;
    if !raw_desc.desc.parameters.is_null() && raw_desc.desc.num_parameters > 0 {
        let total = raw_desc.desc.num_parameters as usize;
        for i in 0..total.min(64) {
            let p = unsafe { raw_desc.desc.parameters.cast::<[u32; 8]>().add(i).read_unaligned() };
            let ty = p[0];
            let vis = p[6];
            match ty {
                0 => {
                    dword_cost = dword_cost.saturating_add(1);
                    let num_ranges = p[2];
                    let ranges_ptr = u64::from(p[4]) | (u64::from(p[5]) << 32);
                    let mut r_desc = String::new();
                    if ranges_ptr != 0 && num_ranges > 0 {
                        let ptr_u8 = ranges_ptr as *const u8;
                        let stride = if raw_desc.version >= 2 { 24usize } else { 20usize };
                        for r in 0..(num_ranges as usize).min(64) {
                            let rp = unsafe { ptr_u8.add(r * stride).cast::<[u32; 5]>().read_unaligned() };
                            let (rt, nd, br, sp) = (rp[0], rp[1], rp[2], rp[3]);
                            if rt == 2 && sp == 0 && br == 0 && nd >= 1 {
                                has_b0_space0 = true;
                            }
                            if rt == 0
                                && sp == 1
                                && br <= 255
                                && nd >= 1
                                && (nd == u32::MAX || br.saturating_add(nd) > 255)
                            {
                                has_t255_space1 = true;
                            }
                            if rt == 3 && sp == 0 && br < 8 && nd >= 1 {
                                let end = br.saturating_add(nd).min(8);
                                for reg in br..end {
                                    present_s0_7_mask |= 1u8 << reg;
                                }
                            }
                            if i < 12 && r < 4 {
                                if !r_desc.is_empty() {
                                    r_desc.push(';');
                                }
                                let rty = match rt {
                                    0 => "SRV",
                                    1 => "UAV",
                                    2 => "CBV",
                                    3 => "SMP",
                                    _ => "?",
                                };
                                r_desc.push_str(&format!("{rty} r{br}+{nd:#x} s{sp}"));
                            }
                        }
                    }
                    if i < 12 {
                        if !summary.is_empty() {
                            summary.push(',');
                        }
                        summary.push_str(&format!("p{i}(TBL n={num_ranges} [{r_desc}] v={vis})"));
                    }
                }
                1 => {
                    let (reg, sp, cnt) = (p[2], p[3], p[4]);
                    dword_cost = dword_cost.saturating_add(cnt);
                    if sp == 0 && reg == 0 && cnt > 0 {
                        has_b0_space0 = true;
                    }
                    if i < 12 {
                        if !summary.is_empty() {
                            summary.push(',');
                        }
                        summary.push_str(&format!("p{i}(CONST b{reg} s{sp} x{cnt} v={vis})"));
                    }
                }
                2..=4 => {
                    let (reg, sp, flg) = (p[2], p[3], p[4]);
                    dword_cost = dword_cost.saturating_add(2);
                    if ty == 2 && sp == 0 && reg == 0 {
                        has_b0_space0 = true;
                    }
                    if ty == 3 && sp == 1 && reg == 255 {
                        has_t255_space1 = true;
                    }
                    if i < 12 {
                        if !summary.is_empty() {
                            summary.push(',');
                        }
                        let k = match ty {
                            2 => "CBV",
                            3 => "SRV",
                            _ => "UAV",
                        };
                        summary.push_str(&format!("p{i}({k} r{reg} s{sp} f={flg:#x} v={vis})"));
                    }
                }
                _ => {
                    dword_cost = dword_cost.saturating_add(2);
                }
            }
        }
    }
    if (raw_desc.version == 1 || raw_desc.version == 2)
        && raw_desc.desc.num_static_samplers > 0
        && !raw_desc.desc.static_samplers.is_null()
    {
        let n = (raw_desc.desc.num_static_samplers as usize).min(128);
        for s in 0..n {
            let ss = unsafe {
                raw_desc
                    .desc
                    .static_samplers
                    .cast::<[u32; 13]>()
                    .add(s)
                    .read_unaligned()
            };
            if ss[11] == 0 && ss[10] < 8 {
                present_s0_7_mask |= 1u8 << ss[10];
            }
        }
    }
    RootSigSummary {
        summary,
        has_b0_space0,
        has_t255_space1,
        present_s0_7_mask,
        dword_cost,
    }
}

pub(crate) fn needs_synthetic_rs_injection(raw_desc: &D3D12VersionedRootSigDesc) -> bool {
    if (raw_desc.desc.flags & 0x40) != 0 || (raw_desc.version != 1 && raw_desc.version != 2) {
        return false;
    }
    let s = summarize_root_sig(raw_desc);
    (!s.has_b0_space0 && s.dword_cost.saturating_add(2) <= 64)
        || (!s.has_t255_space1 && s.dword_cost.saturating_add(2) <= 64)
        || s.present_s0_7_mask != 0xFF
}

pub(crate) fn log_unique_root_sig(
    ctx: &str,
    raw_desc: &D3D12VersionedRootSigDesc,
    slots: SyntheticRootSlots,
    added_samplers: u32,
) {
    let s = summarize_root_sig(raw_desc);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in s.summary.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h ^= u64::from(raw_desc.desc.flags) << 32 | u64::from(raw_desc.desc.num_static_samplers);
    let mut set = LOGGED_UNIQUE_RS.lock().unwrap_or_else(|e| e.into_inner());
    if set.len() < 8 && set.insert(h) {
        boot_trace(
            "dx12xs_pc",
            "RootSigLayout",
            &format!(
                "ctx={ctx} ver={} params={} samplers={} flags={:#x} dwords={} has_b0={} has_t255={} s0_7_mask={:#04x} synth_b0={:?} synth_t255={:?} synth_s={added_samplers} [{}]",
                raw_desc.version,
                raw_desc.desc.num_parameters,
                raw_desc.desc.num_static_samplers,
                raw_desc.desc.flags,
                s.dword_cost,
                s.has_b0_space0,
                s.has_t255_space1,
                s.present_s0_7_mask,
                slots.b0_slot,
                slots.t255_s1_slot,
                s.summary,
            ),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn D3D12SerializeVersionedRootSignature(
    root_sig_desc: *const c_void,
    blob_out: *mut *mut c_void,
    error_blob_out: *mut *mut c_void,
) -> HRESULT {
    if blob_out.is_null() {
        return E_POINTER;
    }
    let Some(raw_desc) = (unsafe { root_sig_desc.cast::<D3D12VersionedRootSigDesc>().as_ref() })
    else {
        return E_INVALIDARG;
    };
    let d3d12 = host_d3d12();
    if d3d12.is_null() {
        return E_FAIL;
    }
    let Some(proc_fn) = (unsafe {
        GetProcAddress(
            d3d12,
            c"D3D12SerializeVersionedRootSignature".as_ptr().cast(),
        )
    }) else {
        return E_FAIL;
    };

    // Strip Xbox-specific root signature flags (bits 24..=31) without mutating caller memory,
    // and enable SM 6.6 ResourceDescriptorHeap/SamplerDescriptorHeap indexing (0xC00) for DXPK shaders.
    let mut sanitized = *raw_desc;
    sanitized.desc.flags &= !XBOX_ROOT_SIGNATURE_FLAGS_MASK;
    if (sanitized.desc.flags & 0x40) == 0 {
        sanitized.desc.flags |= 0xC00;
    }

    let rs_summary = summarize_root_sig(raw_desc);
    let mut patched_params: Vec<[u32; 8]> = Vec::new();
    let mut added_slots = SyntheticRootSlots::default();
    let orig_num_params = raw_desc.desc.num_parameters;
    let can_patch_params = (sanitized.desc.flags & 0x40) == 0
        && (sanitized.version == 1 || sanitized.version == 2)
        && (orig_num_params == 0 || !raw_desc.desc.parameters.is_null());
    if can_patch_params && ((!rs_summary.has_b0_space0 || !rs_summary.has_t255_space1) && rs_summary.dword_cost.saturating_add(2) <= 64) {
        patched_params.reserve(orig_num_params as usize + 2);
        for i in 0..(orig_num_params as usize) {
            patched_params.push(unsafe {
                raw_desc.desc.parameters.cast::<[u32; 8]>().add(i).read_unaligned()
            });
        }
        let desc_flags = if sanitized.version >= 2 { 0x2 } else { 0 };
        let mut cur_dwords = rs_summary.dword_cost;
        // Append Root CBV(b0, space=0, DATA_VOLATILE, VISIBILITY_ALL) when absent.
        if !rs_summary.has_b0_space0 && cur_dwords.saturating_add(2) <= 64 {
            let slot = patched_params.len() as u32;
            patched_params.push([2, 0, 0, 0, desc_flags, 0, 0, 0]);
            cur_dwords += 2;
            added_slots.b0_slot = Some(slot);
        }
        // Append Root SRV(t255, space=1, DATA_VOLATILE, VISIBILITY_ALL) for DXPK SLOT_STRIDES when absent.
        if !rs_summary.has_t255_space1 && cur_dwords.saturating_add(2) <= 64 {
            let slot = patched_params.len() as u32;
            patched_params.push([3, 0, 255, 1, desc_flags, 0, 0, 0]);
            added_slots.t255_s1_slot = Some(slot);
        }
        if !patched_params.is_empty() && (added_slots.b0_slot.is_some() || added_slots.t255_s1_slot.is_some()) {
            sanitized.desc.num_parameters = patched_params.len() as u32;
            sanitized.desc.parameters = patched_params.as_ptr().cast();
        }
    }

    let mut patched_samplers: Vec<[u32; 13]> = Vec::new();
    let mut added_samplers = 0u32;
    let orig_num_samplers = raw_desc.desc.num_static_samplers;
    if rs_summary.present_s0_7_mask != 0xFF
        && (sanitized.desc.flags & 0x40) == 0
        && (sanitized.version == 1 || sanitized.version == 2)
        && (orig_num_samplers == 0 || !raw_desc.desc.static_samplers.is_null())
    {
        let missing = (!rs_summary.present_s0_7_mask).count_ones() as usize;
        patched_samplers.reserve(orig_num_samplers as usize + missing);
        for i in 0..(orig_num_samplers as usize) {
            patched_samplers.push(unsafe {
                raw_desc
                    .desc
                    .static_samplers
                    .cast::<[u32; 13]>()
                    .add(i)
                    .read_unaligned()
            });
        }
        // Static samplers for missing s0..s7, space=0 (VISIBILITY_ALL) cost 0 root DWORDs.
        for reg in 0u32..8 {
            if (rs_summary.present_s0_7_mask & (1u8 << reg)) == 0 {
                patched_samplers.push([0x15, 3, 3, 3, 0, 1, 1, 0, 0, 0x7F7F_FFFF, reg, 0, 0]);
                added_samplers += 1;
            }
        }
        sanitized.desc.num_static_samplers = orig_num_samplers + added_samplers;
        sanitized.desc.static_samplers = patched_samplers.as_ptr().cast();
    }

    type FnTy = extern "system" fn(
        *const D3D12VersionedRootSigDesc,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT;
    let f: FnTy = unsafe { std::mem::transmute(proc_fn) };
    let mut hr = f(&sanitized, blob_out, error_blob_out);
    if hr < 0 && added_samplers > 0 {
        sanitized.desc.num_static_samplers = raw_desc.desc.num_static_samplers;
        sanitized.desc.static_samplers = raw_desc.desc.static_samplers;
        added_samplers = 0;
        hr = f(&sanitized, blob_out, error_blob_out);
    }
    if hr < 0 && added_slots.t255_s1_slot.is_some() {
        patched_params.pop();
        added_slots.t255_s1_slot = None;
        if added_slots.b0_slot.is_some() {
            sanitized.desc.num_parameters = patched_params.len() as u32;
            sanitized.desc.parameters = patched_params.as_ptr().cast();
        } else {
            sanitized.desc.num_parameters = raw_desc.desc.num_parameters;
            sanitized.desc.parameters = raw_desc.desc.parameters;
        }
        hr = f(&sanitized, blob_out, error_blob_out);
    }
    if hr < 0 && added_slots.b0_slot.is_some() {
        sanitized.desc.num_parameters = raw_desc.desc.num_parameters;
        sanitized.desc.parameters = raw_desc.desc.parameters;
        added_slots.b0_slot = None;
        hr = f(&sanitized, blob_out, error_blob_out);
    }
    log_unique_root_sig("D3D12SerializeVersionedRootSignature", raw_desc, added_slots, added_samplers);

    let (blob_ptr, blob_len) = if hr >= 0 {
        let blob = unsafe { *blob_out };
        if !blob.is_null() {
            let vtbl = unsafe { *blob.cast::<*const *const c_void>() };
            type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
            type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
            let get_ptr: GetPtrFn = unsafe { std::mem::transmute(*vtbl.add(3)) };
            let get_sz: GetSzFn = unsafe { std::mem::transmute(*vtbl.add(4)) };
            let (p, l) = (unsafe { get_ptr(blob) }, unsafe { get_sz(blob) });
            if (added_slots.b0_slot.is_some() || added_slots.t255_s1_slot.is_some())
                && !p.is_null()
                && l > 0
            {
                let mut map = SYNTHETIC_RS_BLOBS.lock().unwrap_or_else(|e| e.into_inner());
                if map.len() > 4096 {
                    map.clear();
                }
                map.insert((p as usize, l), added_slots);
            }
            (p, l)
        } else {
            (std::ptr::null(), 0)
        }
    } else {
        (std::ptr::null(), 0)
    };
    boot_trace_hr(
        "dx12xs_pc",
        "D3D12SerializeVersionedRootSignature",
        hr,
        &format!(
            "ver={} params={}->{} [{}] samplers={}->{} raw_flags={:#x} clean_flags={:#x} synth_b0={:?} synth_t255={:?} synth_s={added_samplers} blob={blob_ptr:?} len={blob_len}",
            raw_desc.version,
            raw_desc.desc.num_parameters,
            sanitized.desc.num_parameters,
            rs_summary.summary,
            raw_desc.desc.num_static_samplers,
            sanitized.desc.num_static_samplers,
            raw_desc.desc.flags,
            sanitized.desc.flags,
            added_slots.b0_slot,
            added_slots.t255_s1_slot
        ),
    );
    hr
}

/// Calls `IUnknown::QueryInterface` (slot 0) and `Release` (slot 2) on a COM object.
unsafe fn com_query_and_release(
    obj: *mut c_void,
    target_iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    let vtbl = unsafe { *obj.cast::<*const *const c_void>() };
    type QiFn = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> HRESULT;
    type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
    let qi: QiFn = unsafe { std::mem::transmute(*vtbl) };
    let release: RelFn = unsafe { std::mem::transmute(*vtbl.add(2)) };
    let hr = unsafe { qi(obj, target_iid, out) };
    unsafe { release(obj) };
    hr
}

#[unsafe(no_mangle)]
pub extern "system" fn D3D12XboxCreateDevice(
    adapter: *mut c_void,
    params: *const D3D12XboxCreateDeviceParams,
    iid: *const Guid,
    device_out: *mut *mut c_void,
) -> HRESULT {
    install_panic_hook();
    if device_out.is_null() {
        return E_POINTER;
    }
    let Some(req_iid) = (unsafe { iid.as_ref() }) else {
        return E_INVALIDARG;
    };

    if let Some(p) = unsafe { params.as_ref() } {
        LAST_DEV_VERSION.store(p.version, Ordering::Relaxed);
        LAST_DEV_SCRATCH_BYTES.store(p.scratch_buffer_size as u64, Ordering::Relaxed);
        LAST_DEV_FLAGS_3C.store(p.flags_3c, Ordering::Relaxed);
    }

    let d3d12 = host_d3d12();
    if d3d12.is_null() {
        return E_FAIL;
    }
    maybe_enable_debug_layer(d3d12);
    let Some(proc_fn) = (unsafe { GetProcAddress(d3d12, c"D3D12CreateDevice".as_ptr().cast()) })
    else {
        return E_FAIL;
    };

    type CreateDevFn =
        extern "system" fn(*mut c_void, u32, *const Guid, *mut *mut c_void) -> HRESULT;
    let create_dev: CreateDevFn = unsafe { std::mem::transmute(proc_fn) };

    let mut real_dev: *mut c_void = std::ptr::null_mut();
    let mut hr = create_dev(adapter, D3D_FEATURE_LEVEL_12_0, iid, &mut real_dev);
    if hr < 0 {
        let mut base_dev: *mut c_void = std::ptr::null_mut();
        let base_hr = create_dev(adapter, D3D_FEATURE_LEVEL_12_0, &IID_ID3D12DEVICE, &mut base_dev);
        if base_hr >= 0 && !base_dev.is_null() {
            hr = unsafe { com_query_and_release(base_dev, iid, &mut real_dev) };
        }
    }

    if hr >= 0 && !real_dev.is_null() {
        let wrapped = com_proxy::wrap_xbox_device(real_dev, req_iid);
        unsafe { *device_out = wrapped };
        boot_trace_hr(
            "dx12xs_pc",
            "D3D12XboxCreateDevice",
            S_OK,
            &format!("iid={} wrapped={wrapped:?}", req_iid.format_guid()),
        );
        S_OK
    } else {
        boot_trace_hr(
            "dx12xs_pc",
            "D3D12XboxCreateDevice",
            hr,
            &format!("iid={}", req_iid.format_guid()),
        );
        hr
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn LuciasOverlayAttachWindow(hwnd: *mut c_void) -> HRESULT {
    shim_common::telemetry::set_target_hwnd(hwnd as usize);
    overlay::ensure_started();
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn LuciasOverlayTick() -> HRESULT {
    shim_common::telemetry::record_frame_present();
    overlay::notify_present_tick();
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn LuciasOverlayToggle() -> u32 {
    u32::from(shim_common::telemetry::toggle_overlay_visible())
}

#[unsafe(no_mangle)]
pub extern "system" fn LuciasOverlayRecordShaderError(
    hash: u64,
    stage: *const i8,
    hr: HRESULT,
) -> HRESULT {
    let stage_str = if stage.is_null() {
        "PSO"
    } else {
        unsafe { std::ffi::CStr::from_ptr(stage) }
            .to_str()
            .unwrap_or("PSO")
    };
    shim_common::telemetry::record_shader_error(hash, stage_str, hr);
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn LuciasOverlayShutdown() -> HRESULT {
    overlay::shutdown();
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_vm_config_and_device_params() {
        let mut cfg = D3D12XboxVirtualMemoryConfig {
            flags: 0x3,
            reserved: 0,
            title_va_size: 4 * 1024 * 1024 * 1024,
            system_va_size: 512 * 1024 * 1024,
            extra: 0x42,
        };
        assert_eq!(D3D12ConfigureVirtualMemoryX(&mut cfg), S_OK);
        assert_eq!(recorded_vm_config(), cfg);

        let mut query_cfg = D3D12XboxVirtualMemoryConfig::default();
        assert_eq!(D3D12ConfigureVirtualMemoryX(&mut query_cfg), S_OK);
        assert!(query_cfg.system_va_size > 0 && query_cfg.extra > query_cfg.system_va_size);
    }

    #[test]
    fn xbox_device_params_layout_matches_rva_spec() {
        assert_eq!(std::mem::offset_of!(D3D12XboxCreateDeviceParams, flags_3c), 0x3C);
        assert_eq!(size_of::<D3D12XboxCreateDeviceParams>(), 0x50);
    }

    #[test]
    fn root_signature_serialization_strips_xbox_flags() {
        shim_common::telemetry::use_temp_telemetry_json_for_tests();
        let desc = D3D12VersionedRootSigDesc {
            version: 2, // D3D_ROOT_SIGNATURE_VERSION_1_1
            _pad: 0,
            desc: D3D12RootSigDescCommon {
                num_parameters: 0,
                _pad0: 0,
                parameters: std::ptr::null(),
                num_static_samplers: 0,
                _pad1: 0,
                static_samplers: std::ptr::null(),
                flags: 0xFF00_0C00, // Xbox-only upper bits + SM 6.6 directly indexed flags (0xC00)
                _pad2: 0,
            },
        };
        let mut blob: *mut c_void = std::ptr::null_mut();
        let mut err: *mut c_void = std::ptr::null_mut();
        let hr = D3D12SerializeVersionedRootSignature(
            (&raw const desc).cast(),
            &mut blob,
            &mut err,
        );
        assert_eq!(hr, S_OK, "expected masked root signature serialization to succeed");
        assert!(!blob.is_null());
        unsafe {
            let vtbl = *blob.cast::<*const *const c_void>();
            type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
            type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let get_ptr: GetPtrFn = std::mem::transmute(*vtbl.add(3));
            let get_sz: GetSzFn = std::mem::transmute(*vtbl.add(4));
            let rel: RelFn = std::mem::transmute(*vtbl.add(2));
            let ptr = get_ptr(blob);
            let sz = get_sz(blob);
            assert!(!ptr.is_null() && sz > 0);

            // Also verify CreateRootSignature with 0xC00 flags succeeds on the host D3D12 device!
            let params = D3D12XboxCreateDeviceParams {
                version: 0x20004,
                device_flags: 0,
                p_scratch_buffer: std::ptr::null_mut(),
                scratch_buffer_size: 0x10_0000,
                ring_buffer_size: 0,
                command_allocator_size: 0,
                reserved_28: [0; 2],
                reserved_38: 0,
                flags_3c: 0x20,
                reserved_40: [0; 2],
            };
            let mut dev = std::ptr::null_mut();
            assert_eq!(D3D12XboxCreateDevice(std::ptr::null_mut(), &params, &IID_ID3D12DEVICE11, &mut dev), S_OK);
            let d_vtbl = *dev.cast::<*const *const c_void>();
            type CreateRsFn = unsafe extern "system" fn(*mut c_void, u32, *const c_void, usize, *const Guid, *mut *mut c_void) -> HRESULT;
            let create_rs: CreateRsFn = std::mem::transmute(*d_vtbl.add(16));
            let iid_rs = Guid::new(0xc54a_6b66, 0x72df, 0x4ee8, [0x8b, 0xe5, 0xa9, 0x46, 0xa1, 0x42, 0x92, 0x14]);
            let mut rs_obj = std::ptr::null_mut();
            let rs_hr = create_rs(dev, 1, ptr, sz, &iid_rs, &mut rs_obj);
            assert_eq!(rs_hr, S_OK, "CreateRootSignature(flags=0xC00, node=1) failed: {rs_hr:#010x}");
            assert!(!rs_obj.is_null());
            let rs_vtbl = *rs_obj.cast::<*const *const c_void>();
            let rs_rel: RelFn = std::mem::transmute(*rs_vtbl.add(2));
            rs_rel(rs_obj);
            let d_rel: RelFn = std::mem::transmute(*d_vtbl.add(2));
            d_rel(dev);

            rel(blob);
        }
    }

    #[test]
    fn layered_overlay_hud_renders_and_toggles() {
        shim_common::telemetry::reset_for_tests();
        shim_common::telemetry::record_shader_error(0xCAFE_BABE_1234_5678, "PS", -1);
        shim_common::telemetry::record_warning("dx12xs_pc", "hud smoke warning");
        let drawn = overlay::smoke_layered_hud_once().expect("layered HUD window smoke failed");
        assert!(drawn > 1000, "expected rendered pixels in DIB, got {drawn}");
        assert_eq!(LuciasOverlayToggle(), 0);
        assert_eq!(LuciasOverlayToggle(), 1);
        let _ = LuciasOverlayShutdown();
    }

    #[test]
    fn root_signature_appends_b0_space0_only_when_missing() {
        shim_common::telemetry::use_temp_telemetry_json_for_tests();
        // Root signature with 1 SRV param at t0, space=3 (no b0, space=0) -> appends synthetic CBV at slot 1.
        let p_srv: [u32; 8] = [3, 0, 0, 3, 0, 0, 0, 0];
        let desc = D3D12VersionedRootSigDesc {
            version: 2,
            _pad: 0,
            desc: D3D12RootSigDescCommon {
                num_parameters: 1,
                _pad0: 0,
                parameters: (&raw const p_srv).cast(),
                num_static_samplers: 0,
                _pad1: 0,
                static_samplers: std::ptr::null(),
                flags: 0,
                _pad2: 0,
            },
        };
        let mut blob: *mut c_void = std::ptr::null_mut();
        let mut err: *mut c_void = std::ptr::null_mut();
        assert_eq!(D3D12SerializeVersionedRootSignature((&raw const desc).cast(), &mut blob, &mut err), S_OK);
        assert!(!blob.is_null());
        unsafe {
            let vtbl = *blob.cast::<*const *const c_void>();
            type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
            type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let get_ptr: GetPtrFn = std::mem::transmute(*vtbl.add(3));
            let get_sz: GetSzFn = std::mem::transmute(*vtbl.add(4));
            let rel: RelFn = std::mem::transmute(*vtbl.add(2));
            let slots = take_synthetic_slots_for_blob(get_ptr(blob), get_sz(blob));
            assert_eq!(
                slots,
                Some(SyntheticRootSlots {
                    b0_slot: Some(1),
                    t255_s1_slot: Some(2),
                })
            );
            rel(blob);
            if !err.is_null() {
                let ev = *err.cast::<*const *const c_void>();
                let erel: RelFn = std::mem::transmute(*ev.add(2));
                erel(err);
            }
        }

        // Root signature already binding CBV(b0, space=0) and SRV(t255, space=1) -> no synthetic slots added.
        let p_both: [[u32; 8]; 2] = [
            [2, 0, 0, 0, 0x2, 0, 0, 0],
            [3, 0, 255, 1, 0x2, 0, 0, 0],
        ];
        let desc2 = D3D12VersionedRootSigDesc {
            version: 2,
            _pad: 0,
            desc: D3D12RootSigDescCommon {
                num_parameters: 2,
                _pad0: 0,
                parameters: p_both.as_ptr().cast(),
                num_static_samplers: 0,
                _pad1: 0,
                static_samplers: std::ptr::null(),
                flags: 0,
                _pad2: 0,
            },
        };
        let mut blob2: *mut c_void = std::ptr::null_mut();
        let mut err2: *mut c_void = std::ptr::null_mut();
        assert_eq!(D3D12SerializeVersionedRootSignature((&raw const desc2).cast(), &mut blob2, &mut err2), S_OK);
        unsafe {
            let vtbl = *blob2.cast::<*const *const c_void>();
            type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
            type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let get_ptr: GetPtrFn = std::mem::transmute(*vtbl.add(3));
            let get_sz: GetSzFn = std::mem::transmute(*vtbl.add(4));
            let rel: RelFn = std::mem::transmute(*vtbl.add(2));
            assert_eq!(take_synthetic_slots_for_blob(get_ptr(blob2), get_sz(blob2)), None);
            rel(blob2);
            if !err2.is_null() {
                let ev = *err2.cast::<*const *const c_void>();
                let erel: RelFn = std::mem::transmute(*ev.add(2));
                erel(err2);
            }
        }

        // Root signature at 64-DWORD budget (32 RootCBVs) skips t255, space=1 cleanly.
        let p_full: [[u32; 8]; 32] = std::array::from_fn(|i| [2, 0, i as u32, 0, 0x2, 0, 0, 0]);
        let desc_full = D3D12VersionedRootSigDesc {
            version: 2,
            _pad: 0,
            desc: D3D12RootSigDescCommon {
                num_parameters: 32,
                _pad0: 0,
                parameters: p_full.as_ptr().cast(),
                num_static_samplers: 0,
                _pad1: 0,
                static_samplers: std::ptr::null(),
                flags: 0,
                _pad2: 0,
            },
        };
        assert!(!needs_synthetic_rs_injection(&desc_full) || !summarize_root_sig(&desc_full).has_t255_space1);
        let mut blob_full: *mut c_void = std::ptr::null_mut();
        let mut err_full: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            D3D12SerializeVersionedRootSignature((&raw const desc_full).cast(), &mut blob_full, &mut err_full),
            S_OK
        );
        unsafe {
            let vtbl = *blob_full.cast::<*const *const c_void>();
            type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
            type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let get_ptr: GetPtrFn = std::mem::transmute(*vtbl.add(3));
            let get_sz: GetSzFn = std::mem::transmute(*vtbl.add(4));
            let rel: RelFn = std::mem::transmute(*vtbl.add(2));
            assert_eq!(take_synthetic_slots_for_blob(get_ptr(blob_full), get_sz(blob_full)), None);
            rel(blob_full);
            if !err_full.is_null() {
                let ev = *err_full.cast::<*const *const c_void>();
                let erel: RelFn = std::mem::transmute(*ev.add(2));
                erel(err_full);
            }
        }
    }

    #[test]
    fn present_context_swapchain_presents_and_cleans_up() {
        shim_common::telemetry::use_temp_telemetry_json_for_tests();
        let d3d12 = host_d3d12();
        assert!(!d3d12.is_null());
        let proc_fn = unsafe { GetProcAddress(d3d12, c"D3D12CreateDevice".as_ptr().cast()) }.unwrap();
        type CreateDevFn = extern "system" fn(*mut c_void, u32, *const Guid, *mut *mut c_void) -> HRESULT;
        let create_dev: CreateDevFn = unsafe { std::mem::transmute(proc_fn) };
        let mut real_dev: *mut c_void = std::ptr::null_mut();
        assert_eq!(create_dev(std::ptr::null_mut(), D3D_FEATURE_LEVEL_12_0, &IID_ID3D12DEVICE, &mut real_dev), S_OK);
        unsafe {
            #[repr(C)]
            struct QDesc { ty: u32, pri: i32, flags: u32, node: u32 }
            let d_vtbl = *real_dev.cast::<*const *const c_void>();
            type CreateQFn = unsafe extern "system" fn(*mut c_void, *const QDesc, *const Guid, *mut *mut c_void) -> HRESULT;
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let iid_q = Guid::new(0x0ec8_70a6, 0x5d7e, 0x4c22, [0x8c, 0xfc, 0x5b, 0xaa, 0xe0, 0x76, 0x16, 0xed]);
            let create_q: CreateQFn = std::mem::transmute(*d_vtbl.add(8));
            let mut real_q = std::ptr::null_mut();
            assert_eq!(create_q(real_dev, &QDesc { ty: 0, pri: 0, flags: 0, node: 0 }, &iid_q, &mut real_q), S_OK);

            let mut p = presenter::PresentContext::new(real_dev, std::ptr::null_mut(), 640, 360, 28)
                .expect("PresentContext::new should create window and IDXGISwapChain3");
            assert_ne!(p.hwnd(), 0);
            let (hr, copied) = p.present_plane(real_q, std::ptr::null_mut(), None, 0, None, 1);
            assert!(hr >= 0, "IDXGISwapChain3::Present failed: {hr:#010x}");
            assert!(!copied);
            drop(p);
            let q_vtbl = *real_q.cast::<*const *const c_void>();
            let q_rel: RelFn = std::mem::transmute(*q_vtbl.add(2));
            q_rel(real_q);
            let d_rel: RelFn = std::mem::transmute(*d_vtbl.add(2));
            d_rel(real_dev);
        }
    }

    #[test]
    fn allowlisted_dev_assert_rvas_match_strictly() {
        assert!(is_allowlisted_dev_assert_rva(0x04DC_BC9D));
        assert!(!is_allowlisted_dev_assert_rva(0x0247_4606));
        assert!(!is_allowlisted_dev_assert_rva(0));
    }
}
