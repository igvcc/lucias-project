//! Xbox Scarlett `d3d12_xs.dll` -> Win32 `d3d12.dll` / `dxgi.dll` COM vtable proxy.
//!
//! Enforces Scarlett struct layouts (`Device+0x18 != 0`, `Queue+0x10 = kind`,
//! `List >= 0x600B` with zeroed `put/limits` at `+0x18..+0x40`, `Pipeline >= 0x40B`
//! 16-byte aligned), C-style `sret`-first ABI on `GetResourceAllocationInfo` /
//! `GetCustomHeapProperties` / `GetResourceAllocationInfo2`, scalar `u64` return on
//! `DescriptorHeap::Get*DescriptorHandleForHeapStart`, and Scarlett console slot maps.

#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use shim_common::{
    E_INVALIDARG, E_NOINTERFACE, E_NOTIMPL, E_POINTER, Guid, HRESULT, S_OK, boot_trace,
    boot_trace_hr,
};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, LoadLibraryW,
};

pub const IID_IUNKNOWN: Guid = Guid::new(0, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
const DXGI_ERROR_NOT_FOUND: HRESULT = 0x887A_0002_u32 as i32;
const DXGI_ERROR_MORE_DATA: HRESULT = 0x887A_0003_u32 as i32;
const DXGI_ERROR_UNSUPPORTED: HRESULT = 0x887A_0004_u32 as i32;
const DXGI_ERROR_DEVICE_REMOVED: HRESULT = 0x887A_0005_u32 as i32;
const DXGI_ERROR_DEVICE_HUNG: HRESULT = 0x887A_0006_u32 as i32;
const DXGI_ERROR_DEVICE_RESET: HRESULT = 0x887A_0007_u32 as i32;
const DXGI_ERROR_DRIVER_INTERNAL_ERROR: HRESULT = 0x887A_0020_u32 as i32;

#[inline]
fn is_device_removed_hr(hr: HRESULT) -> bool {
    matches!(
        hr,
        DXGI_ERROR_DEVICE_REMOVED
            | DXGI_ERROR_DEVICE_HUNG
            | DXGI_ERROR_DEVICE_RESET
            | DXGI_ERROR_DRIVER_INTERNAL_ERROR
    )
}

#[inline]
pub(crate) fn query_real_removed_reason(real_device: *mut c_void) -> HRESULT {
    if real_device.is_null() {
        return S_OK;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void) -> HRESULT;
    unsafe { com_slot::<FnTy>(real_device, 37)(real_device) }
}

fn log_if_device_removed(real_device: *mut c_void, caller: &str, hr: HRESULT) {
    if is_device_removed_hr(hr) {
        let reason = query_real_removed_reason(real_device);
        boot_trace_hr(
            "dx12xs_pc",
            "DEVICE_REMOVED_REASON",
            reason,
            &format!("caller={caller} call_hr={:#010x}", hr as u32),
        );
    }
}

const IID_ID3D12INFO_QUEUE: Guid = Guid::new(
    0x0742_a90b,
    0xc387,
    0x483f,
    [0xb9, 0x46, 0x30, 0xa7, 0xe4, 0xe6, 0x14, 0x58],
);

#[repr(C)]
struct D3D12MessageRaw {
    category: i32,
    severity: i32,
    id: i32,
    _pad: u32,
    p_description: *const u8,
    description_byte_length: usize,
}

fn acquire_info_queue(real_device: *mut c_void) -> *mut c_void {
    if real_device.is_null() {
        return std::ptr::null_mut();
    }
    let mut iq: *mut c_void = std::ptr::null_mut();
    type QiFn = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<QiFn>(real_device, 0)(real_device, &IID_ID3D12INFO_QUEUE, &mut iq) };
    if hr >= 0 && !iq.is_null() {
        type SetLimitFn = unsafe extern "system" fn(*mut c_void, u64) -> HRESULT;
        let _ = unsafe { com_slot::<SetLimitFn>(iq, 3)(iq, 4096) };
        boot_trace_hr("dx12xs_pc", "ID3D12InfoQueue", S_OK, "attached");
        iq
    } else {
        std::ptr::null_mut()
    }
}

pub(crate) fn drain_info_queue(info_queue: *mut c_void, context: &str) {
    if info_queue.is_null() {
        return;
    }
    type ClearFn = unsafe extern "system" fn(*mut c_void);
    type GetMsgFn =
        unsafe extern "system" fn(*mut c_void, u64, *mut D3D12MessageRaw, *mut usize) -> HRESULT;
    type GetCountFn = unsafe extern "system" fn(*mut c_void) -> u64;

    let count = unsafe { com_slot::<GetCountFn>(info_queue, 8)(info_queue) };
    if count == 0 {
        return;
    }
    let get_msg = unsafe { com_slot::<GetMsgFn>(info_queue, 5) };
    let limit = count.min(32);
    for i in 0..limit {
        let mut len = 0usize;
        if unsafe { get_msg(info_queue, i, std::ptr::null_mut(), &mut len) } < 0 || len == 0 {
            continue;
        }
        let mut buf = vec![0u64; len.div_ceil(8)];
        let msg_ptr = buf.as_mut_ptr().cast::<D3D12MessageRaw>();
        if unsafe { get_msg(info_queue, i, msg_ptr, &mut len) } < 0 {
            continue;
        }
        let msg = unsafe { &*msg_ptr };
        if msg.severity <= 2 && !msg.p_description.is_null() && msg.description_byte_length > 0 {
            let slice = unsafe { std::slice::from_raw_parts(msg.p_description, msg.description_byte_length) };
            let text = String::from_utf8_lossy(slice).trim_end_matches('\0').to_owned();
            let tag = if msg.severity <= 1 { "D3D12InfoQueue_ERR" } else { "D3D12InfoQueue_WARN" };
            boot_trace(
                "dx12xs_pc",
                tag,
                &format!("ctx={context} id={} sev={} {text}", msg.id, msg.severity),
            );
        }
    }
    unsafe { com_slot::<ClearFn>(info_queue, 4)(info_queue) };
}

pub const IID_ID3D12DEVICE: Guid = Guid::new(
    0x1898_19f1,
    0x1db6,
    0x4b57,
    [0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7],
);
pub const IID_ID3D12DEVICE11: Guid = Guid::new(
    0x5405_c344,
    0xd457,
    0x444e,
    [0xb4, 0xdd, 0x23, 0x66, 0xe4, 0x5a, 0xee, 0x39],
);

const DEVICE_LEVEL_IIDS: [Guid; 9] = [
    Guid::new(0x77ac_ce80, 0x638e, 0x4e65, [0x88, 0x95, 0xc1, 0xf2, 0x33, 0x86, 0x86, 0x3e]),
    Guid::new(0x30ba_a41e, 0xb15b, 0x475c, [0xa0, 0xbb, 0x1a, 0xf5, 0xc5, 0xb6, 0x43, 0x28]),
    Guid::new(0x81da_dc15, 0x2bad, 0x4392, [0x93, 0xc5, 0x10, 0x13, 0x45, 0xc4, 0xaa, 0x98]),
    Guid::new(0xe865_df17, 0xa9ee, 0x46f9, [0xa4, 0x63, 0x30, 0x98, 0x31, 0x5a, 0xa2, 0xe5]),
    Guid::new(0x8b4f_173b, 0x2fea, 0x4b80, [0x8f, 0x58, 0x43, 0x07, 0x19, 0x1a, 0xb9, 0x5d]),
    Guid::new(0xc70b_221b, 0x40e4, 0x4a17, [0x89, 0xaf, 0x02, 0x5a, 0x07, 0x27, 0xa6, 0xdc]),
    Guid::new(0x5c01_4b53, 0x68a1, 0x4b9b, [0x8b, 0xd1, 0xdd, 0x60, 0x46, 0xb9, 0x35, 0x8b]),
    Guid::new(0x728f_1fa2, 0xea11, 0x4a9f, [0x9b, 0x52, 0x9b, 0x42, 0xa4, 0x84, 0xd5, 0xc9]),
    IID_ID3D12DEVICE11,
];

const PAGEABLE_IIDS: [Guid; 3] = [
    Guid::new(0x63ee_58fb, 0x1268, 0x4835, [0x86, 0xda, 0xf0, 0x08, 0xce, 0x62, 0xf0, 0xd6]),
    Guid::new(0x905d_b94b, 0xa00c, 0x4140, [0x9d, 0xf5, 0x2b, 0x64, 0xca, 0x9e, 0xa3, 0x57]),
    Guid::new(0xc4fe_c28f, 0x7966, 0x4e95, [0x9f, 0x94, 0xf4, 0x31, 0xcb, 0x56, 0xc3, 0xb8]),
];

const QUEUE_IIDS: [Guid; 4] = [
    Guid::new(0x0ec8_70a6, 0x5d7e, 0x4c22, [0x8c, 0xfc, 0x5b, 0xaa, 0xe0, 0x76, 0x16, 0xed]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const ALLOCATOR_IIDS: [Guid; 4] = [
    Guid::new(0x6102_dee4, 0xaf59, 0x4b09, [0xb9, 0x99, 0xb4, 0x4d, 0x73, 0xf0, 0x9b, 0x24]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const LIST_IIDS: [Guid; 10] = [
    Guid::new(0x7116_d91c, 0xe7e4, 0x47ce, [0xb8, 0xc6, 0xec, 0x81, 0x68, 0xf4, 0x37, 0xe5]),
    Guid::new(0x5b16_0d0f, 0xac1b, 0x4185, [0x8b, 0xa8, 0xb3, 0xae, 0x42, 0xa5, 0xa4, 0x55]),
    Guid::new(0x5531_03fb, 0x1fe7, 0x4557, [0xbb, 0x38, 0x94, 0x6d, 0x7d, 0x0e, 0x7c, 0xa7]),
    Guid::new(0x38c3_e585, 0xff17, 0x412c, [0x91, 0x50, 0x4f, 0xc6, 0xf9, 0xd7, 0x2a, 0x28]),
    Guid::new(0x6fda_83a7, 0xb84c, 0x4e38, [0x9a, 0xc8, 0xc7, 0xbd, 0x22, 0x01, 0x6b, 0x3d]),
    Guid::new(0x8754_318e, 0xd3a9, 0x4541, [0x98, 0xcf, 0x64, 0x5b, 0x50, 0xdc, 0x48, 0x74]),
    Guid::new(0x5505_0859, 0x4024, 0x474c, [0x98, 0xcf, 0x64, 0x5b, 0x51, 0xdc, 0x48, 0x74]),
    Guid::new(0xc382_7890, 0x4024, 0x474c, [0x98, 0xcf, 0x64, 0x5b, 0x51, 0xdc, 0x48, 0x74]),
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const FENCE_IIDS: [Guid; 5] = [
    Guid::new(0x0a75_3dcf, 0xc4d8, 0x4b91, [0xad, 0xf6, 0xbe, 0x5a, 0x60, 0xd9, 0x5a, 0x76]),
    Guid::new(0x4336_85fe, 0xe22b, 0x4ca0, [0xa8, 0xdb, 0xb5, 0xb4, 0xf4, 0xdd, 0x0e, 0x4a]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const SIGNATURE_IIDS: [Guid; 4] = [
    Guid::new(0xc36a_797c, 0xec80, 0x4f0a, [0x89, 0x85, 0xa7, 0xb2, 0x47, 0x50, 0x82, 0xd1]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const DESC_HEAP_IIDS: [Guid; 4] = [
    Guid::new(0x8efb_471d, 0x616c, 0x4f49, [0x90, 0xf7, 0x12, 0x7b, 0xb7, 0x63, 0xfa, 0x51]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const PIPELINE_IIDS: [Guid; 4] = [
    Guid::new(0x765a_30f3, 0xf624, 0x4c6f, [0xa8, 0x28, 0xac, 0xe9, 0x48, 0x62, 0x24, 0x45]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const RESOURCE_IIDS: [Guid; 4] = [
    Guid::new(0x6964_42be, 0xa72e, 0x4059, [0xbc, 0x79, 0x5b, 0x5c, 0x98, 0x04, 0x0f, 0xad]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const HEAP_IIDS: [Guid; 4] = [
    Guid::new(0x6b3b_2502, 0x6e51, 0x45b3, [0x90, 0xee, 0x98, 0x84, 0x26, 0x5e, 0x8d, 0xf3]),
    PAGEABLE_IIDS[0],
    PAGEABLE_IIDS[1],
    PAGEABLE_IIDS[2],
];

const DXGI_DEVICE_IIDS: [Guid; 3] = [
    Guid::new(0x54ec_77fa, 0x1377, 0x44e6, [0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c]),
    Guid::new(0x77db_970f, 0x6276, 0x48ba, [0xba, 0x28, 0x07, 0x01, 0x43, 0xb4, 0x39, 0x2c]),
    Guid::new(0x0500_8617, 0xfbfd, 0x4051, [0xa7, 0x90, 0x14, 0x48, 0x84, 0xb4, 0xf6, 0xa9]),
];
const DXGI_ADAPTER_IIDS: [Guid; 3] = [
    Guid::new(0x2411_e7e1, 0x12ac, 0x4ccf, [0xbd, 0x14, 0x97, 0x98, 0xe8, 0x53, 0x4d, 0xc0]),
    Guid::new(0x2903_8f61, 0x3839, 0x4626, [0x91, 0xfd, 0x08, 0x68, 0x79, 0x01, 0x1a, 0x05]),
    Guid::new(0x0aa1_ae0a, 0xfa0e, 0x4b84, [0x86, 0x44, 0xe0, 0x5f, 0xf8, 0xe5, 0xac, 0xb5]),
];
const DXGI_FACTORY_IIDS: [Guid; 3] = [
    Guid::new(0x7b71_66ec, 0x21c7, 0x44ae, [0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69]),
    Guid::new(0x770a_ae78, 0xf26f, 0x4dba, [0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87]),
    Guid::new(0x50c8_3a1c, 0xe072, 0x4c48, [0x87, 0xb0, 0x36, 0x30, 0xfa, 0x36, 0xa6, 0xd0]),
];
const DXGI_OUTPUT_IIDS: [Guid; 1] = [Guid::new(
    0xae02_eedb,
    0xc735,
    0x4690,
    [0x8d, 0x52, 0x5a, 0x8d, 0xc2, 0x02, 0x13, 0xaa],
)];

#[repr(transparent)]
struct Table<const N: usize>(pub [*const c_void; N]);
unsafe impl<const N: usize> Sync for Table<N> {}

const KIND_DEVICE: usize = 0;
const KIND_QUEUE: usize = 1;
const KIND_LIST: usize = 2;
const KIND_ALLOCATOR: usize = 3;
const KIND_FENCE: usize = 4;
const KIND_DESC_HEAP: usize = 5;
const KIND_PIPELINE: usize = 6;
const KIND_RESOURCE: usize = 7;
const KIND_HEAP: usize = 8;
const KIND_DXGI: usize = 9;
const KIND_SIGNATURE: usize = 10;

fn kind_name(kind: usize) -> &'static str {
    match kind {
        KIND_DEVICE => "ID3D12DeviceX",
        KIND_QUEUE => "ID3D12CommandQueueX",
        KIND_LIST => "ID3D12GraphicsCommandListX",
        KIND_ALLOCATOR => "ID3D12CommandAllocatorX",
        KIND_FENCE => "ID3D12FenceX",
        KIND_DESC_HEAP => "ID3D12DescriptorHeapX",
        KIND_PIPELINE => "ID3D12PipelineStateX",
        KIND_RESOURCE => "ID3D12ResourceX",
        KIND_HEAP => "ID3D12HeapX",
        KIND_DXGI => "IDXGIX",
        KIND_SIGNATURE => "ID3D12CommandSignatureX",
        _ => "UnknownCOM",
    }
}

extern "system" fn missing_slot<const KIND: usize, const SLOT: usize>(_this: *mut c_void) -> HRESULT {
    boot_trace(
        "dx12xs_pc",
        "UNIMPL_COM_SLOT",
        &format!("{} slot={SLOT} (+{:#x})", kind_name(KIND), SLOT * 8),
    );
    E_NOTIMPL
}

const fn fill_missing<const KIND: usize, const N: usize>() -> [*const c_void; N] {
    let mut tbl = [std::ptr::null(); N];
    macro_rules! assign_slots {
        ($($i:expr),*) => {
            $(
                if $i < N {
                    tbl[$i] = missing_slot::<KIND, $i> as *const c_void;
                }
            )*
        };
    }
    assign_slots!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
        100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
        140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159
    );
    tbl
}

#[inline]
unsafe fn com_slot<F: Copy>(obj: *mut c_void, slot: usize) -> F {
    let vtbl = unsafe { *obj.cast::<*const *const c_void>() };
    unsafe { std::mem::transmute_copy(&*vtbl.add(slot)) }
}

unsafe fn real_release(obj: *mut c_void) -> u32 {
    if obj.is_null() {
        return 0;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void) -> u32;
    let f: FnTy = unsafe { com_slot(obj, 2) };
    unsafe { f(obj) }
}

fn is_guid_in(iid: *const Guid, set: &[Guid]) -> bool {
    unsafe { iid.as_ref() }.is_some_and(|g| *g == IID_IUNKNOWN || set.contains(g))
}

fn is_device_iid(iid: *const Guid) -> bool {
    unsafe { iid.as_ref() }.is_some_and(|g| {
        *g == IID_IUNKNOWN || *g == IID_ID3D12DEVICE || DEVICE_LEVEL_IIDS.contains(g)
    })
}

// ============================================================================
// Descriptor heap address translation table (Xbox CPU handle <-> Win32 CPU handle)
// ============================================================================

#[derive(Clone, Copy)]
struct HeapRange {
    heap_ty: u32,
    xb_start: u64,
    xb_end: u64,
    xb_stride: u32,
    pc_start: u64,
    pc_gpu_start: u64,
    pc_stride: u32,
    pc_count: u32,
}

static HEAP_RANGES: LazyLock<Mutex<Vec<HeapRange>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static GPU_RESOURCE_RANGES: LazyLock<Mutex<Vec<(u64, u64)>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static RESOURCE_STATES: LazyLock<Mutex<HashMap<usize, u32>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static VIEW_TO_RESOURCE: LazyLock<Mutex<HashMap<u64, usize>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn set_tracked_resource_state(real_res: *mut c_void, state: u32) {
    if !real_res.is_null() {
        let mut states = RESOURCE_STATES.lock().unwrap_or_else(|e| e.into_inner());
        states.insert(real_res as usize, state);
    }
}

pub(crate) fn get_tracked_resource_state(real_res: *mut c_void) -> u32 {
    if real_res.is_null() {
        return 0;
    }
    RESOURCE_STATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(real_res as usize))
        .copied()
        .unwrap_or(0)
}

fn remove_tracked_resource_state(real_res: *mut c_void) {
    if !real_res.is_null() {
        let key = real_res as usize;
        let mut states = RESOURCE_STATES.lock().unwrap_or_else(|e| e.into_inner());
        states.remove(&key);
        let mut views = VIEW_TO_RESOURCE.lock().unwrap_or_else(|e| e.into_inner());
        views.retain(|_, &mut r| r != key);
    }
}

fn bind_view_resource(pc_cpu: u64, real_res: *mut c_void) {
    if pc_cpu != 0 && !real_res.is_null() {
        let mut views = VIEW_TO_RESOURCE.lock().unwrap_or_else(|e| e.into_inner());
        views.insert(pc_cpu, real_res as usize);
    }
}

fn ensure_list_view_state(real_list: *mut c_void, pc_cpu: u64, desired_state: u32) {
    let real_res = {
        let views = VIEW_TO_RESOURCE.lock().unwrap_or_else(|e| e.into_inner());
        views.get(&pc_cpu).copied()
    };
    let Some(res_key) = real_res else {
        return;
    };
    let mut states = RESOURCE_STATES.lock().unwrap_or_else(|e| e.into_inner());
    let Some(&cur) = states.get(&res_key) else {
        return;
    };
    if (cur & desired_state) == desired_state && (desired_state != 0 || cur == 0) {
        return;
    }
    if cur != desired_state {
        if DIAG_SKIP.barriers {
            return;
        }
        static VIEW_BARRIER_LOGS: AtomicU32 = AtomicU32::new(0);
        let bn = VIEW_BARRIER_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if bn <= 128 {
            boot_trace(
                "dx12xs_pc",
                "ListX::ensure_view_state",
                &format!("#{bn} list={real_list:?} res={res_key:#x} pc_cpu={pc_cpu:#x} {cur:#x}->{desired_state:#x}"),
            );
        }
        let barrier = ResourceBarrierRaw {
            ty: 0,
            flags: 0,
            u: [
                res_key as u64,
                ((cur as u64) << 32) | 0xFFFF_FFFF,
                u64::from(desired_state),
            ],
        };
        type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const ResourceBarrierRaw);
        unsafe { com_slot::<FnTy>(real_list, 26)(real_list, 1, &barrier) };
        states.insert(res_key, desired_state);
    }
}

fn register_gpu_buffer_va(real_res: *mut c_void, desc: &ResourceDescRaw) -> u64 {
    if real_res.is_null() || desc.dimension != 1 || desc.width == 0 {
        return 0;
    }
    type GetVaFn = unsafe extern "system" fn(*mut c_void) -> u64;
    let va = unsafe { com_slot::<GetVaFn>(real_res, 11)(real_res) };
    if va != 0 {
        let mut ranges = GPU_RESOURCE_RANGES.lock().unwrap_or_else(|e| e.into_inner());
        ranges.push((va, desc.width));
    }
    va
}

fn unregister_gpu_buffer_va(va: u64) {
    if va == 0 {
        return;
    }
    let mut ranges = GPU_RESOURCE_RANGES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pos) = ranges.iter().rposition(|&(base, _)| base == va) {
        ranges.swap_remove(pos);
    }
}

fn find_registered_gpu_buffer(va: u64, size: u32) -> bool {
    if va == 0 {
        return false;
    }
    let ranges = GPU_RESOURCE_RANGES.lock().unwrap_or_else(|e| e.into_inner());
    let end = va.saturating_add(u64::from(size));
    ranges
        .iter()
        .any(|&(base, len)| va >= base && end <= base.saturating_add(len))
}

static UNTRANSLATED_DESC_WARNS: AtomicU32 = AtomicU32::new(0);

fn translate_cpu_handle_for_ty(xb_handle: u64, expected_ty: Option<u32>) -> Option<u64> {
    let ranges = HEAP_RANGES.lock().unwrap_or_else(|e| e.into_inner());
    for r in ranges.iter().rev() {
        if expected_ty.is_some_and(|ty| r.heap_ty != ty) {
            continue;
        }
        if xb_handle >= r.xb_start && xb_handle < r.xb_end && r.xb_stride > 0 {
            let idx = (xb_handle - r.xb_start) / u64::from(r.xb_stride);
            let clamped = if r.pc_count > 0 {
                idx.min(u64::from(r.pc_count - 1))
            } else {
                idx
            };
            return Some(r.pc_start + clamped * u64::from(r.pc_stride));
        }
    }
    let n = UNTRANSLATED_DESC_WARNS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || n.is_power_of_two() {
        boot_trace(
            "dx12xs_pc",
            "DescriptorHandle::untranslated_skip",
            &format!("handle={xb_handle:#x} ty={expected_ty:?} count={n}"),
        );
    }
    None
}

fn translate_gpu_handle(xb_handle: u64) -> Option<u64> {
    if xb_handle == 0 {
        return None;
    }
    let ranges = HEAP_RANGES.lock().unwrap_or_else(|e| e.into_inner());
    for r in ranges.iter().rev() {
        if r.pc_gpu_start == 0 {
            continue;
        }
        let pc_gpu_end = r
            .pc_gpu_start
            .saturating_add(u64::from(r.pc_count).saturating_mul(u64::from(r.pc_stride)));
        if xb_handle >= r.pc_gpu_start && xb_handle < pc_gpu_end {
            return Some(xb_handle);
        }
        if xb_handle >= r.xb_start && xb_handle < r.xb_end && r.xb_stride > 0 {
            let idx = (xb_handle - r.xb_start) / u64::from(r.xb_stride);
            let clamped = if r.pc_count > 0 {
                idx.min(u64::from(r.pc_count - 1))
            } else {
                idx
            };
            return Some(r.pc_gpu_start + clamped * u64::from(r.pc_stride));
        }
    }
    None
}

fn xbox_descriptor_stride(kind: u32) -> Option<u32> {
    match kind {
        0 => Some(32),  // CBV/SRV/UAV
        1 => Some(16),  // Sampler
        2 => Some(128), // RTV
        3 => Some(128), // DSV
        _ => None,
    }
}

// ============================================================================
// DeviceX (`0x58`-byte Xbox prefix + real Win32 ID3D12Device pointer)
// ============================================================================

const IID_IDXGIADAPTER3: Guid = Guid::new(
    0x6459_67a4,
    0x1392,
    0x4310,
    [0xa7, 0x98, 0x80, 0x53, 0xce, 0x3e, 0x93, 0xfd],
);
const IID_IDXGIFACTORY1: Guid = Guid::new(
    0x770a_ae78,
    0xf26f,
    0x4dba,
    [0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87],
);
const IID_ID3D12FENCE: Guid = Guid::new(
    0x0a75_3dcf,
    0xc4d8,
    0x4b91,
    [0xad, 0xf6, 0xbe, 0x5a, 0x60, 0xd9, 0x5a, 0x76],
);

#[repr(C)]
#[derive(Default)]
struct DxgiQueryVideoMemoryInfo {
    budget: u64,
    current_usage: u64,
    available_for_reservation: u64,
    current_reservation: u64,
}

fn acquire_primary_dxgi_adapter3() -> *mut c_void {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    let name: Vec<u16> = "dxgi.dll\0".encode_utf16().collect();
    let h = unsafe { LoadLibraryW(name.as_ptr()) };
    if h.is_null() {
        return std::ptr::null_mut();
    }
    let Some(proc_fn) = (unsafe { GetProcAddress(h, c"CreateDXGIFactory1".as_ptr().cast()) }) else {
        return std::ptr::null_mut();
    };
    type CreateFac1Fn = unsafe extern "system" fn(*const Guid, *mut *mut c_void) -> HRESULT;
    let create_fac: CreateFac1Fn = unsafe { std::mem::transmute(proc_fn) };
    let mut fac: *mut c_void = std::ptr::null_mut();
    if unsafe { create_fac(&IID_IDXGIFACTORY1, &mut fac) } < 0 || fac.is_null() {
        return std::ptr::null_mut();
    }
    let mut adp: *mut c_void = std::ptr::null_mut();
    type EnumAdp1Fn = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> HRESULT;
    let hr_enum = unsafe { com_slot::<EnumAdp1Fn>(fac, 12)(fac, 0, &mut adp) };
    unsafe { real_release(fac) };
    if hr_enum < 0 || adp.is_null() {
        return std::ptr::null_mut();
    }
    let mut adp3: *mut c_void = std::ptr::null_mut();
    type QiFn = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> HRESULT;
    let hr_qi = unsafe { com_slot::<QiFn>(adp, 0)(adp, &IID_IDXGIADAPTER3, &mut adp3) };
    unsafe { real_release(adp) };
    if hr_qi >= 0 { adp3 } else { std::ptr::null_mut() }
}

fn sample_vram_usage(dxgi_adapter3: *mut c_void) {
    if dxgi_adapter3.is_null() {
        return;
    }
    let mut info = DxgiQueryVideoMemoryInfo::default();
    type QueryVidMemFn =
        unsafe extern "system" fn(*mut c_void, u32, u32, *mut DxgiQueryVideoMemoryInfo) -> HRESULT;
    let hr = unsafe { com_slot::<QueryVidMemFn>(dxgi_adapter3, 14)(dxgi_adapter3, 0, 0, &mut info) };
    if hr >= 0 {
        let used_mib = (info.current_usage / (1024 * 1024)) as u32;
        let budget_mib = (info.budget / (1024 * 1024)) as u32;
        shim_common::telemetry::set_vram_usage_mib(used_mib, budget_mib);
    }
}

const UMA_UPLOAD_RING_SIZE: usize = 32 * 1024 * 1024;
const MAX_UMA_UPLOAD_ALLOC: usize = 4 * 1024 * 1024;

struct UmaUploadRing {
    res: *mut c_void,
    mapped: *mut u8,
    gpu_va: u64,
    size: usize,
    cursor: usize,
}
unsafe impl Send for UmaUploadRing {}

pub(crate) fn align_and_wrap_ring_offset(
    cursor: usize,
    ring_size: usize,
    alloc_bytes: usize,
    align: usize,
) -> Option<(usize, usize)> {
    if ring_size == 0 || alloc_bytes == 0 || alloc_bytes > ring_size {
        return None;
    }
    let a = align.max(1);
    let aligned = cursor.next_multiple_of(a);
    let off = if aligned.saturating_add(alloc_bytes) <= ring_size {
        aligned
    } else {
        0
    };
    Some((off, off + alloc_bytes))
}

#[repr(C)]
pub struct DeviceX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    null_constant_buffer: AtomicU64,
    out_of_line: [u32; 16],
    real_device: *mut c_void,
    dxgi_adapter3: *mut c_void,
    info_queue: *mut c_void,
    is_newer_dev11: bool,
    frame_interval_us: AtomicU32,
    frame_token: AtomicU64,
    dxpk_fallback_root_sig: AtomicUsize,
    null_cb_resource: AtomicUsize,
    synthetic_rs_slots: Mutex<HashMap<usize, crate::SyntheticRootSlots>>,
    failed_rs_stages: Mutex<HashSet<(usize, u8)>>,
    rs_blobs: Mutex<HashMap<usize, Vec<u8>>>,
    compute_rs_upgrades: Mutex<HashMap<usize, usize>>,
    compute_rs_build_lock: Mutex<()>,
    uma_upload_ring: Mutex<Option<UmaUploadRing>>,
}

const _: () = assert!(std::mem::offset_of!(DeviceX, out_of_line) == 0x18);

static FRAME_START: LazyLock<Instant> = LazyLock::new(Instant::now);

#[derive(Default)]
struct DiagSkipFlags {
    clear_rtv: bool,
    bind_b0: bool,
    om_rt: bool,
    ia: bool,
    rs_vp: bool,
    heaps: bool,
    barriers: bool,
}

impl DiagSkipFlags {
    fn parse(raw: &str) -> Self {
        let mut s = Self::default();
        for tok in raw.split(',').map(|t| t.trim().to_ascii_lowercase()) {
            match tok.as_str() {
                "clear_rtv" => s.clear_rtv = true,
                "bind_b0" => s.bind_b0 = true,
                "om_rt" => s.om_rt = true,
                "ia" => s.ia = true,
                "rs_vp" => s.rs_vp = true,
                "heaps" => s.heaps = true,
                "barriers" => s.barriers = true,
                "all" => {
                    s.clear_rtv = true;
                    s.bind_b0 = true;
                    s.om_rt = true;
                    s.ia = true;
                    s.rs_vp = true;
                    s.heaps = true;
                    s.barriers = true;
                }
                _ => {}
            }
        }
        s
    }
}

static DIAG_SKIP: LazyLock<DiagSkipFlags> = LazyLock::new(|| {
    let raw = std::env::var("LUCIAS_DIAG_LIST4_SKIP").unwrap_or_default();
    let parsed = DiagSkipFlags::parse(&raw);
    if !raw.is_empty() {
        boot_trace("dx12xs_pc", "LUCIAS_DIAG_LIST4_SKIP", &format!("active={raw}"));
    }
    parsed
});

#[derive(Default, Clone, Copy)]
struct ClearRtvMaskFlags {
    skip_3: bool,
    skip_4: bool,
    skip_after_2: bool,
    no_present_copy: bool,
    no_present_init: bool,
}

impl ClearRtvMaskFlags {
    fn parse(raw: &str) -> Self {
        let mut s = Self::default();
        for tok in raw.split(',').map(|t| t.trim().to_ascii_lowercase()) {
            match tok.as_str() {
                "skip_3" => s.skip_3 = true,
                "skip_4" => s.skip_4 = true,
                "skip_after_2" => s.skip_after_2 = true,
                "no_present_copy" => s.no_present_copy = true,
                "no_present_init" => s.no_present_init = true,
                _ => {}
            }
        }
        s
    }
}

static CLEAR_RTV_MASK: LazyLock<ClearRtvMaskFlags> = LazyLock::new(|| {
    let raw = std::env::var("LUCIAS_DIAG_CLEAR_RTV_MASK").unwrap_or_default();
    let parsed = ClearRtvMaskFlags::parse(&raw);
    if !raw.is_empty() {
        boot_trace("dx12xs_pc", "LUCIAS_DIAG_CLEAR_RTV_MASK", &format!("active={raw}"));
    }
    parsed
});

pub fn wrap_xbox_device(real_device: *mut c_void, requested_iid: &Guid) -> *mut c_void {
    let is_newer_dev11 = *requested_iid == IID_ID3D12DEVICE11;
    let dxgi_adapter3 = acquire_primary_dxgi_adapter3();
    let info_queue = acquire_info_queue(real_device);
    sample_vram_usage(dxgi_adapter3);
    shim_common::telemetry::sample_process_ram_mib();
    crate::overlay::ensure_started();
    let dev = Box::new(DeviceX {
        vtable: DEVICE_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        null_constant_buffer: AtomicU64::new(0),
        out_of_line: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        real_device,
        dxgi_adapter3,
        info_queue,
        is_newer_dev11,
        frame_interval_us: AtomicU32::new(16_667),
        frame_token: AtomicU64::new(1),
        dxpk_fallback_root_sig: AtomicUsize::new(0),
        null_cb_resource: AtomicUsize::new(0),
        synthetic_rs_slots: Mutex::new(HashMap::new()),
        failed_rs_stages: Mutex::new(HashSet::new()),
        rs_blobs: Mutex::new(HashMap::new()),
        compute_rs_upgrades: Mutex::new(HashMap::new()),
        compute_rs_build_lock: Mutex::new(()),
        uma_upload_ring: Mutex::new(None),
    });
    Box::into_raw(dev).cast()
}

fn is_rs_stage_failed(d: &DeviceX, rs: *mut c_void, kind: u8) -> bool {
    if rs.is_null() {
        return false;
    }
    d.failed_rs_stages
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&(rs as usize, kind))
}

fn mark_rs_stage_failed(d: &DeviceX, rs: *mut c_void, kind: u8) {
    if !rs.is_null() {
        let mut set = d.failed_rs_stages.lock().unwrap_or_else(|e| e.into_inner());
        if set.len() < 4096 {
            set.insert((rs as usize, kind));
        }
    }
}

fn upload_cpu_slice_to_gpu_va(
    d: &DeviceX,
    cpu_va: u64,
    copy_bytes: usize,
    alloc_bytes: usize,
    align: usize,
) -> Option<u64> {
    if cpu_va < 0x10000
        || copy_bytes == 0
        || alloc_bytes < copy_bytes
        || alloc_bytes > MAX_UMA_UPLOAD_ALLOC
        || d.real_device.is_null()
    {
        return None;
    }
    if !is_readable_bytes(cpu_va as *const c_void, copy_bytes) {
        return None;
    }
    let mut guard = d.uma_upload_ring.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        let heap_props: [u32; 5] = [2, 0, 0, 0, 0]; // D3D12_HEAP_TYPE_UPLOAD
        let desc = ResourceDescRaw {
            dimension: 1,
            alignment: 0,
            width: UMA_UPLOAD_RING_SIZE as u64,
            height: 1,
            depth_or_array: 1,
            mip_levels: 1,
            format: 0,
            sample_count: 1,
            sample_quality: 0,
            layout: 1,
            flags: 0,
        };
        let mut res: *mut c_void = std::ptr::null_mut();
        type CreateCommFn = unsafe extern "system" fn(
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
            com_slot::<CreateCommFn>(d.real_device, 27)(
                d.real_device,
                &heap_props,
                0,
                &desc,
                0xAC3, // D3D12_RESOURCE_STATE_GENERIC_READ
                std::ptr::null(),
                &RESOURCE_IIDS[0],
                &mut res,
            )
        };
        if hr < 0 || res.is_null() {
            boot_trace_hr("dx12xs_pc", "DeviceX::UmaUploadRing::init", hr, "CreateCommittedResource failed");
            return None;
        }
        type MapFn = unsafe extern "system" fn(*mut c_void, u32, *const c_void, *mut *mut c_void) -> HRESULT;
        type GetVaFn = unsafe extern "system" fn(*mut c_void) -> u64;
        let mut mapped: *mut c_void = std::ptr::null_mut();
        let hr_map = unsafe { com_slot::<MapFn>(res, 8)(res, 0, std::ptr::null(), &mut mapped) };
        let gpu_va = unsafe { com_slot::<GetVaFn>(res, 11)(res) };
        if hr_map < 0 || mapped.is_null() || gpu_va == 0 {
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::UmaUploadRing::init",
                hr_map,
                &format!("Map/GetVA failed mapped={mapped:?} va={gpu_va:#x}"),
            );
            unsafe { real_release(res) };
            return None;
        }
        GPU_RESOURCE_RANGES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((gpu_va, UMA_UPLOAD_RING_SIZE as u64));
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::UmaUploadRing::init",
            S_OK,
            &format!("res={res:?} gpu_va={gpu_va:#x} size={UMA_UPLOAD_RING_SIZE:#x}"),
        );
        *guard = Some(UmaUploadRing {
            res,
            mapped: mapped.cast(),
            gpu_va,
            size: UMA_UPLOAD_RING_SIZE,
            cursor: 0,
        });
    }
    let ring = guard.as_mut()?;
    let (off, next_cursor) = align_and_wrap_ring_offset(ring.cursor, ring.size, alloc_bytes, align)?;
    ring.cursor = next_cursor;
    unsafe {
        std::ptr::copy_nonoverlapping(cpu_va as *const u8, ring.mapped.add(off), copy_bytes);
        if alloc_bytes > copy_bytes {
            std::ptr::write_bytes(ring.mapped.add(off + copy_bytes), 0, alloc_bytes - copy_bytes);
        }
    }
    Some(ring.gpu_va + off as u64)
}

fn ensure_null_cb_gpu_va(d: &DeviceX) -> u64 {
    let existing = d.null_constant_buffer.load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }
    let heap_props: [u32; 5] = [2, 0, 0, 0, 0]; // D3D12_HEAP_TYPE_UPLOAD
    let desc = ResourceDescRaw {
        dimension: 1,
        alignment: 0,
        width: 256,
        height: 1,
        depth_or_array: 1,
        mip_levels: 1,
        format: 0,
        sample_count: 1,
        sample_quality: 0,
        layout: 1,
        flags: 0,
    };
    let mut res: *mut c_void = std::ptr::null_mut();
    type CreateCommFn = unsafe extern "system" fn(
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
        com_slot::<CreateCommFn>(d.real_device, 27)(
            d.real_device,
            &heap_props,
            0,
            &desc,
            0xAC3,
            std::ptr::null(),
            &RESOURCE_IIDS[0],
            &mut res,
        )
    };
    if hr < 0 || res.is_null() {
        boot_trace_hr("dx12xs_pc", "DeviceX::null_cb_create", hr, "failed");
        return 0;
    }
    type MapFn = unsafe extern "system" fn(*mut c_void, u32, *const c_void, *mut *mut c_void) -> HRESULT;
    type UnmapFn = unsafe extern "system" fn(*mut c_void, u32, *const c_void);
    let mut mapped: *mut c_void = std::ptr::null_mut();
    if unsafe { com_slot::<MapFn>(res, 8)(res, 0, std::ptr::null(), &mut mapped) } >= 0 && !mapped.is_null() {
        unsafe { std::ptr::write_bytes(mapped.cast::<u8>(), 0, 256) };
        unsafe { com_slot::<UnmapFn>(res, 9)(res, 0, std::ptr::null()) };
    }
    type GetVaFn = unsafe extern "system" fn(*mut c_void) -> u64;
    let va = unsafe { com_slot::<GetVaFn>(res, 11)(res) };
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::null_cb_create",
        S_OK,
        &format!("res={res:?} va={va:#x}"),
    );
    if va == 0 {
        unsafe { real_release(res) };
        return 0;
    }
    match d
        .null_cb_resource
        .compare_exchange(0, res as usize, Ordering::AcqRel, Ordering::Acquire)
    {
        Ok(_) => {
            d.null_constant_buffer.store(va, Ordering::Release);
            va
        }
        Err(_) => {
            unsafe { real_release(res) };
            d.null_constant_buffer.load(Ordering::Acquire)
        }
    }
}

extern "system" fn dev_query_interface(
    this: *mut DeviceX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let d = unsafe { &*this };
    if is_device_iid(iid) {
        dev_add_ref(this);
        unsafe { *out = this.cast() };
        return S_OK;
    }
    if is_guid_in(iid, &DXGI_DEVICE_IIDS) {
        dev_add_ref(this);
        let dxgi = Box::new(DxgiDeviceProxy {
            vtable: DXGI_DEVICE_VTABLE.0.as_ptr(),
            refs: AtomicU32::new(1),
            parent_dev: this,
        });
        unsafe { *out = Box::into_raw(dxgi).cast() };
        return S_OK;
    }
    let g_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
    boot_trace(
        "dx12xs_pc",
        "DeviceX::QueryInterface",
        &format!("E_NOINTERFACE iid={g_str} newer={}", d.is_newer_dev11),
    );
    unsafe { *out = std::ptr::null_mut() };
    E_NOINTERFACE
}

extern "system" fn dev_add_ref(this: *mut DeviceX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn dev_release(this: *mut DeviceX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let boxed = unsafe { Box::from_raw(this) };
        let fallback_rs = boxed.dxpk_fallback_root_sig.load(Ordering::Acquire);
        if fallback_rs != 0 {
            unsafe { real_release(fallback_rs as *mut c_void) };
        }
        let null_cb_res = boxed.null_cb_resource.load(Ordering::Acquire);
        if null_cb_res != 0 {
            unsafe { real_release(null_cb_res as *mut c_void) };
        }
        if let Some(ring) = boxed.uma_upload_ring.into_inner().ok().flatten() {
            unregister_gpu_buffer_va(ring.gpu_va);
            if !ring.res.is_null() {
                unsafe { real_release(ring.res) };
            }
        }
        if !boxed.info_queue.is_null() {
            unsafe { real_release(boxed.info_queue) };
        }
        if !boxed.dxgi_adapter3.is_null() {
            unsafe { real_release(boxed.dxgi_adapter3) };
        }
        unsafe { real_release(boxed.real_device) };
    }
    left
}

extern "system" fn dev_get_private_data(
    this: *mut DeviceX,
    guid: *const Guid,
    size: *mut u32,
    data: *mut c_void,
) -> HRESULT {
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *const Guid, *mut u32, *mut c_void) -> HRESULT;
    unsafe { com_slot::<FnTy>(real, 3)(real, guid, size, data) }
}

extern "system" fn dev_set_private_data(
    this: *mut DeviceX,
    guid: *const Guid,
    size: u32,
    data: *const c_void,
) -> HRESULT {
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *const Guid, u32, *const c_void) -> HRESULT;
    unsafe { com_slot::<FnTy>(real, 4)(real, guid, size, data) }
}

extern "system" fn dev_set_private_data_iface(
    this: *mut DeviceX,
    guid: *const Guid,
    iface: *const c_void,
) -> HRESULT {
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *const Guid, *const c_void) -> HRESULT;
    unsafe { com_slot::<FnTy>(real, 5)(real, guid, iface) }
}

extern "system" fn dev_set_name(this: *mut DeviceX, name: *const u16) -> HRESULT {
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT;
    unsafe { com_slot::<FnTy>(real, 6)(real, name) }
}

extern "system" fn dev_get_node_count(_this: *mut DeviceX) -> u32 {
    1
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PcQueueDesc {
    ty: u32,
    priority: i32,
    flags: u32,
    node_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XboxQueueDesc {
    ty: u32,
    flags: u32,
    engine_or_pipe: u32,
    queue: u32,
}

extern "system" fn dev_create_command_queue(
    this: *mut DeviceX,
    desc: *const PcQueueDesc,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() || desc.is_null() {
        return E_INVALIDARG;
    }
    let d = unsafe { &*this };
    let mut pc_desc = unsafe { *desc };
    pc_desc.flags &= 1;
    let mut real_q: *mut c_void = std::ptr::null_mut();
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *const PcQueueDesc, *const Guid, *mut *mut c_void) -> HRESULT;
    let hr = unsafe {
        com_slot::<FnTy>(d.real_device, 8)(d.real_device, &pc_desc, &QUEUE_IIDS[0], &mut real_q)
    };
    let rem = query_real_removed_reason(d.real_device);
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateCommandQueue",
        hr,
        &format!("type={} removed_reason={:#010x}", pc_desc.ty, rem as u32),
    );
    drain_info_queue(d.info_queue, "CreateCommandQueue");
    if hr < 0 {
        log_if_device_removed(d.real_device, "DeviceX::CreateCommandQueue", hr);
        unsafe { *out = std::ptr::null_mut() };
        return hr;
    }
    if !is_guid_in(iid, &QUEUE_IIDS) {
        unsafe { real_release(real_q) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    let mut timing_fence: *mut c_void = std::ptr::null_mut();
    type CreateFenceFn =
        unsafe extern "system" fn(*mut c_void, u64, u32, *const Guid, *mut *mut c_void) -> HRESULT;
    let _ = unsafe {
        com_slot::<CreateFenceFn>(d.real_device, 36)(
            d.real_device,
            0,
            0,
            &IID_ID3D12FENCE,
            &mut timing_fence,
        )
    };
    dev_add_ref(this);
    let q = Box::new(QueueX {
        vtable: if d.is_newer_dev11 {
            NEWER_QUEUE_VTABLE.0.as_ptr()
        } else {
            QUEUE_VTABLE.0.as_ptr()
        },
        bits: 0,
        refs: AtomicU32::new(1),
        kind: pc_desc.ty,
        desc: pc_desc,
        parent_dev: this,
        real_queue: real_q,
        timing_fence,
        timing_seq: AtomicU64::new(0),
        pending_seq: AtomicU64::new(0),
        pending_submit_qpc: AtomicU64::new(0),
        present_tick: AtomicU64::new(0),
        present_ctx: Mutex::new(None),
    });
    unsafe { *out = Box::into_raw(q).cast() };
    S_OK
}

extern "system" fn dev_create_command_queue_x(
    this: *mut DeviceX,
    desc: *const XboxQueueDesc,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    let Some(xd) = (unsafe { desc.as_ref() }) else {
        return E_INVALIDARG;
    };
    let pc = PcQueueDesc {
        ty: xd.ty,
        priority: 0,
        flags: xd.flags & 1,
        node_mask: 0,
    };
    dev_create_command_queue(this, &pc, iid, out)
}

extern "system" fn dev_create_command_allocator(
    this: *mut DeviceX,
    ty: u32,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let d = unsafe { &*this };
    let mut real_alloc: *mut c_void = std::ptr::null_mut();
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const Guid, *mut *mut c_void) -> HRESULT;
    let hr = unsafe {
        com_slot::<FnTy>(d.real_device, 9)(d.real_device, ty, &ALLOCATOR_IIDS[0], &mut real_alloc)
    };
    let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
    if hr < 0 {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateCommandAllocator",
            hr,
            &format!("type={ty} iid={iid_str}"),
        );
        unsafe { *out = std::ptr::null_mut() };
        return hr;
    }
    if !is_guid_in(iid, &ALLOCATOR_IIDS) {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateCommandAllocator",
            E_NOINTERFACE,
            &format!("type={ty} E_NOINTERFACE iid={iid_str}"),
        );
        unsafe { real_release(real_alloc) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    dev_add_ref(this);
    let obj = Box::new(AllocatorX {
        vtable: ALLOCATOR_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        parent_dev: this,
        real_alloc,
    });
    let wrapped = Box::into_raw(obj).cast();
    unsafe { *out = wrapped };
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateCommandAllocator",
        S_OK,
        &format!("type={ty} out={wrapped:?}"),
    );
    S_OK
}

fn wrap_pipeline_ex(
    parent_dev: *mut DeviceX,
    real_pso: *mut c_void,
    used_fallback_rs: bool,
) -> *mut c_void {
    dev_add_ref(parent_dev);
    let pso = Box::new(PipelineX {
        vtable: PIPELINE_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        inline_zero: [0; 4],
        parent_dev,
        real_pso,
        used_fallback_rs,
        compute_rs_override: std::ptr::null_mut(),
        diag_dsv_fmt: 0,
        diag_rtv0_fmt: 0,
        diag_depth_en: 0,
        diag_depth_func: 0,
        diag_vs_hash: 0,
        diag_ps_hash: 0,
    });
    Box::into_raw(pso).cast()
}

fn wrap_pipeline(parent_dev: *mut DeviceX, real_pso: *mut c_void) -> *mut c_void {
    wrap_pipeline_ex(parent_dev, real_pso, false)
}

#[repr(C)]
struct ShaderBytecodeRaw {
    ptr: *const u8,
    len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ComputePsoDescRaw {
    root_signature: *mut c_void,
    cs: ShaderBytecodeRaw,
    node_mask: u32,
    cached_pso: ShaderBytecodeRaw,
    flags: u32,
}

impl Copy for ShaderBytecodeRaw {}
impl Clone for ShaderBytecodeRaw {
    fn clone(&self) -> Self {
        *self
    }
}

fn probe_pso_shaders(desc: *const c_void, is_compute: bool) -> (u64, &'static str) {
    if desc.is_null() {
        return (0, if is_compute { "CS" } else { "PSO" });
    }
    let stages: &[(&'static str, usize)] = if is_compute {
        &[("CS", 0x08)]
    } else {
        &[("VS", 0x08), ("PS", 0x18), ("DS", 0x28), ("HS", 0x38), ("GS", 0x48)]
    };
    let mut primary_hash = 0u64;
    let mut primary_stage = stages[0].0;
    for &(stage, offset) in stages {
        let bc = unsafe { &*desc.cast::<u8>().add(offset).cast::<ShaderBytecodeRaw>() };
        if !bc.ptr.is_null() && bc.len >= 4 && bc.len <= 32 * 1024 * 1024 {
            let slice = unsafe { std::slice::from_raw_parts(bc.ptr, bc.len) };
            let h = crate::dxpk::fnv1a_64(slice);
            if primary_hash == 0 {
                primary_hash = h;
                primary_stage = stage;
            }
            crate::dxpk::probe_dxpk_for_telemetry(slice, stage);
        }
    }
    (primary_hash, primary_stage)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GraphicsPsoDescRaw {
    root_signature: *mut c_void,
    stages: [ShaderBytecodeRaw; 5], // VS, PS, DS, HS, GS
    stream_output: [u64; 4],
    blend_state: [u32; 82],
    sample_mask: u32,
    rasterizer_state: [u32; 11],
    depth_stencil_state: [u32; 13],
    input_layout_ptr: *const c_void,
    input_layout_count: u32,
    ib_strip_cut_value: u32,
    primitive_topology_type: u32,
    num_render_targets: u32,
    rtv_formats: [u32; 8],
    dsv_format: u32,
    sample_desc: [u32; 2],
    node_mask: u32,
    cached_pso: ShaderBytecodeRaw,
    flags: u32,
}
const _: () = assert!(size_of::<GraphicsPsoDescRaw>() == 648);

extern "system" fn dev_create_graphics_pso(
    this: *mut DeviceX,
    desc: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let d = unsafe { &*this };
    let real = d.real_device;
    let mut primary_hash = 0u64;
    let mut primary_stage = "PSO";
    let mut owned_blobs: Vec<Vec<u8>> = Vec::new();
    let mut patched_opt = if !desc.is_null() {
        let mut g = unsafe { desc.cast::<GraphicsPsoDescRaw>().read_unaligned() };
        let stage_names = ["VS", "PS", "DS", "HS", "GS"];
        for (i, &stage_name) in stage_names.iter().enumerate() {
            let bc = g.stages[i];
            if !bc.ptr.is_null() && bc.len >= 4 && bc.len <= 32 * 1024 * 1024 {
                let slice = unsafe { std::slice::from_raw_parts(bc.ptr, bc.len) };
                if primary_hash == 0 {
                    primary_hash = crate::dxpk::fnv1a_64(slice);
                    primary_stage = stage_name;
                }
                if let Some(blob) = crate::dxpk::lookup_pc_dxil(slice) {
                    g.stages[i] = ShaderBytecodeRaw {
                        ptr: blob.as_ptr(),
                        len: blob.len(),
                    };
                    owned_blobs.push(blob);
                }
            }
        }
        for fmt in &mut g.rtv_formats {
            *fmt = map_rtv_format(*fmt);
        }
        g.dsv_format = sanitize_dsv_format(g.dsv_format);
        g.primitive_topology_type = sanitize_primitive_topology_type(g.primitive_topology_type);
        g.cached_pso = ShaderBytecodeRaw {
            ptr: std::ptr::null(),
            len: 0,
        };
        Some(g)
    } else {
        None
    };

    let mut real_pso: *mut c_void = std::ptr::null_mut();
    let mut used_fallback = false;
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *const c_void, *const Guid, *mut *mut c_void) -> HRESULT;
    let orig_rs = patched_opt.as_ref().map_or(std::ptr::null_mut(), |g| g.root_signature);
    let skip_try1 = !owned_blobs.is_empty() && is_rs_stage_failed(d, orig_rs, 1);
    let mut hr = if skip_try1 {
        let fallback_rs = get_dxpk_fallback_root_sig(d);
        if !fallback_rs.is_null() {
            if let Some(ref mut g) = patched_opt {
                g.root_signature = fallback_rs;
                used_fallback = true;
                unsafe {
                    com_slot::<FnTy>(real, 10)(
                        real,
                        (g as *const GraphicsPsoDescRaw).cast(),
                        &PIPELINE_IIDS[0],
                        &mut real_pso,
                    )
                }
            } else {
                E_INVALIDARG
            }
        } else {
            E_INVALIDARG
        }
    } else if let Some(ref g) = patched_opt {
        unsafe { com_slot::<FnTy>(real, 10)(real, (g as *const GraphicsPsoDescRaw).cast(), &PIPELINE_IIDS[0], &mut real_pso) }
    } else {
        unsafe { com_slot::<FnTy>(real, 10)(real, desc, &PIPELINE_IIDS[0], &mut real_pso) }
    };
    if !skip_try1 && hr < 0 && !owned_blobs.is_empty() {
        mark_rs_stage_failed(d, orig_rs, 1);
        if let Some(ref mut g) = patched_opt {
            let fallback_rs = get_dxpk_fallback_root_sig(d);
            if !fallback_rs.is_null() {
                g.root_signature = fallback_rs;
                used_fallback = true;
                hr = unsafe {
                    com_slot::<FnTy>(real, 10)(
                        real,
                        (g as *const GraphicsPsoDescRaw).cast(),
                        &PIPELINE_IIDS[0],
                        &mut real_pso,
                    )
                };
            }
        }
    }
    drop(owned_blobs);
    drain_info_queue(d.info_queue, "CreateGraphicsPipelineState");
    let (sh_hash, sh_stage) = if primary_hash == 0 {
        probe_pso_shaders(desc, false)
    } else {
        (primary_hash, primary_stage)
    };
    let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
    if hr >= 0 && !real_pso.is_null() {
        if !is_guid_in(iid, &PIPELINE_IIDS) {
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::CreateGraphicsPipelineState",
                E_NOINTERFACE,
                &format!("E_NOINTERFACE iid={iid_str}"),
            );
            unsafe { real_release(real_pso) };
            unsafe { *out = std::ptr::null_mut() };
            return E_NOINTERFACE;
        }
        shim_common::telemetry::record_shader_compiled();
        let wrapped = wrap_pipeline_ex(this, real_pso, used_fallback);
        if let Some(ref g) = patched_opt {
            unsafe {
                let p = &mut *wrapped.cast::<PipelineX>();
                p.diag_dsv_fmt = g.dsv_format;
                p.diag_rtv0_fmt = g.rtv_formats[0];
                p.diag_depth_en = g.depth_stencil_state[0];
                p.diag_depth_func = g.depth_stencil_state[2];
            }
        }
        unsafe { *out = wrapped };
        if let Some(ref g) = patched_opt {
            if g.num_render_targets == 1 && g.rtv_formats[0] == 28 && !used_fallback {
                static PSO28_LOGS: AtomicU32 = AtomicU32::new(0);
                if PSO28_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
                    boot_trace(
                        "dx12xs_pc",
                        "DeviceX::CreateGraphicsPSO(rtv28)",
                        &format!(
                            "real_pso={real_pso:?} hash={sh_hash:#018x} in_elems={} cull={} depth_en={} depth_func={} blend0_en={} dsv_fmt={}",
                            g.input_layout_count,
                            g.rasterizer_state[1],
                            g.depth_stencil_state[0],
                            g.depth_stencil_state[2],
                            g.blend_state[2],
                            g.dsv_format,
                        ),
                    );
                }
            }
        }
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateGraphicsPipelineState",
            S_OK,
            &format!("stage={sh_stage} hash={sh_hash:#018x} fallback_rs={used_fallback} out={wrapped:?}"),
        );
        S_OK
    } else {
        // Fallback stub PSO wrapper if shader bytecode is Xbox DXBC/SGD5 so LUCIAS PROJECT proceeds cleanly.
        shim_common::telemetry::record_shader_error(sh_hash, sh_stage, hr);
        unsafe { *out = wrap_pipeline(this, std::ptr::null_mut()) };
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateGraphicsPipelineState(stub)",
            hr,
            &format!("stage={sh_stage} hash={sh_hash:#018x}"),
        );
        S_OK
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FallbackDescRange1 {
    range_type: u32,
    num_descriptors: u32,
    base_register: u32,
    register_space: u32,
    flags: u32,
    offset_from_table_start: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FallbackRootParam1 {
    param_type: u32,
    _pad0: u32,
    num_ranges: u32,
    _pad1: u32,
    ranges: *const FallbackDescRange1,
    visibility: u32,
    _pad2: u32,
}

#[repr(C)]
struct FallbackRootSigDesc1 {
    num_parameters: u32,
    _pad0: u32,
    parameters: *const FallbackRootParam1,
    num_static_samplers: u32,
    _pad1: u32,
    static_samplers: *const c_void,
    flags: u32,
    _pad2: u32,
}

#[repr(C)]
struct FallbackVersionedRootSig {
    version: u32,
    _pad0: u32,
    desc: FallbackRootSigDesc1,
}

fn get_dxpk_fallback_root_sig(d: &DeviceX) -> *mut c_void {
    let cached = d.dxpk_fallback_root_sig.load(Ordering::Acquire);
    if cached != 0 {
        return cached as *mut c_void;
    }
    const VOLATILE_DESC: u32 = 0x3; // DESCRIPTORS_VOLATILE (0x1) | DATA_VOLATILE (0x2)
    const VOLATILE_SAMPLER: u32 = 0x1; // DESCRIPTORS_VOLATILE only (samplers have no DATA_*)
    const SAMPLER_MAX: u32 = 1024;  // 1024 * 2 tables = 2048 <= D3D12_MAX_SHADER_VISIBLE_SAMPLER_HEAP_SIZE
    let ranges = [
        FallbackDescRange1 { range_type: 2, num_descriptors: u32::MAX, base_register: 0, register_space: 0, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 0, num_descriptors: u32::MAX, base_register: 0, register_space: 0, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 1, num_descriptors: u32::MAX, base_register: 0, register_space: 0, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 2, num_descriptors: u32::MAX, base_register: 0, register_space: 1, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 0, num_descriptors: u32::MAX, base_register: 0, register_space: 1, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 1, num_descriptors: u32::MAX, base_register: 0, register_space: 1, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 2, num_descriptors: u32::MAX, base_register: 0, register_space: 2, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 0, num_descriptors: u32::MAX, base_register: 0, register_space: 2, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 1, num_descriptors: u32::MAX, base_register: 0, register_space: 2, flags: VOLATILE_DESC, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 3, num_descriptors: SAMPLER_MAX, base_register: 0, register_space: 0, flags: VOLATILE_SAMPLER, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 3, num_descriptors: SAMPLER_MAX, base_register: 0, register_space: 1, flags: VOLATILE_SAMPLER, offset_from_table_start: 0 },
        FallbackDescRange1 { range_type: 0, num_descriptors: u32::MAX, base_register: 0, register_space: 3, flags: VOLATILE_DESC, offset_from_table_start: 0 },
    ];
    let params: [FallbackRootParam1; 12] = std::array::from_fn(|i| FallbackRootParam1 {
        param_type: 0,
        _pad0: 0,
        num_ranges: 1,
        _pad1: 0,
        ranges: &raw const ranges[i],
        visibility: 0,
        _pad2: 0,
    });
    let versioned = FallbackVersionedRootSig {
        version: 2,
        _pad0: 0,
        desc: FallbackRootSigDesc1 {
            num_parameters: params.len() as u32,
            _pad0: 0,
            parameters: params.as_ptr(),
            num_static_samplers: 0,
            _pad1: 0,
            static_samplers: std::ptr::null(),
            flags: 0xC01, // ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT | CBV_SRV_UAV_HEAP_DIRECTLY_INDEXED | SAMPLER_HEAP_DIRECTLY_INDEXED
            _pad2: 0,
        },
    };
    let mut blob: *mut c_void = std::ptr::null_mut();
    let mut err_blob: *mut c_void = std::ptr::null_mut();
    let ser_hr = crate::D3D12SerializeVersionedRootSignature(
        (&raw const versioned).cast(),
        &mut blob,
        &mut err_blob,
    );
    if !err_blob.is_null() {
        let vtbl = unsafe { *err_blob.cast::<*const *const c_void>() };
        type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const u8;
        type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
        let get_ptr: GetPtrFn = unsafe { std::mem::transmute(*vtbl.add(3)) };
        let get_sz: GetSzFn = unsafe { std::mem::transmute(*vtbl.add(4)) };
        let (ep, es) = (unsafe { get_ptr(err_blob) }, unsafe { get_sz(err_blob) });
        if !ep.is_null() && es > 0 {
            let msg = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ep, es.min(512)) });
            #[cfg(test)]
            eprintln!("DXPKFallbackRootSig SerializeErr ({ser_hr:#010x}): {}", msg.trim());
            boot_trace_hr("dx12xs_pc", "DXPKFallbackRootSig::SerializeErr", ser_hr, msg.trim());
        }
        unsafe { real_release(err_blob) };
    }
    if ser_hr < 0 || blob.is_null() {
        #[cfg(test)]
        eprintln!("DXPKFallbackRootSig Serialize failed ({ser_hr:#010x})");
        boot_trace_hr("dx12xs_pc", "DXPKFallbackRootSig::Serialize", ser_hr, "failed");
        return std::ptr::null_mut();
    }
    let vtbl = unsafe { *blob.cast::<*const *const c_void>() };
    type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
    type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
    let get_ptr: GetPtrFn = unsafe { std::mem::transmute(*vtbl.add(3)) };
    let get_sz: GetSzFn = unsafe { std::mem::transmute(*vtbl.add(4)) };
    let (ptr, len) = (unsafe { get_ptr(blob) }, unsafe { get_sz(blob) });

    let mut real_rs: *mut c_void = std::ptr::null_mut();
    type CreateRsFn = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *const c_void,
        usize,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let rs_iid = Guid::new(
        0xc54a_6b66,
        0x72df,
        0x4ee8,
        [0x8b, 0xe5, 0xa9, 0x46, 0xa1, 0x42, 0x92, 0x14],
    );
    let hr = unsafe {
        com_slot::<CreateRsFn>(d.real_device, 16)(d.real_device, 0, ptr, len, &rs_iid, &mut real_rs)
    };
    unsafe { real_release(blob) };
    if hr < 0 || real_rs.is_null() {
        #[cfg(test)]
        eprintln!("DXPKFallbackRootSig Create failed ({hr:#010x})");
        boot_trace_hr("dx12xs_pc", "DXPKFallbackRootSig::Create", hr, "failed");
        return std::ptr::null_mut();
    }
    match d.dxpk_fallback_root_sig.compare_exchange(
        0,
        real_rs as usize,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => real_rs,
        Err(existing) => {
            unsafe { real_release(real_rs) };
            existing as *mut c_void
        }
    }
}

fn get_or_create_compute_rs_upgrade(d: &DeviceX, orig_rs: *mut c_void) -> *mut c_void {
    if orig_rs.is_null() {
        return std::ptr::null_mut();
    }
    if let Some(&cached) = d
        .compute_rs_upgrades
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(orig_rs as usize))
    {
        return cached as *mut c_void;
    }
    let _build_guard = d.compute_rs_build_lock.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&cached) = d
        .compute_rs_upgrades
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(orig_rs as usize))
    {
        return cached as *mut c_void;
    }
    let Some(blob_bytes) = d
        .rs_blobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(orig_rs as usize))
        .cloned()
    else {
        return std::ptr::null_mut();
    };
    let d3d12 = crate::host_d3d12();
    if d3d12.is_null() {
        return std::ptr::null_mut();
    }
    let Some(create_deser) = (unsafe {
        GetProcAddress(
            d3d12,
            c"D3D12CreateVersionedRootSignatureDeserializer".as_ptr().cast(),
        )
    }) else {
        return std::ptr::null_mut();
    };
    let Some(ser_proc) = (unsafe {
        GetProcAddress(
            d3d12,
            c"D3D12SerializeVersionedRootSignature".as_ptr().cast(),
        )
    }) else {
        return std::ptr::null_mut();
    };
    type DeserFn =
        unsafe extern "system" fn(*const c_void, usize, *const Guid, *mut *mut c_void) -> HRESULT;
    type SerFn =
        unsafe extern "system" fn(*const c_void, *mut *mut c_void, *mut *mut c_void) -> HRESULT;
    let deser_fn: DeserFn = unsafe { std::mem::transmute(create_deser) };
    let ser_fn: SerFn = unsafe { std::mem::transmute(ser_proc) };
    let deser_iid = Guid::new(
        0x7f91_ce67,
        0x090c,
        0x4bb7,
        [0xb7, 0x8e, 0xed, 0x8f, 0xf2, 0xe3, 0x1d, 0xa0],
    );
    let mut deser: *mut c_void = std::ptr::null_mut();
    if unsafe { deser_fn(blob_bytes.as_ptr().cast(), blob_bytes.len(), &deser_iid, &mut deser) } < 0
        || deser.is_null()
    {
        return std::ptr::null_mut();
    }
    type GetUnconvFn =
        unsafe extern "system" fn(*mut c_void) -> *const crate::D3D12VersionedRootSigDesc;
    let raw_desc = unsafe { com_slot::<GetUnconvFn>(deser, 4)(deser) };
    let mut up_rs: *mut c_void = std::ptr::null_mut();
    if let Some(rd) = unsafe { raw_desc.as_ref() } {
        let mut sanitized = *rd;
        let n = rd.desc.num_parameters as usize;
        let mut params: Vec<[u32; 8]> = Vec::with_capacity(n + 3);
        if !rd.desc.parameters.is_null() && n > 0 {
            for i in 0..n {
                params.push(unsafe { rd.desc.parameters.cast::<[u32; 8]>().add(i).read_unaligned() });
            }
        }
        let desc_flags = if sanitized.version >= 2 { 0x2 } else { 0 };
        params.push([4, 0, 252, 1, desc_flags, 0, 0, 0]); // UAV u252 space1
        params.push([3, 0, 254, 1, desc_flags, 0, 0, 0]); // SRV t254 space1
        params.push([2, 0, 3, 1, desc_flags, 0, 0, 0]); // CBV b3 space1
        sanitized.desc.num_parameters = params.len() as u32;
        sanitized.desc.parameters = params.as_ptr().cast();
        let mut ser_blob: *mut c_void = std::ptr::null_mut();
        let mut err_blob: *mut c_void = std::ptr::null_mut();
        let ser_hr = unsafe { ser_fn((&raw const sanitized).cast(), &mut ser_blob, &mut err_blob) };
        if !err_blob.is_null() {
            unsafe { real_release(err_blob) };
        }
        if ser_hr >= 0 && !ser_blob.is_null() {
            let vtbl = unsafe { *ser_blob.cast::<*const *const c_void>() };
            type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
            type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
            let gp: GetPtrFn = unsafe { std::mem::transmute(*vtbl.add(3)) };
            let gs: GetSzFn = unsafe { std::mem::transmute(*vtbl.add(4)) };
            let (ptr, len) = (unsafe { gp(ser_blob) }, unsafe { gs(ser_blob) });
            let rs_iid = Guid::new(
                0xc54a_6b66,
                0x72df,
                0x4ee8,
                [0x8b, 0xe5, 0xa9, 0x46, 0xa1, 0x42, 0x92, 0x14],
            );
            type CreateRsFn = unsafe extern "system" fn(
                *mut c_void,
                u32,
                *const c_void,
                usize,
                *const Guid,
                *mut *mut c_void,
            ) -> HRESULT;
            let create_hr = unsafe {
                com_slot::<CreateRsFn>(d.real_device, 16)(
                    d.real_device,
                    0,
                    ptr,
                    len,
                    &rs_iid,
                    &mut up_rs,
                )
            };
            unsafe { real_release(ser_blob) };
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::UpgradeComputeRS",
                create_hr,
                &format!("orig={orig_rs:?} up={up_rs:?}"),
            );
        }
    }
    unsafe { real_release(deser) };
    if !up_rs.is_null() {
        d.compute_rs_upgrades
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(orig_rs as usize, up_rs as usize);
    }
    up_rs
}

extern "system" fn dev_create_compute_pso(
    this: *mut DeviceX,
    desc: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let d = unsafe { &*this };
    let real = d.real_device;
    let (sh_hash, sh_stage, pc_dxil) = if !desc.is_null() {
        let raw_cs = unsafe { &*desc.cast::<u8>().add(0x08).cast::<ShaderBytecodeRaw>() };
        if !raw_cs.ptr.is_null() && raw_cs.len >= 4 && raw_cs.len <= 32 * 1024 * 1024 {
            let slice = unsafe { std::slice::from_raw_parts(raw_cs.ptr, raw_cs.len) };
            let h = crate::dxpk::fnv1a_64(slice);
            let blob = crate::dxpk::lookup_pc_dxil(slice);
            (h, "CS", blob)
        } else {
            (0, "CS", None)
        }
    } else {
        (0, "CS", None)
    };
    let mut real_pso: *mut c_void = std::ptr::null_mut();
    let mut used_fallback = false;
    let mut compute_rs_override: *mut c_void = std::ptr::null_mut();
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *const c_void, *const Guid, *mut *mut c_void) -> HRESULT;
    let mut hr = if let Some(ref blob) = pc_dxil {
        let mut patched = unsafe { desc.cast::<ComputePsoDescRaw>().read_unaligned() };
        let orig_rs = patched.root_signature;
        patched.cs = ShaderBytecodeRaw {
            ptr: blob.as_ptr(),
            len: blob.len(),
        };
        patched.cached_pso = ShaderBytecodeRaw {
            ptr: std::ptr::null(),
            len: 0,
        };
        let skip_try1 = is_rs_stage_failed(d, orig_rs, 0);
        let try1 = if skip_try1 {
            E_INVALIDARG
        } else {
            unsafe {
                com_slot::<FnTy>(real, 11)(
                    real,
                    (&raw const patched).cast(),
                    &PIPELINE_IIDS[0],
                    &mut real_pso,
                )
            }
        };
        if try1 < 0 {
            if !skip_try1 {
                mark_rs_stage_failed(d, orig_rs, 0);
            }
            let up_rs = get_or_create_compute_rs_upgrade(d, orig_rs);
            let try_up = if !up_rs.is_null() {
                patched.root_signature = up_rs;
                unsafe {
                    com_slot::<FnTy>(real, 11)(
                        real,
                        (&raw const patched).cast(),
                        &PIPELINE_IIDS[0],
                        &mut real_pso,
                    )
                }
            } else {
                E_INVALIDARG
            };
            if try_up >= 0 {
                compute_rs_override = up_rs;
                try_up
            } else {
                let fallback_rs = get_dxpk_fallback_root_sig(d);
                if !fallback_rs.is_null() {
                    patched.root_signature = fallback_rs;
                    used_fallback = true;
                    unsafe {
                        com_slot::<FnTy>(real, 11)(
                            real,
                            (&raw const patched).cast(),
                            &PIPELINE_IIDS[0],
                            &mut real_pso,
                        )
                    }
                } else {
                    try1
                }
            }
        } else {
            try1
        }
    } else {
        unsafe { com_slot::<FnTy>(real, 11)(real, desc, &PIPELINE_IIDS[0], &mut real_pso) }
    };
    if hr < 0 && pc_dxil.is_none() && !desc.is_null() {
        let fallback_rs = get_dxpk_fallback_root_sig(d);
        if !fallback_rs.is_null() {
            let mut patched = unsafe { desc.cast::<ComputePsoDescRaw>().read_unaligned() };
            patched.root_signature = fallback_rs;
            patched.cached_pso = ShaderBytecodeRaw {
                ptr: std::ptr::null(),
                len: 0,
            };
            used_fallback = true;
            hr = unsafe {
                com_slot::<FnTy>(real, 11)(
                    real,
                    (&raw const patched).cast(),
                    &PIPELINE_IIDS[0],
                    &mut real_pso,
                )
            };
        }
    }
    drain_info_queue(d.info_queue, "CreateComputePipelineState");
    let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
    if hr >= 0 && !real_pso.is_null() {
        if !is_guid_in(iid, &PIPELINE_IIDS) {
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::CreateComputePipelineState",
                E_NOINTERFACE,
                &format!("E_NOINTERFACE iid={iid_str}"),
            );
            unsafe { real_release(real_pso) };
            unsafe { *out = std::ptr::null_mut() };
            return E_NOINTERFACE;
        }
        shim_common::telemetry::record_shader_compiled();
        let wrapped = wrap_pipeline_ex(this, real_pso, used_fallback);
        if !compute_rs_override.is_null() {
            unsafe { (*(wrapped as *mut PipelineX)).compute_rs_override = compute_rs_override };
        }
        unsafe { *out = wrapped };
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateComputePipelineState",
            S_OK,
            &format!("stage={sh_stage} hash={sh_hash:#018x} fallback_rs={used_fallback} out={wrapped:?}"),
        );
        S_OK
    } else {
        shim_common::telemetry::record_shader_error(sh_hash, sh_stage, hr);
        unsafe { *out = wrap_pipeline(this, std::ptr::null_mut()) };
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateComputePipelineState(stub)",
            hr,
            &format!("stage={sh_stage} hash={sh_hash:#018x}"),
        );
        S_OK
    }
}

extern "system" fn dev_create_compute_pso_x(
    this: *mut DeviceX,
    desc: *const c_void,
    _ext_count: u32,
    _exts: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    dev_create_compute_pso(this, desc, iid, out)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PipelineStateStreamDescRaw {
    size_in_bytes: usize,
    stream: *const u8,
}

fn xbox_stream_subobject_info(kind: u32) -> Option<(usize, Option<(&'static str, u32)>)> {
    match kind {
        1 => Some((24, Some(("VS", 1)))),
        2 => Some((24, Some(("PS", 2)))),
        3 => Some((24, Some(("DS", 3)))),
        4 => Some((24, Some(("HS", 4)))),
        5 => Some((24, Some(("GS", 5)))),
        6 => Some((24, Some(("CS", 6)))),
        23 => Some((24, Some(("AS", 24)))), // Xbox 23 -> PC 24 (AS)
        24 => Some((24, Some(("MS", 25)))), // Xbox 24 -> PC 25 (MS)
        0 => Some((16, None)),
        7 | 15 => Some((40, None)),
        8 => Some((336, None)),
        9 | 13 | 14 | 16 | 18 | 20 => Some((8, None)),
        10 => Some((48, None)),
        11 => Some((56, None)),
        12 | 19 => Some((24, None)),
        17 => Some((16, None)),
        21 => Some((64, None)),
        22 => Some((32, None)),
        _ => None,
    }
}

extern "system" fn dev_create_pipeline_state_stream(
    this: *mut DeviceX,
    desc: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if !is_guid_in(iid, &PIPELINE_IIDS) {
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    let Some(stream_desc) = (unsafe { desc.cast::<PipelineStateStreamDescRaw>().as_ref() }) else {
        unsafe { *out = wrap_pipeline(this, std::ptr::null_mut()) };
        return S_OK;
    };
    if stream_desc.stream.is_null() || stream_desc.size_in_bytes < 8 || stream_desc.size_in_bytes > 65536 {
        unsafe { *out = wrap_pipeline(this, std::ptr::null_mut()) };
        return S_OK;
    }

    let mut pc_stream = Vec::with_capacity(stream_desc.size_in_bytes);
    let mut owned_blobs: Vec<Vec<u8>> = Vec::new();
    let mut stage_dumps: Vec<(&'static str, u64, &[u8], bool)> = Vec::new();
    let mut primary_hash = 0u64;
    let mut primary_stage = "STREAM";
    let mut root_sig_patch_off: Option<usize> = None;
    let mut input_layout_off: Option<usize> = None;
    let mut rtv_fmts_logged = [0u32; 8];
    let mut num_rt_logged = 0u32;
    let mut dsv_fmt_logged = 0u32;
    let mut depth_en_logged = 0u32;
    let mut depth_fn_logged = 0u32;
    let mut input_elems_logged = 0u32;
    let mut sample_cnt_logged = 0u32;
    let mut tags: Vec<u32> = Vec::new();
    let mut at = 0usize;

    while at + 8 <= stream_desc.size_in_bytes {
        let kind = unsafe { stream_desc.stream.add(at).cast::<u32>().read_unaligned() };
        tags.push(kind);
        let Some((sz, shader_info)) = xbox_stream_subobject_info(kind) else {
            break;
        };
        if at + sz > stream_desc.size_in_bytes {
            break;
        }
        let dst_off = pc_stream.len();
        let src_slice = unsafe { std::slice::from_raw_parts(stream_desc.stream.add(at), sz) };
        pc_stream.extend_from_slice(src_slice);

        if kind == 0 {
            root_sig_patch_off = Some(dst_off + 8);
        } else if let Some((stage, pc_kind)) = shader_info {
            pc_stream[dst_off..dst_off + 4].copy_from_slice(&pc_kind.to_le_bytes());
            let bc = unsafe {
                stream_desc
                    .stream
                    .add(at + 8)
                    .cast::<ShaderBytecodeRaw>()
                    .read_unaligned()
            };
            if !bc.ptr.is_null() && bc.len >= 4 && bc.len <= 32 * 1024 * 1024 {
                let slice = unsafe { std::slice::from_raw_parts(bc.ptr, bc.len) };
                let hash = crate::dxpk::fnv1a_64(slice);
                if primary_hash == 0 {
                    primary_hash = hash;
                    primary_stage = stage;
                }
                let dxpk_blob = crate::dxpk::lookup_pc_dxil(slice);
                let dxpk_hit = dxpk_blob.is_some();
                stage_dumps.push((stage, hash, slice, dxpk_hit));
                if let Some(blob) = dxpk_blob {
                    let patched_bc = ShaderBytecodeRaw {
                        ptr: blob.as_ptr(),
                        len: blob.len(),
                    };
                    unsafe {
                        pc_stream
                            .as_mut_ptr()
                            .add(dst_off + 8)
                            .cast::<ShaderBytecodeRaw>()
                            .write_unaligned(patched_bc);
                    }
                    owned_blobs.push(blob);
                }
            }
        } else if kind == 12 {
            // INPUT_LAYOUT: [u32 kind, u32 pad, *const D3D12_INPUT_ELEMENT_DESC, u32 num_elements, u32 pad]
            input_layout_off = Some(dst_off + 8);
            input_elems_logged = u32::from_le_bytes(pc_stream[dst_off + 16..dst_off + 20].try_into().unwrap());
        } else if kind == 14 {
            // PRIMITIVE_TOPOLOGY: [u32 kind, u32 topology_type]
            let off = dst_off + 4;
            let raw_topo = u32::from_le_bytes(pc_stream[off..off + 4].try_into().unwrap());
            let topo = sanitize_primitive_topology_type(raw_topo);
            pc_stream[off..off + 4].copy_from_slice(&topo.to_le_bytes());
        } else if kind == 15 {
            // RENDER_TARGET_FORMATS: [u32 kind, u32 rtv_formats[8], u32 num_rt]
            for (i, slot) in rtv_fmts_logged.iter_mut().enumerate() {
                let off = dst_off + 4 + i * 4;
                let fmt = map_rtv_format(u32::from_le_bytes(pc_stream[off..off + 4].try_into().unwrap()));
                pc_stream[off..off + 4].copy_from_slice(&fmt.to_le_bytes());
                *slot = fmt;
            }
            num_rt_logged = u32::from_le_bytes(pc_stream[dst_off + 36..dst_off + 40].try_into().unwrap());
        } else if kind == 16 {
            // DEPTH_STENCIL_FORMAT: [u32 kind, u32 dsv_format]
            let off = dst_off + 4;
            let fmt = sanitize_dsv_format(u32::from_le_bytes(pc_stream[off..off + 4].try_into().unwrap()));
            pc_stream[off..off + 4].copy_from_slice(&fmt.to_le_bytes());
            dsv_fmt_logged = fmt;
        } else if kind == 8 {
            // BLEND: [u32 kind, BOOL alpha_to_cov, BOOL indep_blend, RT0: BlendEnable(+12), ..., WriteMask(+48)]
            if sz >= 52 {
                let b_en = u32::from_le_bytes(pc_stream[dst_off + 12..dst_off + 16].try_into().unwrap());
                let src_b = u32::from_le_bytes(pc_stream[dst_off + 20..dst_off + 24].try_into().unwrap());
                let dst_b = u32::from_le_bytes(pc_stream[dst_off + 24..dst_off + 28].try_into().unwrap());
                let wmask = pc_stream[dst_off + 48];
                depth_fn_logged = (b_en & 1) | ((src_b & 0xFF) << 8) | ((dst_b & 0xFF) << 16) | (u32::from(wmask) << 24);
            }
        } else if kind == 11 || kind == 21 {
            depth_en_logged = u32::from_le_bytes(pc_stream[dst_off + 4..dst_off + 8].try_into().unwrap());
        } else if kind == 17 {
            sample_cnt_logged = u32::from_le_bytes(pc_stream[dst_off + 4..dst_off + 8].try_into().unwrap());
        } else if kind == 19 {
            // CACHED_PSO: clear blob pointer + size
            pc_stream[dst_off + 8..dst_off + 24].fill(0);
        }
        at += sz;
    }

    let d = unsafe { &*this };
    let real = d.real_device;
    let mut real_pso: *mut c_void = std::ptr::null_mut();
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        *const PipelineStateStreamDescRaw,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let pc_desc = PipelineStateStreamDescRaw {
        size_in_bytes: pc_stream.len(),
        stream: pc_stream.as_ptr(),
    };
    let mut used_fallback = false;
    let orig_rs = root_sig_patch_off.map_or(std::ptr::null_mut(), |rs_off| unsafe {
        pc_stream
            .as_ptr()
            .add(rs_off)
            .cast::<*mut c_void>()
            .read_unaligned()
    });
    let skip_try1 = !pc_stream.is_empty() && !owned_blobs.is_empty() && is_rs_stage_failed(d, orig_rs, 2);
    let mut hr = if pc_stream.is_empty() {
        E_INVALIDARG
    } else if skip_try1 {
        if let Some(rs_off) = root_sig_patch_off {
            let fallback_rs = get_dxpk_fallback_root_sig(d);
            if !fallback_rs.is_null() {
                unsafe {
                    pc_stream
                        .as_mut_ptr()
                        .add(rs_off)
                        .cast::<*mut c_void>()
                        .write_unaligned(fallback_rs);
                }
                used_fallback = true;
                unsafe { com_slot::<FnTy>(real, 47)(real, &pc_desc, &PIPELINE_IIDS[0], &mut real_pso) }
            } else {
                E_INVALIDARG
            }
        } else {
            E_INVALIDARG
        }
    } else {
        unsafe { com_slot::<FnTy>(real, 47)(real, &pc_desc, &PIPELINE_IIDS[0], &mut real_pso) }
    };
    if !skip_try1 && hr < 0 {
        if !owned_blobs.is_empty() {
            mark_rs_stage_failed(d, orig_rs, 2);
        }
        if let Some(rs_off) = root_sig_patch_off {
            let fallback_rs = get_dxpk_fallback_root_sig(d);
            if !fallback_rs.is_null() {
                unsafe {
                    pc_stream
                        .as_mut_ptr()
                        .add(rs_off)
                        .cast::<*mut c_void>()
                        .write_unaligned(fallback_rs);
                }
                used_fallback = true;
                hr = unsafe { com_slot::<FnTy>(real, 47)(real, &pc_desc, &PIPELINE_IIDS[0], &mut real_pso) };
            }
        }
    }
    let mut _sanitized_il_buf: Vec<u8> = Vec::new();
    if hr == (0x8007_0057_u32 as i32) && !owned_blobs.is_empty() {
        if let Some(il_off) = input_layout_off {
            let orig_ptr = unsafe { pc_stream.as_ptr().add(il_off).cast::<*const u8>().read_unaligned() };
            let orig_cnt = u32::from_le_bytes(pc_stream[il_off + 8..il_off + 12].try_into().unwrap());
            if !orig_ptr.is_null() && orig_cnt > 0 && orig_cnt <= 64 {
                let elem_bytes = (orig_cnt as usize) * 32;
                let src_elems = unsafe { std::slice::from_raw_parts(orig_ptr, elem_bytes) };
                _sanitized_il_buf = src_elems.to_vec();
                for i in 0..orig_cnt as usize {
                    let fmt_off = i * 32 + 12;
                    let f = u32::from_le_bytes(_sanitized_il_buf[fmt_off..fmt_off + 4].try_into().unwrap());
                    let mapped = map_xbox_dxgi_format(f);
                    _sanitized_il_buf[fmt_off..fmt_off + 4].copy_from_slice(&mapped.to_le_bytes());
                }
                unsafe {
                    pc_stream
                        .as_mut_ptr()
                        .add(il_off)
                        .cast::<*const u8>()
                        .write_unaligned(_sanitized_il_buf.as_ptr());
                }
                hr = unsafe { com_slot::<FnTy>(real, 47)(real, &pc_desc, &PIPELINE_IIDS[0], &mut real_pso) };
            }
            if hr == (0x8007_0057_u32 as i32) {
                unsafe {
                    pc_stream
                        .as_mut_ptr()
                        .add(il_off)
                        .cast::<*const u8>()
                        .write_unaligned(std::ptr::null());
                }
                pc_stream[il_off + 8..il_off + 12].fill(0);
                hr = unsafe { com_slot::<FnTy>(real, 47)(real, &pc_desc, &PIPELINE_IIDS[0], &mut real_pso) };
            }
        }
    }
    drop(owned_blobs);
    drain_info_queue(d.info_queue, "CreatePipelineState");
    if hr >= 0 && !real_pso.is_null() {
        shim_common::telemetry::record_shader_compiled();
        let wrapped = wrap_pipeline_ex(this, real_pso, used_fallback);
        unsafe {
            let p = &mut *wrapped.cast::<PipelineX>();
            p.diag_dsv_fmt = dsv_fmt_logged;
            p.diag_rtv0_fmt = rtv_fmts_logged[0];
            p.diag_depth_en = depth_en_logged;
            p.diag_depth_func = depth_fn_logged;
            for (st, h, _, _) in &stage_dumps {
                if *st == "VS" {
                    p.diag_vs_hash = *h;
                } else if *st == "PS" || *st == "CS" {
                    p.diag_ps_hash = *h;
                }
            }
            *out = wrapped;
        }
        static OK_LOGS: AtomicU32 = AtomicU32::new(0);
        if (rtv_fmts_logged[0] == 28 && dsv_fmt_logged == 0 && num_rt_logged == 1)
            && OK_LOGS.fetch_add(1, Ordering::Relaxed) < 64
        {
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::CreatePipelineState(rtv28_nodsv)",
                S_OK,
                &format!(
                    "out={real_pso:?} stage={primary_stage} hash={primary_hash:#018x} fallback_rs={used_fallback} bytes={} rtv={rtv_fmts_logged:?} num_rt={num_rt_logged} dsv={dsv_fmt_logged} tags={tags:?}",
                    pc_stream.len()
                ),
            );
        }
    } else {
        shim_common::telemetry::record_shader_error(primary_hash, primary_stage, hr);
        unsafe { *out = wrap_pipeline(this, std::ptr::null_mut()) };
        static ERR_LOGS: AtomicU32 = AtomicU32::new(0);
        if ERR_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
            let dump_dir = std::path::Path::new(r"E:\LUCIAS_PROJECT\logs\missed_shaders");
            let _ = std::fs::create_dir_all(dump_dir);
            let mut stage_parts = Vec::with_capacity(stage_dumps.len());
            for (stage, hash, slice, dxpk_hit) in &stage_dumps {
                let dump_path = dump_dir.join(format!("{stage}_{hash:016x}.bin"));
                let _ = std::fs::write(&dump_path, slice);
                let fourcc = format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    slice[0],
                    slice.get(1).copied().unwrap_or(0),
                    slice.get(2).copied().unwrap_or(0),
                    slice.get(3).copied().unwrap_or(0),
                );
                stage_parts.push(format!(
                    "{stage}(hash={hash:#018x},raw_len={},fourcc=0x{fourcc},dxpk_hit={dxpk_hit})",
                    slice.len()
                ));
            }
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::CreatePipelineState(stub)",
                hr,
                &format!(
                    "stage={primary_stage} hash={primary_hash:#018x} bytes={} tags={tags:?} rtv_fmts={rtv_fmts_logged:?} num_rt={num_rt_logged} dsv_fmt={dsv_fmt_logged} input_elems={input_elems_logged} sample_cnt={sample_cnt_logged} stages=[{}]",
                    pc_stream.len(),
                    stage_parts.join(", ")
                ),
            );
        }
    }
    S_OK
}

extern "system" fn dev_create_command_list(
    this: *mut DeviceX,
    node_mask: u32,
    ty: u32,
    allocator: *mut AllocatorX,
    pso: *mut PipelineX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() || allocator.is_null() {
        return E_INVALIDARG;
    }
    let d = unsafe { &*this };
    let real_alloc = unsafe { &*allocator }.real_alloc;
    let real_pso = if pso.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*pso }.real_pso
    };
    let mut real_list: *mut c_void = std::ptr::null_mut();
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        u32,
        u32,
        *mut c_void,
        *mut c_void,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let hr = unsafe {
        com_slot::<FnTy>(d.real_device, 12)(
            d.real_device,
            node_mask,
            ty,
            real_alloc,
            real_pso,
            &LIST_IIDS[0],
            &mut real_list,
        )
    };
    let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
    if hr < 0 {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateCommandList",
            hr,
            &format!("type={ty} node={node_mask:#x} iid={iid_str}"),
        );
        unsafe { *out = std::ptr::null_mut() };
        return hr;
    }
    if !is_guid_in(iid, &LIST_IIDS) {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateCommandList",
            E_NOINTERFACE,
            &format!("type={ty} E_NOINTERFACE iid={iid_str}"),
        );
        unsafe { real_release(real_list) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    dev_add_ref(this);
    let has_real_pso = !real_pso.is_null();
    let cur_pso_used_fallback = !pso.is_null() && unsafe { &*pso }.used_fallback_rs;
    let list = Box::new(ListX {
        vtable: if d.is_newer_dev11 {
            NEWER_LIST_VTABLE.0.as_ptr()
        } else {
            LIST_VTABLE.0.as_ptr()
        },
        bits: 0,
        refs: AtomicU32::new(1),
        kind: ty,
        put: [0; 5],
        _xbox_pad: [0; 1384],
        parent_dev: this,
        real_list,
        closed: AtomicBool::new(false),
        has_real_pso: AtomicBool::new(has_real_pso),
        cur_pso_used_fallback: AtomicBool::new(cur_pso_used_fallback),
        last_cmp_pso_upgrade: AtomicUsize::new(0),
        uploads: Mutex::new(Vec::new()),
        recent_ops: Mutex::new(([("", 0, 0); 16], 0)),
        last_pso: AtomicUsize::new(real_pso as usize),
        last_gfx_rs: AtomicUsize::new(0),
        last_vb_count: AtomicU32::new(0),
        last_rtv_count: AtomicU32::new(0),
    });
    let wrapped = Box::into_raw(list).cast();
    unsafe { *out = wrapped };
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateCommandList",
        S_OK,
        &format!("type={ty} node={node_mask:#x} out={wrapped:?}"),
    );
    S_OK
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XboxCmdListDesc {
    ty: u32,
    flags: u32,
}

extern "system" fn dev_create_command_list_x(
    this: *mut DeviceX,
    desc: *const XboxCmdListDesc,
    allocator: *mut AllocatorX,
    pso: *mut PipelineX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    let Some(xd) = (unsafe { desc.as_ref() }) else {
        return E_INVALIDARG;
    };
    dev_create_command_list(this, 0, xd.ty, allocator, pso, iid, out)
}

extern "system" fn dev_check_feature_support(
    this: *mut DeviceX,
    feature: u32,
    data: *mut c_void,
    size: u32,
) -> HRESULT {
    let real = unsafe { &*this }.real_device;
    if feature == 0 && size == 64 && !data.is_null() {
        let mut pc_opts = [0u32; 15];
        type FnTy = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> HRESULT;
        let hr = unsafe { com_slot::<FnTy>(real, 13)(real, 0, pc_opts.as_mut_ptr().cast(), 60) };
        if hr >= 0 {
            let mut xb_opts = [0u32; 16];
            xb_opts[..11].copy_from_slice(&pc_opts[..11]);
            xb_opts[11] = 0;
            xb_opts[12..16].copy_from_slice(&pc_opts[11..15]);
            unsafe { data.cast::<[u32; 16]>().write_unaligned(xb_opts) };
        }
        return hr;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> HRESULT;
    unsafe { com_slot::<FnTy>(real, 13)(real, feature, data, size) }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DescriptorHeapDesc {
    pub ty: u32,
    pub num_descriptors: u32,
    pub flags: u32,
    pub node_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HeapPlacement {
    address: u64,
    size: u64,
}

extern "system" fn dev_create_descriptor_heap(
    this: *mut DeviceX,
    desc_ptr: *const DescriptorHeapDesc,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(&desc) = (unsafe { desc_ptr.as_ref() }) else {
        return E_INVALIDARG;
    };
    let Some(xb_stride) = xbox_descriptor_stride(desc.ty) else {
        return E_INVALIDARG;
    };
    if !is_guid_in(iid, &DESC_HEAP_IIDS) {
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }

    let pc_stride = dev_get_desc_inc_size(this, desc.ty).max(1);
    let xb_size = u64::from(xb_stride) * u64::from(desc.num_descriptors.max(1));
    let pc_size = u64::from(pc_stride) * u64::from(desc.num_descriptors.max(1));
    let alloc_size = u64::from(pc_stride.max(xb_stride)) * u64::from(desc.num_descriptors.max(1));
    let placement = unsafe { desc_ptr.add(1).cast::<HeapPlacement>().read_unaligned() };
    let placed = placement.address != 0 && (placement.size == xb_size || placement.size == pc_size);
    let range_bytes = if placed { placement.size } else { alloc_size };

    let d = unsafe { &*this };
    let mut pc_desc = desc;
    pc_desc.flags &= 1; // Strip Xbox-only descriptor heap flags
    // Win32 D3D12 caps SHADER_VISIBLE CBV_SRV_UAV heaps at 1,000,000 (Tier 2 limit).
    const MAX_PC_SHADER_VISIBLE_CBV_SRV_UAV: u32 = 1_000_000;
    if pc_desc.ty == 0
        && (pc_desc.flags & 1) != 0
        && pc_desc.num_descriptors > MAX_PC_SHADER_VISIBLE_CBV_SRV_UAV
    {
        pc_desc.num_descriptors = MAX_PC_SHADER_VISIBLE_CBV_SRV_UAV;
    }
    let mut real_heap: *mut c_void = std::ptr::null_mut();
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        *const DescriptorHeapDesc,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let hr = unsafe {
        com_slot::<FnTy>(d.real_device, 14)(d.real_device, &pc_desc, &DESC_HEAP_IIDS[0], &mut real_heap)
    };
    log_if_device_removed(d.real_device, "DeviceX::CreateDescriptorHeap", hr);
    drain_info_queue(d.info_queue, "CreateDescriptorHeap");
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateDescriptorHeap",
        hr,
        &format!(
            "ty={} num={}->{} flags={:#x}->{:#x} placed={} xb_size={xb_size:#x} pl_addr={:#x} pl_sz={:#x} real={real_heap:?}",
            desc.ty, desc.num_descriptors, pc_desc.num_descriptors, desc.flags, pc_desc.flags,
            placed, placement.address, placement.size
        ),
    );

    let (pc_cpu_start, pc_gpu_start) = if hr >= 0 && !real_heap.is_null() {
        type HandleFn = unsafe extern "system" fn(*mut c_void, *mut u64) -> *mut u64;
        let mut cpu = 0u64;
        let mut gpu = 0u64;
        unsafe { com_slot::<HandleFn>(real_heap, 9)(real_heap, &mut cpu) };
        if (desc.flags & 1) != 0 {
            unsafe { com_slot::<HandleFn>(real_heap, 10)(real_heap, &mut gpu) };
        }
        (cpu, gpu)
    } else {
        (0, 0)
    };

    let (cpu_start, owned_mem) = if placed {
        (placement.address, None)
    } else {
        let Ok(bytes) = usize::try_from(alloc_size) else {
            return E_INVALIDARG;
        };
        let Ok(layout) = Layout::from_size_align(bytes.max(64), 64) else {
            return E_INVALIDARG;
        };
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return 0x8007_000E_u32 as i32; // E_OUTOFMEMORY
        }
        (ptr as u64, Some((ptr, layout)))
    };

    if pc_cpu_start != 0 {
        let mut ranges = HEAP_RANGES.lock().unwrap_or_else(|e| e.into_inner());
        ranges.push(HeapRange {
            heap_ty: desc.ty,
            xb_start: cpu_start,
            xb_end: cpu_start.saturating_add(range_bytes),
            xb_stride: pc_stride,
            pc_start: pc_cpu_start,
            pc_gpu_start,
            pc_stride,
            pc_count: pc_desc.num_descriptors.max(1),
        });
    }

    dev_add_ref(this);
    let obj = Box::new(DescriptorHeapX {
        vtable: DESC_HEAP_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        desc,
        cpu_start,
        gpu_start: if placed { cpu_start } else if pc_gpu_start != 0 { pc_gpu_start } else { cpu_start },
        owned_mem,
        parent_dev: this,
        real_heap,
    });
    unsafe { *out = Box::into_raw(obj).cast() };
    S_OK
}

extern "system" fn dev_get_desc_inc_size(this: *mut DeviceX, ty: u32) -> u32 {
    if ty > 3 {
        static INVALID_TY_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = INVALID_TY_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 4 {
            boot_trace(
                "dx12xs_pc",
                "DeviceX::GetDescriptorHandleIncrementSize",
                &format!("invalid heap type={ty} -> 0"),
            );
        }
        return 0;
    }
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    unsafe { com_slot::<FnTy>(real, 15)(real, ty) }
}

extern "system" fn dev_create_root_signature(
    this: *mut DeviceX,
    node_mask: u32,
    blob: *const c_void,
    blob_len: usize,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateRootSignature",
            E_POINTER,
            "out=null",
        );
        return E_POINTER;
    }
    let d = unsafe { &*this };
    let real = d.real_device;
    let pre_reason = query_real_removed_reason(real);
    let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());

    // Ensure every root signature passed to CreateRootSignature carries 0xC00
    // (CBV_SRV_UAV_HEAP_DIRECTLY_INDEXED | SAMPLER_HEAP_DIRECTLY_INDEXED) so DXPK SM 6.6
    // shaders never fail (#882) or mismatch at Dispatch() time.
    let mut patched_blob: *mut c_void = std::ptr::null_mut();
    let mut synthetic_slots = crate::take_synthetic_slots_for_blob(blob, blob_len);
    let (use_blob, use_len) = if !blob.is_null() && blob_len >= 16 {
        let d3d12 = crate::host_d3d12();
        let mut upgraded = (blob, blob_len);
        if !d3d12.is_null() {
            if let Some(create_deser) =
                unsafe { GetProcAddress(d3d12, c"D3D12CreateVersionedRootSignatureDeserializer".as_ptr().cast()) }
            {
                type DeserFn = unsafe extern "system" fn(
                    *const c_void,
                    usize,
                    *const Guid,
                    *mut *mut c_void,
                ) -> HRESULT;
                let deser_fn: DeserFn = unsafe { std::mem::transmute(create_deser) };
                let deser_iid = Guid::new(
                    0x7f91_ce67,
                    0x090c,
                    0x4bb7,
                    [0xb7, 0x8e, 0xed, 0x8f, 0xf2, 0xe3, 0x1d, 0xa0],
                );
                let mut deser: *mut c_void = std::ptr::null_mut();
                if unsafe { deser_fn(blob, blob_len, &deser_iid, &mut deser) } >= 0 && !deser.is_null() {
                    type GetUnconvFn = unsafe extern "system" fn(*mut c_void) -> *const crate::D3D12VersionedRootSigDesc;
                    let raw_desc = unsafe { com_slot::<GetUnconvFn>(deser, 4)(deser) };
                    if let Some(rd) = unsafe { raw_desc.as_ref() } {
                        crate::log_unique_root_sig(
                            "dev_create_root_signature",
                            rd,
                            synthetic_slots.unwrap_or_default(),
                            0,
                        );
                        let needs_flags = (rd.desc.flags & 0x40) == 0 && (rd.desc.flags & 0xC00) != 0xC00;
                        let needs_inj =
                            synthetic_slots.is_none() && crate::needs_synthetic_rs_injection(rd);
                        if needs_flags || needs_inj {
                            let mut err_blob: *mut c_void = std::ptr::null_mut();
                            let ser_hr = crate::D3D12SerializeVersionedRootSignature(
                                raw_desc.cast(),
                                &mut patched_blob,
                                &mut err_blob,
                            );
                            if !err_blob.is_null() {
                                unsafe { real_release(err_blob) };
                            }
                            if ser_hr >= 0 && !patched_blob.is_null() {
                                let vtbl = unsafe { *patched_blob.cast::<*const *const c_void>() };
                                type GetPtrFn = unsafe extern "system" fn(*mut c_void) -> *const c_void;
                                type GetSzFn = unsafe extern "system" fn(*mut c_void) -> usize;
                                let gp: GetPtrFn = unsafe { std::mem::transmute(*vtbl.add(3)) };
                                let gs: GetSzFn = unsafe { std::mem::transmute(*vtbl.add(4)) };
                                let (up_ptr, up_len) = (unsafe { gp(patched_blob) }, unsafe { gs(patched_blob) });
                                upgraded = (up_ptr, up_len);
                                if synthetic_slots.is_none() {
                                    synthetic_slots = crate::take_synthetic_slots_for_blob(up_ptr, up_len);
                                }
                            }
                        }
                    }
                    unsafe { real_release(deser) };
                }
            }
        }
        upgraded
    } else {
        (blob, blob_len)
    };

    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *const c_void,
        usize,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(real, 16)(real, node_mask, use_blob, use_len, iid, out) };
    if !patched_blob.is_null() {
        unsafe { real_release(patched_blob) };
    }
    let out_ptr = unsafe { *out };
    if hr >= 0 && !out_ptr.is_null() {
        if !use_blob.is_null() && use_len > 0 && use_len <= 65536 {
            let saved = unsafe { std::slice::from_raw_parts(use_blob.cast::<u8>(), use_len) }.to_vec();
            d.rs_blobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(out_ptr as usize, saved);
        }
        if let Some(slots) = synthetic_slots {
            d.synthetic_rs_slots
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(out_ptr as usize, slots);
        }
    }
    drain_info_queue(d.info_queue, "CreateRootSignature");
    if hr < 0 {
        let post_reason = query_real_removed_reason(real);
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateRootSignature",
            hr,
            &format!(
                "node={node_mask:#x} len={blob_len} iid={iid_str} out={out_ptr:?} pre_reason={:#010x} post_reason={:#010x}",
                pre_reason as u32, post_reason as u32
            ),
        );
        log_if_device_removed(real, "DeviceX::CreateRootSignature", hr);
    } else {
        let b0 = synthetic_slots.and_then(|s| s.b0_slot);
        let t255 = synthetic_slots.and_then(|s| s.t255_s1_slot);
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateRootSignature",
            hr,
            &format!("node={node_mask:#x} len={blob_len} iid={iid_str} synth_b0={b0:?} synth_t255={t255:?} out={out_ptr:?}"),
        );
    }
    hr
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CbvDescRaw {
    buffer_location: u64,
    size_in_bytes: u32,
    _pad: u32,
}

extern "system" fn dev_create_cbv(this: *mut DeviceX, desc: *const c_void, cpu: u64) {
    let pc_opt = translate_cpu_handle_for_ty(cpu, Some(0));
    static CBV_LOGS: AtomicU32 = AtomicU32::new(0);
    let cbv_n = CBV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    let raw_cbv = if desc.is_null() {
        CbvDescRaw {
            buffer_location: 0,
            size_in_bytes: 0,
            _pad: 0,
        }
    } else {
        unsafe { desc.cast::<CbvDescRaw>().read_unaligned() }
    };
    if cbv_n <= 16 || pc_opt.is_none() {
        static CBV_MISS_LOGS: AtomicU32 = AtomicU32::new(0);
        let log_miss = pc_opt.is_none() && CBV_MISS_LOGS.fetch_add(1, Ordering::Relaxed) < 16;
        if cbv_n <= 16 || log_miss {
            boot_trace(
                "dx12xs_pc",
                "DeviceX::CreateConstantBufferView",
                &format!(
                    "#{cbv_n} xb_cpu={cpu:#x} pc_cpu={:?} loc={:#x} size={}",
                    pc_opt.map(|v| format!("{v:#x}")),
                    raw_cbv.buffer_location,
                    raw_cbv.size_in_bytes
                ),
            );
        }
    }
    let Some(pc_cpu) = pc_opt else {
        return;
    };
    let d = unsafe { &*this };
    let real = d.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *const c_void, u64);

    if desc.is_null() {
        unsafe { com_slot::<FnTy>(real, 17)(real, std::ptr::null(), pc_cpu) };
        log_view_device_removed_once(real, "CreateConstantBufferView", std::ptr::null_mut(), std::ptr::null());
        drain_info_queue(d.info_queue, "CreateConstantBufferView(null)");
        return;
    }

    let aligned_size = raw_cbv.size_in_bytes.min(64 * 1024).next_multiple_of(256);

    if raw_cbv.buffer_location != 0
        && (raw_cbv.buffer_location % 256) == 0
        && aligned_size > 0
        && find_registered_gpu_buffer(raw_cbv.buffer_location, aligned_size)
    {
        let clean = CbvDescRaw {
            buffer_location: raw_cbv.buffer_location,
            size_in_bytes: aligned_size,
            _pad: 0,
        };
        unsafe { com_slot::<FnTy>(real, 17)(real, (&raw const clean).cast(), pc_cpu) };
    } else if raw_cbv.buffer_location != 0 && aligned_size > 0 {
        if let Some(pc_va) = upload_cpu_slice_to_gpu_va(
            d,
            raw_cbv.buffer_location,
            (raw_cbv.size_in_bytes as usize).min(aligned_size as usize),
            aligned_size as usize,
            256,
        ) {
            static UMA_CBV_LOGS: AtomicU32 = AtomicU32::new(0);
            let n = UMA_CBV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 16 {
                boot_trace(
                    "dx12xs_pc",
                    "DeviceX::CreateConstantBufferView(uma-upload)",
                    &format!(
                        "#{n} xb={:#x} pc={pc_va:#x} size={}->{aligned_size}",
                        raw_cbv.buffer_location, raw_cbv.size_in_bytes
                    ),
                );
            }
            let clean = CbvDescRaw {
                buffer_location: pc_va,
                size_in_bytes: aligned_size,
                _pad: 0,
            };
            unsafe { com_slot::<FnTy>(real, 17)(real, (&raw const clean).cast(), pc_cpu) };
        } else {
            static UNTRACKED_CBV_LOGS: AtomicU32 = AtomicU32::new(0);
            let n = UNTRACKED_CBV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 8 || n.is_power_of_two() {
                boot_trace(
                    "dx12xs_pc",
                    "DeviceX::CreateConstantBufferView(null-fallback)",
                    &format!(
                        "loc={:#x} size={}->{} count={n}",
                        raw_cbv.buffer_location, raw_cbv.size_in_bytes, aligned_size
                    ),
                );
            }
            unsafe { com_slot::<FnTy>(real, 17)(real, std::ptr::null(), pc_cpu) };
        }
    } else {
        // Untranslated Xbox UMA CPU VA or unaligned/zero CBV: bind a valid Win32 null CBV
        // so D3D12Core never triggers DXGI_ERROR_INVALID_CALL / Device Removed.
        static UNTRACKED_CBV_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = UNTRACKED_CBV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 8 || n.is_power_of_two() {
            boot_trace(
                "dx12xs_pc",
                "DeviceX::CreateConstantBufferView(null-fallback)",
                &format!(
                    "loc={:#x} size={}->{} count={n}",
                    raw_cbv.buffer_location, raw_cbv.size_in_bytes, aligned_size
                ),
            );
        }
        unsafe { com_slot::<FnTy>(real, 17)(real, std::ptr::null(), pc_cpu) };
    }
    log_view_device_removed_once(real, "CreateConstantBufferView", std::ptr::null_mut(), desc);
    drain_info_queue(d.info_queue, "CreateConstantBufferView");
}

extern "system" fn dev_create_srv(
    this: *mut DeviceX,
    res: *mut ResourceX,
    desc: *const c_void,
    cpu: u64,
) {
    let Some(pc_cpu) = translate_cpu_handle_for_ty(cpu, Some(0)) else {
        return;
    };
    let d = unsafe { &*this };
    let real = d.real_device;
    let real_res = if res.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*res }.real_resource
    };
    let mut desc_scratch = ViewDesc40([0; 10]);
    let pc_desc = patch_view_desc_remapped(res, desc, &mut desc_scratch);
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, u64);
    unsafe { com_slot::<FnTy>(real, 18)(real, real_res, pc_desc, pc_cpu) };
    log_view_device_removed_once(real, "CreateShaderResourceView", res, pc_desc);
    drain_info_queue(d.info_queue, "CreateShaderResourceView");
}

extern "system" fn dev_create_uav(
    this: *mut DeviceX,
    res: *mut ResourceX,
    counter: *mut ResourceX,
    desc: *const c_void,
    cpu: u64,
) {
    let Some(pc_cpu) = translate_cpu_handle_for_ty(cpu, Some(0)) else {
        return;
    };
    let d = unsafe { &*this };
    let real = d.real_device;
    let mut desc_scratch = ViewDesc40([0; 10]);
    let (real_res, real_cnt, pc_desc) = if !res.is_null() {
        let rr = unsafe { &*res };
        if !resource_allows_pc_uav(&rr.desc) {
            let clean_desc = sanitize_resource_desc(&rr.desc);
            let fallback_desc = sanitize_uav_fallback_desc(desc, &mut desc_scratch);
            static NON_UAV_LOGS: AtomicU32 = AtomicU32::new(0);
            let n = NON_UAV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 16 {
                boot_trace(
                    "dx12xs_pc",
                    "CreateUnorderedAccessView(non-uav-null-fallback)",
                    &format!(
                        "#{n} res={:?} res_fmt={} raw_flags={:#x} clean_flags={:#x} pc_fmt={} dim={}",
                        rr.real_resource,
                        rr.desc.format,
                        rr.desc.flags,
                        clean_desc.flags,
                        desc_scratch.0[0],
                        desc_scratch.0[1]
                    ),
                );
            }
            (std::ptr::null_mut(), std::ptr::null_mut(), fallback_desc)
        } else {
            let real_cnt = if counter.is_null() {
                std::ptr::null_mut()
            } else {
                unsafe { &*counter }.real_resource
            };
            (rr.real_resource, real_cnt, patch_view_desc_remapped(res, desc, &mut desc_scratch))
        }
    } else {
        let real_cnt = if counter.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe { &*counter }.real_resource
        };
        (std::ptr::null_mut(), real_cnt, patch_view_desc_remapped(res, desc, &mut desc_scratch))
    };
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void, *const c_void, u64);
    unsafe { com_slot::<FnTy>(real, 19)(real, real_res, real_cnt, pc_desc, pc_cpu) };
    log_view_device_removed_once(real, "CreateUnorderedAccessView", res, pc_desc);
    drain_info_queue(d.info_queue, "CreateUnorderedAccessView");
}

extern "system" fn dev_create_rtv(
    this: *mut DeviceX,
    res: *mut ResourceX,
    desc: *const c_void,
    cpu: u64,
) {
    let Some(pc_cpu) = translate_cpu_handle_for_ty(cpu, Some(2)) else {
        return;
    };
    let d = unsafe { &*this };
    let real = d.real_device;
    let real_res = if res.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*res }.real_resource
    };
    bind_view_resource(pc_cpu, real_res);
    let mut pc_desc = [0u32; 5];
    let (raw_desc_opt, pc_desc_ptr) = if desc.is_null() {
        (None, std::ptr::null())
    } else {
        let raw_desc = unsafe { desc.cast::<[u32; 5]>().read_unaligned() };
        pc_desc = raw_desc;
        pc_desc[0] = remap_view_format_for_writable(res, raw_desc[0]);
        (Some(raw_desc), (&raw const pc_desc).cast::<c_void>())
    };
    static RTV_LOGS: AtomicU32 = AtomicU32::new(0);
    let rtv_n = RTV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if rtv_n <= 32 {
        let res_info = if res.is_null() {
            String::from("null")
        } else {
            let rd = unsafe { &*res }.desc;
            format!("dim={} {}x{} fmt={} flg={:#x}", rd.dimension, rd.width, rd.height, rd.format, rd.flags)
        };
        let rtv_desc_str = match raw_desc_opt {
            Some(r) => format!(
                "[{:#x},{:#x},{:#x},{:#x},{:#x}]->fmt={}",
                r[0], r[1], r[2], r[3], r[4], pc_desc[0]
            ),
            None => String::from("null"),
        };
        boot_trace(
            "dx12xs_pc",
            "DeviceX::CreateRenderTargetView",
            &format!("#{rtv_n} real_res={real_res:?} pc_cpu={pc_cpu:#x} desc={rtv_desc_str} [{res_info}]"),
        );
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, u64);
    unsafe { com_slot::<FnTy>(real, 20)(real, real_res, pc_desc_ptr, pc_cpu) };
    log_view_device_removed_once(real, "CreateRenderTargetView", res, pc_desc_ptr);
    drain_info_queue(d.info_queue, "CreateRenderTargetView");
}

extern "system" fn dev_create_dsv(
    this: *mut DeviceX,
    res: *mut ResourceX,
    desc: *const c_void,
    cpu: u64,
) {
    let Some(pc_cpu) = translate_cpu_handle_for_ty(cpu, Some(3)) else {
        return;
    };
    let d = unsafe { &*this };
    let real = d.real_device;
    let real_res = if res.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*res }.real_resource
    };
    bind_view_resource(pc_cpu, real_res);
    static DSV_LOGS: AtomicU32 = AtomicU32::new(0);
    let dsv_n = DSV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if dsv_n <= 32 {
        let desc_info = if res.is_null() {
            String::from("null")
        } else {
            let rr = unsafe { &*res };
            let rd = rr.desc;
            format!(
                "hp_ty={} dim={} {}x{} fmt={} flg={:#x}",
                rr.heap_ty, rd.dimension, rd.width, rd.height, rd.format, rd.flags
            )
        };
        boot_trace(
            "dx12xs_pc",
            "DeviceX::CreateDepthStencilView",
            &format!("#{dsv_n} real_res={real_res:?} has_desc={} pc_cpu={pc_cpu:#x} [{desc_info}]", !desc.is_null()),
        );
    }
    let mut dsv_scratch;
    let pc_desc = if desc.is_null() {
        std::ptr::null()
    } else {
        dsv_scratch = unsafe { desc.cast::<[u32; 6]>().read_unaligned() };
        let mapped = map_xbox_dxgi_format(dsv_scratch[0]);
        dsv_scratch[0] = if matches!(mapped, 19 | 39 | 44 | 53) {
            sanitize_dsv_format(mapped)
        } else {
            mapped
        };
        (&raw const dsv_scratch).cast::<c_void>()
    };
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, u64);
    unsafe { com_slot::<FnTy>(real, 21)(real, real_res, pc_desc, pc_cpu) };
    log_view_device_removed_once(real, "CreateDepthStencilView", res, pc_desc);
    drain_info_queue(d.info_queue, "CreateDepthStencilView");
}

extern "system" fn dev_create_sampler(this: *mut DeviceX, desc: *const c_void, cpu: u64) {
    let Some(pc_cpu) = translate_cpu_handle_for_ty(cpu, Some(1)) else {
        return;
    };
    let d = unsafe { &*this };
    let real = d.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *const c_void, u64);
    unsafe { com_slot::<FnTy>(real, 22)(real, desc, pc_cpu) };
    drain_info_queue(d.info_queue, "CreateSampler");
}

extern "system" fn dev_copy_descriptors(
    this: *mut DeviceX,
    n_dst: u32,
    dst_starts: *const u64,
    dst_sizes: *const u32,
    n_src: u32,
    src_starts: *const u64,
    src_sizes: *const u32,
    heap_ty: u32,
) {
    let real = unsafe { &*this }.real_device;
    static COPY_LOGS: AtomicU32 = AtomicU32::new(0);
    if COPY_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
        boot_trace("dx12xs_pc", "DeviceX::CopyDescriptors", &format!("n_dst={n_dst} n_src={n_src} ty={heap_ty}"));
    }
    let mut dst_vec: Vec<u64> = Vec::new();
    if !dst_starts.is_null() {
        for i in 0..(n_dst as usize) {
            let h = unsafe { dst_starts.add(i).read_unaligned() };
            let Some(pc_h) = translate_cpu_handle_for_ty(h, Some(heap_ty)) else {
                return;
            };
            dst_vec.push(pc_h);
        }
    }
    let mut src_vec: Vec<u64> = Vec::new();
    if !src_starts.is_null() {
        for i in 0..(n_src as usize) {
            let h = unsafe { src_starts.add(i).read_unaligned() };
            let Some(pc_h) = translate_cpu_handle_for_ty(h, Some(heap_ty)) else {
                return;
            };
            src_vec.push(pc_h);
        }
    }
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *const u64,
        *const u32,
        u32,
        *const u64,
        *const u32,
        u32,
    );
    unsafe {
        com_slot::<FnTy>(real, 23)(
            real,
            n_dst,
            dst_vec.as_ptr(),
            dst_sizes,
            n_src,
            src_vec.as_ptr(),
            src_sizes,
            heap_ty,
        )
    }
}

extern "system" fn dev_copy_descriptors_simple(
    this: *mut DeviceX,
    n: u32,
    dst: u64,
    src: u64,
    heap_ty: u32,
) {
    let (Some(pc_dst), Some(pc_src)) = (
        translate_cpu_handle_for_ty(dst, Some(heap_ty)),
        translate_cpu_handle_for_ty(src, Some(heap_ty)),
    ) else {
        return;
    };
    static COPY_SIMPLE_LOGS: AtomicU32 = AtomicU32::new(0);
    if heap_ty == 0 && COPY_SIMPLE_LOGS.fetch_add(1, Ordering::Relaxed) < 8 {
        boot_trace("dx12xs_pc", "DeviceX::CopyDescriptorsSimple(ty0)", &format!("n={n} ty={heap_ty} dst={dst:#x}->{pc_dst:#x} src={src:#x}->{pc_src:#x}"));
    }
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u64, u64, u32);
    unsafe { com_slot::<FnTy>(real, 24)(real, n, pc_dst, pc_src, heap_ty) }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResourceDescRaw {
    pub dimension: u32,
    pub alignment: u64,
    pub width: u64,
    pub height: u32,
    pub depth_or_array: u16,
    pub mip_levels: u16,
    pub format: u32,
    pub sample_count: u32,
    pub sample_quality: u32,
    pub layout: u32,
    pub flags: u32,
}

pub(crate) fn map_xbox_dxgi_format(fmt: u32) -> u32 {
    match fmt {
        116 | 117 | 189 => 24,
        118 => 45,
        119 => 46,
        120 => 47,
        190 => 115,
        191 => 87,
        other => other,
    }
}

pub(crate) fn sanitize_primitive_topology_type(topo: u32) -> u32 {
    if topo == 0 || topo > 4 { 3 } else { topo }
}

pub(crate) fn sanitize_primitive_topology(topo: u32) -> u32 {
    match topo {
        1..=5 | 10..=13 | 33..=64 => topo,
        _ => 4,
    }
}

pub(crate) fn sanitize_dsv_format(fmt: u32) -> u32 {
    match map_xbox_dxgi_format(fmt) {
        19 => 20, // R32G8X24_TYPELESS -> D32_FLOAT_S8X24_UINT
        39 => 40, // R32_TYPELESS -> D32_FLOAT
        44 => 45, // R24G8_TYPELESS -> D24_UNORM_S8_UINT
        53 | 54 => 55, // R16_TYPELESS (53) / R16_FLOAT (54) -> D16_UNORM (55)
        other => other,
    }
}

fn is_typeless_format(fmt: u32) -> bool {
    matches!(fmt, 19 | 27 | 39 | 44 | 53 | 70 | 73 | 76 | 90)
}

fn sanitize_resource_desc(desc: &ResourceDescRaw) -> ResourceDescRaw {
    let mut out = *desc;
    out.alignment = 0;
    out.layout = if out.dimension == 1 { 1 } else { 0 };
    out.flags &= 0x0F;
    if (out.flags & 0x2) != 0 {
        // Win32 forbids ALLOW_DEPTH_STENCIL | ALLOW_UNORDERED_ACCESS.
        out.flags &= !0x4;
    }
    out.format = map_xbox_dxgi_format(out.format);
    if (out.flags & 0x2) != 0 && (out.flags & 0x8) == 0 {
        out.format = match out.format {
            20 => 19,
            40 => 39,
            45 => 44,
            55 => 53,
            other => other,
        };
    }
    if (out.flags & 0x5) != 0 {
        // PC D3D12 forbids ALLOW_RENDER_TARGET / ALLOW_UNORDERED_ACCESS on R9G9B9E5_SHAREDEXP (67)
        // and ALLOW_RENDER_TARGET / ALLOW_UNORDERED_ACCESS on B4G4R4A4_UNORM (115); remap writable
        // instances to R11G11B10_FLOAT (26) / B8G8R8A8_UNORM (87), leaving SRV-only intact.
        if let Some(pc_fmt) = writable_format_remap(out.format) {
            out.format = pc_fmt;
        }
    }
    if (out.flags & 0x4) != 0 {
        // Win32 forbids ALLOW_UNORDERED_ACCESS on sRGB, packed 16-bit (B5G6R5/B5G5R5A1),
        // and block-compressed formats.
        if matches!(out.format, 70..=86 | 94..=99) {
            out.flags &= !0x4;
        }
        out.format = match out.format {
            29 => 27,
            72 => 70,
            75 => 73,
            78 => 76,
            91 => 90,
            other => other,
        };
    }
    out
}

fn writable_format_remap(fmt: u32) -> Option<u32> {
    match fmt {
        67 => Some(26),  // R9G9B9E5_SHAREDEXP -> R11G11B10_FLOAT
        115 => Some(87), // B4G4R4A4_UNORM -> B8G8R8A8_UNORM
        _ => None,
    }
}

fn resource_allows_pc_uav(raw_desc: &ResourceDescRaw) -> bool {
    (sanitize_resource_desc(raw_desc).flags & 0x4) != 0
}

fn sanitize_uav_fallback_desc(desc: *const c_void, scratch: &mut ViewDesc40) -> *const c_void {
    if desc.is_null() {
        scratch.0 = [0; 10];
        scratch.0[0] = 42; // DXGI_FORMAT_R32_UINT
        scratch.0[1] = 1; // D3D12_UAV_DIMENSION_BUFFER
        return (&raw const scratch.0).cast();
    }
    let mut words = unsafe { desc.cast::<[u32; 10]>().read_unaligned() };
    if words[1] == 0 {
        words[1] = 1; // D3D12_UAV_DIMENSION_BUFFER
    }
    let mapped = map_xbox_dxgi_format(words[0]);
    let clean_fmt = match mapped {
        0 => {
            if words[1] == 1 && words[5] != 0 {
                0
            } else {
                42
            }
        }
        53 => 56, // R16_TYPELESS -> R16_UNORM
        19 | 39 | 44 | 54 | 27 | 70..=86 | 90..=99 => 42, // R32_UINT
        67 => 26,
        115 => 87,
        other => other,
    };
    if words[1] == 4 {
        words[3] = 0; // PlaneSlice = 0 for TEXTURE2D
    } else if words[1] == 5 {
        words[4] = words[4].max(1); // ArraySize >= 1 for TEXTURE2DARRAY
        words[5] = 0; // PlaneSlice = 0 for TEXTURE2DARRAY
    }
    words[0] = clean_fmt;
    scratch.0 = words;
    (&raw const scratch.0).cast()
}

fn map_rtv_format(fmt: u32) -> u32 {
    let mapped = map_xbox_dxgi_format(fmt);
    writable_format_remap(mapped).unwrap_or(mapped)
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct ViewDesc40([u32; 10]);

fn remapped_writable_resource_target(res: *mut ResourceX) -> Option<(u32, u32)> {
    if res.is_null() {
        return None;
    }
    let desc = unsafe { &*res }.desc;
    if (desc.flags & 0x5) == 0 {
        return None;
    }
    let xb_fmt = map_xbox_dxgi_format(desc.format);
    writable_format_remap(xb_fmt).map(|pc_fmt| (xb_fmt, pc_fmt))
}

fn remap_view_format_for_writable(res: *mut ResourceX, fmt: u32) -> u32 {
    let mapped = map_xbox_dxgi_format(fmt);
    if let Some((xb_fmt, pc_fmt)) = remapped_writable_resource_target(res) {
        if mapped == xb_fmt {
            return pc_fmt;
        }
    }
    mapped
}

fn log_view_device_removed_once(
    real: *mut c_void,
    op: &str,
    res: *mut ResourceX,
    desc: *const c_void,
) {
    static VIEW_REMOVED_LOGGED: AtomicBool = AtomicBool::new(false);
    if VIEW_REMOVED_LOGGED.load(Ordering::Relaxed) || real.is_null() {
        return;
    }
    let reason = query_real_removed_reason(real);
    if reason != S_OK
        && VIEW_REMOVED_LOGGED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
    {
        let res_info = if res.is_null() {
            String::from("res=null")
        } else {
            let rr = unsafe { &*res };
            let rd = rr.desc;
            let cd = sanitize_resource_desc(&rd);
            format!(
                "res={:?} dim={} {}x{}x{} mips={} fmt={}->{} flg={:#x}->{:#x}",
                rr.real_resource,
                rd.dimension,
                rd.width,
                rd.height,
                rd.depth_or_array,
                rd.mip_levels,
                rd.format,
                cd.format,
                rd.flags,
                cd.flags
            )
        };
        let desc_info = if desc.is_null() {
            String::from("desc=null")
        } else if op == "CreateConstantBufferView" {
            let w = unsafe { desc.cast::<[u32; 4]>().read_unaligned() };
            format!("desc=[{:#x},{:#x},{:#x},{:#x}]", w[0], w[1], w[2], w[3])
        } else {
            let w = unsafe { desc.cast::<[u32; 5]>().read_unaligned() };
            format!(
                "desc=[{:#x},{:#x},{:#x},{:#x},{:#x}]",
                w[0], w[1], w[2], w[3], w[4]
            )
        };
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::ViewDeviceRemoved",
            reason,
            &format!("op={op} reason={:#010x} {res_info} {desc_info}", reason as u32),
        );
    }
}

fn patch_view_desc_remapped(
    res: *mut ResourceX,
    desc: *const c_void,
    scratch: &mut ViewDesc40,
) -> *const c_void {
    if desc.is_null() {
        return desc;
    }
    let mut words = unsafe { desc.cast::<[u32; 10]>().read_unaligned() };
    let mapped = remap_view_format_for_writable(res, words[0]);
    if mapped != words[0] {
        words[0] = mapped;
        scratch.0 = words;
        (&raw const scratch.0).cast()
    } else {
        desc
    }
}

fn sanitize_clear_value(
    clean_desc: &ResourceDescRaw,
    clear_val: *const c_void,
    scratch: &mut [u32; 5],
) -> *const c_void {
    if clear_val.is_null()
        || is_typeless_format(clean_desc.format)
        || (clean_desc.flags & 0x3) == 0
    {
        return std::ptr::null();
    }
    *scratch = unsafe { clear_val.cast::<[u32; 5]>().read_unaligned() };
    scratch[0] = map_xbox_dxgi_format(scratch[0]);
    if let Some(pc_fmt) = writable_format_remap(scratch[0]) {
        if clean_desc.format == pc_fmt {
            scratch[0] = pc_fmt;
        }
    }
    scratch.as_ptr().cast()
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceDesc1Raw {
    desc: ResourceDescRaw,
    mip_region: [u32; 3],
    _pad: u32,
}
const _: () = assert!(size_of::<ResourceDesc1Raw>() == 72);

#[repr(C)]
#[derive(Clone, Copy)]
struct AllocationInfo1Raw {
    offset: u64,
    alignment: u64,
    size: u64,
}
const _: () = assert!(size_of::<AllocationInfo1Raw>() == 24);

fn estimate_resource_footprint(desc: &ResourceDescRaw) -> [u64; 2] {
    let align = if desc.alignment >= 65536 && desc.alignment.is_power_of_two() && desc.alignment <= 4 * 1024 * 1024 {
        desc.alignment
    } else {
        65536
    };
    let size = if desc.dimension == 1 {
        desc.width.max(1).next_multiple_of(align)
    } else {
        let w = desc.width.max(1);
        let h = u64::from(desc.height.max(1));
        let d = u64::from(desc.depth_or_array.max(1));
        let bpp = format_bpp(desc.format);
        let base = w.saturating_mul(h).saturating_mul(d).saturating_mul(bpp);
        let with_mips = if desc.mip_levels == 0 || desc.mip_levels > 1 { base.saturating_mul(2) } else { base };
        with_mips.max(align).next_multiple_of(align)
    };
    [size, align]
}

fn xbox_buffer_alloc_info(raw: &ResourceDescRaw) -> [u64; 2] {
    let align = if raw.alignment >= 256 && raw.alignment.is_power_of_two() && raw.alignment <= 65536 {
        raw.alignment
    } else {
        256
    };
    let size = raw.width.max(1).next_multiple_of(align);
    [size, align]
}

fn xbox_texture_alloc_info(raw: &ResourceDescRaw) -> [u64; 2] {
    let align = 65536u64;
    let w = raw.width.max(1);
    let h = u64::from(raw.height.max(1));
    let d = u64::from(raw.depth_or_array.max(1));
    let samples = u64::from(raw.sample_count.max(1));
    let fmt = map_xbox_dxgi_format(raw.format);
    let base = match fmt {
        70..=72 | 79..=81 => w
            .div_ceil(4)
            .saturating_mul(h.div_ceil(4))
            .saturating_mul(8)
            .saturating_mul(d),
        73..=78 | 82..=84 | 94..=99 => w
            .div_ceil(4)
            .saturating_mul(h.div_ceil(4))
            .saturating_mul(16)
            .saturating_mul(d),
        _ => w
            .saturating_mul(h)
            .saturating_mul(d)
            .saturating_mul(format_bpp(fmt))
            .saturating_mul(samples),
    };
    let with_mips = if raw.mip_levels == 0 || raw.mip_levels > 1 {
        base.saturating_add(base / 3)
    } else {
        base
    };
    [with_mips.max(align).next_multiple_of(align), align]
}

fn clamp_texture_alloc_info(pc_info: [u64; 2], xb: [u64; 2]) -> [u64; 2] {
    if pc_info[0] == u64::MAX || pc_info[1] == 0 {
        xb
    } else {
        [pc_info[0].min(xb[0]).max(65536).next_multiple_of(65536), 65536]
    }
}

fn query_single_resource_alloc(real: *mut c_void, raw: &ResourceDescRaw) -> [u64; 2] {
    if raw.dimension == 1 {
        return xbox_buffer_alloc_info(raw);
    }
    let clean = sanitize_resource_desc(raw);
    let mut info = [0u64; 2];
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *mut [u64; 2], u32, u32, *const ResourceDescRaw) -> *mut [u64; 2];
    unsafe { com_slot::<FnTy>(real, 25)(real, &mut info, 1, 1, &clean) };
    let xb = xbox_texture_alloc_info(raw);
    if info[0] == u64::MAX || info[1] == 0 {
        static FB_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = FB_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 32 {
            boot_trace(
                "dx12xs_pc",
                "GetResourceAllocationInfo::fallback",
                &format!(
                    "#{n} dim={} w={} h={} d={} mips={} fmt={}->{} flags={:#x} -> size={:#x} align={:#x}",
                    raw.dimension, raw.width, raw.height, raw.depth_or_array, raw.mip_levels,
                    raw.format, clean.format, raw.flags, xb[0], xb[1]
                ),
            );
        }
        xb
    } else {
        clamp_texture_alloc_info(info, xb)
    }
}

/// C-style `sret`-first ABI (`RCX = out_info`, `RDX = this`).
extern "system" fn dev_get_alloc_info(
    out_info: *mut [u64; 2],
    this: *mut DeviceX,
    visible_mask: u32,
    num_descs: u32,
    descs: *const ResourceDescRaw,
) -> *mut [u64; 2] {
    if out_info.is_null() {
        return out_info;
    }
    if num_descs == 0 || descs.is_null() {
        unsafe { out_info.write([0, 65536]) };
        return out_info;
    }
    let count = num_descs as usize;
    if num_descs == 1 && unsafe { (*descs).dimension } == 1 {
        let raw = unsafe { &*descs };
        let info = xbox_buffer_alloc_info(raw);
        unsafe { out_info.write(info) };
        static XBOX_BUF_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = XBOX_BUF_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 16 {
            boot_trace(
                "dx12xs_pc",
                "GetResourceAllocationInfo(xbox-buf)",
                &format!("#{n} w={} size={:#x} align={:#x}", raw.width, info[0], info[1]),
            );
        }
        return out_info;
    }
    if num_descs > 1 && (0..count).all(|i| unsafe { (*descs.add(i)).dimension } == 1) {
        let mut total_size = 0u64;
        let mut max_align = 256u64;
        for i in 0..count {
            let one = xbox_buffer_alloc_info(unsafe { &*descs.add(i) });
            let off = total_size.next_multiple_of(one[1]);
            total_size = off.saturating_add(one[0]);
            max_align = max_align.max(one[1]);
        }
        unsafe { out_info.write([total_size, max_align]) };
        return out_info;
    }
    let real = unsafe { &*this }.real_device;
    let mut sanitized = Vec::with_capacity(count);
    for i in 0..count {
        sanitized.push(sanitize_resource_desc(unsafe { &*descs.add(i) }));
    }
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *mut [u64; 2], u32, u32, *const ResourceDescRaw) -> *mut [u64; 2];
    unsafe { com_slot::<FnTy>(real, 25)(real, out_info, visible_mask, num_descs, sanitized.as_ptr()) };
    let res = unsafe { *out_info };
    if num_descs == 1 {
        let raw = unsafe { &*descs };
        let xb = xbox_texture_alloc_info(raw);
        let clamped = clamp_texture_alloc_info(res, xb);
        if clamped[0] < res[0] || res[0] == u64::MAX || res[1] == 0 {
            static CLAMP_LOGS: AtomicU32 = AtomicU32::new(0);
            let n = CLAMP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 16 {
                boot_trace(
                    "dx12xs_pc",
                    "GetResourceAllocationInfo(tex-xbox-clamp)",
                    &format!(
                        "#{n} w={} h={} fmt={} samples={} pc_size={:#x} xb_size={:#x} pc_align={:#x}",
                        raw.width, raw.height, raw.format, raw.sample_count, res[0], clamped[0], res[1]
                    ),
                );
            }
        }
        unsafe { out_info.write(clamped) };
    } else {
        let xb_sum: u64 = (0..count)
            .map(|i| {
                let d = unsafe { &*descs.add(i) };
                if d.dimension == 1 {
                    xbox_buffer_alloc_info(d)[0]
                } else {
                    xbox_texture_alloc_info(d)[0]
                }
            })
            .fold(0u64, u64::saturating_add);
        if res[0] == u64::MAX || res[1] == 0 || res[0] > xb_sum || res[1] > 65536 {
            let mut total_size = 0u64;
            let mut max_align = 256u64;
            for i in 0..count {
                let one = query_single_resource_alloc(real, unsafe { &*descs.add(i) });
                let off = total_size.next_multiple_of(one[1]);
                total_size = off.saturating_add(one[0]);
                max_align = max_align.max(one[1]);
            }
            unsafe { out_info.write([total_size, max_align]) };
        }
    }
    let final_res = unsafe { *out_info };
    if final_res[0] >= 4 * 1024 * 1024 {
        static LARGE_TEX_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = LARGE_TEX_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 16 {
            let d0 = unsafe { &*descs };
            boot_trace(
                "dx12xs_pc",
                "GetResourceAllocationInfo(tex-large)",
                &format!(
                    "#{n} count={num_descs} dim={} w={} h={} d={} mips={} fmt={} size={:#x} align={:#x}",
                    d0.dimension, d0.width, d0.height, d0.depth_or_array, d0.mip_levels, d0.format, final_res[0], final_res[1]
                ),
            );
        }
    }
    out_info
}

/// C-style `sret`-first ABI (`RCX = out_props`, `RDX = this`) — fixes Boot Probe #1 crash!
extern "system" fn dev_get_custom_heap_props(
    out_props: *mut [u32; 5],
    this: *mut DeviceX,
    node_mask: u32,
    heap_ty: u32,
) -> *mut [u32; 5] {
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut [u32; 5], u32, u32) -> *mut [u32; 5];
    unsafe { com_slot::<FnTy>(real, 26)(real, out_props, node_mask, heap_ty) };
    out_props
}

/// C-style `sret`-first ABI (`RCX = out_info`, `RDX = this`), 72-byte `ResourceDesc1Raw` stride
/// and 24-byte `AllocationInfo1Raw` per-resource placement output.
extern "system" fn dev_get_alloc_info2(
    out_info: *mut [u64; 2],
    this: *mut DeviceX,
    _visible_mask: u32,
    num_descs: u32,
    descs1: *const ResourceDesc1Raw,
    each1: *mut AllocationInfo1Raw,
) -> *mut [u64; 2] {
    if out_info.is_null() {
        return out_info;
    }
    if num_descs == 0 || descs1.is_null() {
        unsafe { out_info.write([0, 65536]) };
        return out_info;
    }
    let real = unsafe { &*this }.real_device;
    let count = num_descs as usize;
    let mut total_size = 0u64;
    let mut max_align = 65536u64;
    for i in 0..count {
        let raw1 = unsafe { descs1.add(i).read_unaligned() };
        let one = query_single_resource_alloc(real, &raw1.desc);
        let align = one[1].max(1);
        let offset = total_size.next_multiple_of(align);
        if !each1.is_null() {
            unsafe {
                each1.add(i).write_unaligned(AllocationInfo1Raw {
                    offset,
                    alignment: align,
                    size: one[0],
                });
            }
        }
        total_size = offset.saturating_add(one[0]);
        max_align = max_align.max(align);
    }
    unsafe { out_info.write([total_size, max_align]) };
    out_info
}

fn format_bpp(fmt: u32) -> u64 {
    match fmt {
        1..=4 => 16,
        9..=14 => 8,
        48..=52 | 55..=60 | 85 | 86 => 2,
        61..=65 | 109..=112 => 1,
        _ => 4,
    }
}

/// Computes the Xbox Scarlett RDNA2 `ALLOW_DISPLAY` surface footprint (64 KiB-aligned linear
/// pixels plus 256 KiB display tile/DCC metadata padding) so both Series X (`0x04000000`,
/// 2x 4K) and Series S (`0x05200000`, 2x 4K + 2x 1080p) pools stay within RAGE's
/// `<= 0x1FFFFF` slack assertion at `0x247af25`.
fn compute_xbox_display_bytes(raw: &ResourceDescRaw) -> usize {
    const RDNA2_DISPLAY_METADATA_BYTES: u64 = 0x4_0000; // 256 KiB DCC/tile metadata
    let bpp = format_bpp(raw.format);
    let linear = raw
        .width
        .max(1)
        .saturating_mul(u64::from(raw.height.max(1)))
        .saturating_mul(bpp);
    let rounded = (linear.saturating_add(0xFFFF)) & !0xFFFF;
    rounded
        .saturating_add(RDNA2_DISPLAY_METADATA_BYTES)
        .max(0x1_0000) as usize
}

type XMemAllocFn = unsafe extern "system" fn(usize, u64) -> *mut c_void;
type XMemFreeFn = unsafe extern "system" fn(*mut c_void, u64);

fn resolve_xmem_fns() -> Option<(XMemAllocFn, XMemFreeFn)> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    let name: Vec<u16> = "xmem_pc.dll\0".encode_utf16().collect();
    let h = unsafe { GetModuleHandleW(name.as_ptr()) };
    if h.is_null() {
        return None;
    }
    let alloc_p = unsafe { GetProcAddress(h, c"XMemAlloc".as_ptr().cast()) }?;
    let free_p = unsafe { GetProcAddress(h, c"XMemFree".as_ptr().cast()) }?;
    Some(unsafe {
        (
            std::mem::transmute::<unsafe extern "system" fn() -> isize, XMemAllocFn>(alloc_p),
            std::mem::transmute::<unsafe extern "system" fn() -> isize, XMemFreeFn>(free_p),
        )
    })
}

fn wrap_resource(
    parent_dev: *mut DeviceX,
    real_res: *mut c_void,
    desc: ResourceDescRaw,
    gpu_va: u64,
    heap_ty: u32,
    initial_state: u32,
) -> *mut c_void {
    wrap_resource_with_xmem(parent_dev, real_res, desc, None, gpu_va, heap_ty, initial_state)
}

fn wrap_resource_with_xmem(
    parent_dev: *mut DeviceX,
    real_res: *mut c_void,
    desc: ResourceDescRaw,
    xmem_alloc: Option<(usize, u64)>,
    gpu_va: u64,
    heap_ty: u32,
    initial_state: u32,
) -> *mut c_void {
    set_tracked_resource_state(real_res, initial_state);
    dev_add_ref(parent_dev);
    let r = Box::new(ResourceX {
        vtable: RESOURCE_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        desc,
        xmem_alloc,
        gpu_va,
        heap_ty,
        cpu_map_buf: Mutex::new(None),
        parent_dev,
        real_resource: real_res,
    });
    Box::into_raw(r).cast()
}

extern "system" fn dev_create_committed_resource(
    this: *mut DeviceX,
    heap_props: *const [u32; 5],
    heap_flags: u32,
    desc: *const ResourceDescRaw,
    initial_state: u32,
    clear_val: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(raw) = (unsafe { desc.as_ref() }) else {
        return E_INVALIDARG;
    };
    let is_display = (heap_flags & 0x8) != 0;
    let clean_desc = sanitize_resource_desc(raw);
    let mut clear_scratch = [0u32; 5];
    let clean_clear = sanitize_clear_value(&clean_desc, clear_val, &mut clear_scratch);
    let clean_heap_flags = heap_flags & 0x1801;
    let d = unsafe { &*this };
    let real = d.real_device;
    let mut real_res: *mut c_void = std::ptr::null_mut();
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        *const [u32; 5],
        u32,
        *const ResourceDescRaw,
        u32,
        *const c_void,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let mut hr = unsafe {
        com_slot::<FnTy>(real, 27)(
            real,
            heap_props,
            clean_heap_flags,
            &clean_desc,
            initial_state,
            clean_clear,
            &RESOURCE_IIDS[0],
            &mut real_res,
        )
    };
    if hr == (0x8007_000E_u32 as i32) && !heap_props.is_null() && unsafe { (*heap_props)[0] } == 1 {
        let custom_l0 = [4u32, 1, 1, 0, 0];
        let hr2 = unsafe {
            com_slot::<FnTy>(real, 27)(
                real,
                &custom_l0,
                clean_heap_flags,
                &clean_desc,
                initial_state,
                clean_clear,
                &RESOURCE_IIDS[0],
                &mut real_res,
            )
        };
        if hr2 >= 0 {
            hr = hr2;
        }
    }
    if hr < 0 {
        log_if_device_removed(real, "DeviceX::CreateCommittedResource", hr);
        drain_info_queue(d.info_queue, "CreateCommittedResource");
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateCommittedResource",
            hr,
            &format!(
                "dim={} w={} h={} fmt={}->{} flags={:#x}->{:#x} hflags={:#x}->{:#x} state={:#x}",
                raw.dimension,
                raw.width,
                raw.height,
                raw.format,
                clean_desc.format,
                raw.flags,
                clean_desc.flags,
                heap_flags,
                clean_heap_flags,
                initial_state
            ),
        );
        unsafe { *out = std::ptr::null_mut() };
        return hr;
    }
    static COMMITTED_COUNT: AtomicU32 = AtomicU32::new(0);
    let c_idx = COMMITTED_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let is_interest = (raw.dimension == 3 && raw.width >= 3840)
        || raw.format == 19
        || (raw.flags & 0x2) != 0;
    if c_idx <= 24 || raw.width >= 1024 * 1024 || is_interest {
        let hp_ty = unsafe { heap_props.as_ref().map_or(0, |p| p[0]) };
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateCommittedResource",
            S_OK,
            &format!(
                "#{c_idx} real_res={real_res:?} hp_ty={hp_ty} dim={} w={} h={} fmt={}->{} flags={:#x}->{:#x} hflags={:#x} state={:#x}",
                raw.dimension, raw.width, raw.height, raw.format, clean_desc.format, raw.flags, clean_desc.flags, heap_flags, initial_state
            ),
        );
    }
    if !is_guid_in(iid, &RESOURCE_IIDS) {
        unsafe { real_release(real_res) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    let mut xmem_alloc = None;
    if is_display {
        if let Some((xm_alloc, _)) = resolve_xmem_fns() {
            let bytes = compute_xbox_display_bytes(raw);
            let attrs: u64 = (128u64 << 16) | (2u64 << 14) | (16u64 << 24) | (1u64 << 29);
            let ptr = unsafe { xm_alloc(bytes, attrs) };
            boot_trace(
                "dx12xs_pc",
                "ALLOW_DISPLAY::XMemAlloc",
                &format!("{}x{} fmt={} bytes={:#x} ptr={ptr:?}", raw.width, raw.height, raw.format, bytes),
            );
            if !ptr.is_null() {
                xmem_alloc = Some((ptr as usize, attrs));
            }
        }
    }
    let gpu_va = register_gpu_buffer_va(real_res, &clean_desc);
    let heap_ty = unsafe { heap_props.as_ref().map_or(1, |p| p[0]) };
    unsafe {
        *out = wrap_resource_with_xmem(
            this,
            real_res,
            *raw,
            xmem_alloc,
            gpu_va,
            heap_ty,
            initial_state,
        )
    };
    S_OK
}

extern "system" fn dev_create_committed_resource_x(
    this: *mut DeviceX,
    heap_props: *const [u32; 5],
    heap_flags: u32,
    desc: *const ResourceDescRaw,
    initial_state: u32,
    clear_val: *const c_void,
    _dcc_options: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    dev_create_committed_resource(
        this,
        heap_props,
        heap_flags,
        desc,
        initial_state,
        clear_val,
        iid,
        out,
    )
}

extern "system" fn dev_create_committed_resource3(
    this: *mut DeviceX,
    heap_props: *const [u32; 5],
    heap_flags: u32,
    desc: *const ResourceDescRaw,
    _initial_layout: u32,
    clear_val: *const c_void,
    _protected: *mut c_void,
    _castable_cnt: u32,
    _castable_fmts: *const u32,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    // initial_layout is D3D12_BARRIER_LAYOUT (e.g. 3=UNORDERED_ACCESS); PC CreateCommittedResource
    // takes D3D12_RESOURCE_STATES where 0 (COMMON) is valid for all buffers and textures.
    dev_create_committed_resource(
        this,
        heap_props,
        heap_flags,
        desc,
        0,
        clear_val,
        iid,
        out,
    )
}

extern "system" fn dev_create_resource_at_address_x(
    this: *mut DeviceX,
    _va: u64,
    desc: *const ResourceDescRaw,
    _initial_state: u32,
    clear_val: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    let default_props = [1u32, 0, 0, 0, 0]; // DEFAULT heap
    dev_create_committed_resource(
        this,
        &default_props,
        0,
        desc,
        0,
        clear_val,
        iid,
        out,
    )
}

extern "system" fn dev_create_heap(
    this: *mut DeviceX,
    desc: *const [u64; 5],
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() || desc.is_null() {
        return E_INVALIDARG;
    }
    let real = unsafe { &*this }.real_device;
    let mut real_heap: *mut c_void = std::ptr::null_mut();
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *const [u64; 5], *const Guid, *mut *mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(real, 28)(real, desc, &HEAP_IIDS[0], &mut real_heap) };
    let d_raw = unsafe { *desc };
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateHeap",
        hr,
        &format!("size={:#x} props=[{:#x},{:#x},{:#x}] flags={:#x}", d_raw[0], d_raw[1], d_raw[2], d_raw[3], d_raw[4]),
    );
    if hr < 0 {
        log_if_device_removed(real, "DeviceX::CreateHeap", hr);
        unsafe { *out = std::ptr::null_mut() };
        return hr;
    }
    if !is_guid_in(iid, &HEAP_IIDS) {
        let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateHeap",
            E_NOINTERFACE,
            &format!("E_NOINTERFACE iid={iid_str}"),
        );
        unsafe { real_release(real_heap) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    dev_add_ref(this);
    let h = Box::new(HeapX {
        vtable: HEAP_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        desc: unsafe { *desc },
        parent_dev: this,
        real_heap,
    });
    unsafe { *out = Box::into_raw(h).cast() };
    S_OK
}

extern "system" fn dev_create_placed_resource(
    this: *mut DeviceX,
    heap: *mut HeapX,
    offset: u64,
    desc: *const ResourceDescRaw,
    initial_state: u32,
    clear_val: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() || heap.is_null() {
        return E_INVALIDARG;
    }
    let Some(raw) = (unsafe { desc.as_ref() }) else {
        return E_INVALIDARG;
    };
    let clean_desc = sanitize_resource_desc(raw);
    let mut clear_scratch = [0u32; 5];
    let clean_clear = sanitize_clear_value(&clean_desc, clear_val, &mut clear_scratch);
    let real = unsafe { &*this }.real_device;
    let real_heap = unsafe { &*heap }.real_heap;
    let mut real_res: *mut c_void = std::ptr::null_mut();
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        u64,
        *const ResourceDescRaw,
        u32,
        *const c_void,
        *const Guid,
        *mut *mut c_void,
    ) -> HRESULT;
    let mut heap_ty = (unsafe { &*heap }.desc[1] & 0xFFFF_FFFF) as u32;
    let hr = unsafe {
        com_slot::<FnTy>(real, 29)(
            real,
            real_heap,
            offset,
            &clean_desc,
            initial_state,
            clean_clear,
            &RESOURCE_IIDS[0],
            &mut real_res,
        )
    };
    if hr < 0 {
        type CommitFnTy = unsafe extern "system" fn(
            *mut c_void,
            *const [u32; 5],
            u32,
            *const ResourceDescRaw,
            u32,
            *const c_void,
            *const Guid,
            *mut *mut c_void,
        ) -> HRESULT;
        let heap_props = [1u32, 0, 0, 1, 1];
        let commit_hr = unsafe {
            com_slot::<CommitFnTy>(real, 27)(
                real,
                &heap_props,
                0,
                &clean_desc,
                initial_state,
                clean_clear,
                &RESOURCE_IIDS[0],
                &mut real_res,
            )
        };
        if commit_hr >= 0 {
            static PLACED_FB_LOGS: AtomicU32 = AtomicU32::new(0);
            let n = PLACED_FB_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 16 {
                boot_trace_hr(
                    "dx12xs_pc",
                    "CreatePlacedResource(committed-fallback)",
                    hr,
                    &format!(
                        "#{n} dim={} w={} h={} fmt={}->{} flags={:#x}->{:#x} off={offset:#x} state={initial_state:#x}",
                        raw.dimension, raw.width, raw.height, raw.format, clean_desc.format, raw.flags, clean_desc.flags
                    ),
                );
            }
            heap_ty = 1;
        } else {
            log_if_device_removed(real, "DeviceX::CreatePlacedResource", hr);
            boot_trace_hr(
                "dx12xs_pc",
                "DeviceX::CreatePlacedResource",
                hr,
                &format!(
                    "dim={} w={} h={} fmt={}->{} flags={:#x}->{:#x} off={:#x} state={:#x} commit_hr={:#010x}",
                    raw.dimension,
                    raw.width,
                    raw.height,
                    raw.format,
                    clean_desc.format,
                    raw.flags,
                    clean_desc.flags,
                    offset,
                    initial_state,
                    commit_hr as u32
                ),
            );
            unsafe { *out = std::ptr::null_mut() };
            return hr;
        }
    }
    if !is_guid_in(iid, &RESOURCE_IIDS) {
        let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreatePlacedResource",
            E_NOINTERFACE,
            &format!("E_NOINTERFACE iid={iid_str}"),
        );
        unsafe { real_release(real_res) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    let gpu_va = register_gpu_buffer_va(real_res, &clean_desc);
    let is_interest = (raw.dimension == 3 && raw.width >= 3840)
        || raw.format == 19
        || (raw.flags & 0x2) != 0;
    if is_interest {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreatePlacedResource(interest)",
            S_OK,
            &format!(
                "real_res={real_res:?} heap={real_heap:?} hp_ty={heap_ty} off={offset:#x} dim={} w={} h={} fmt={}->{} flags={:#x}->{:#x} state={:#x}",
                raw.dimension, raw.width, raw.height, raw.format, clean_desc.format, raw.flags, clean_desc.flags, initial_state
            ),
        );
    }
    unsafe { *out = wrap_resource(this, real_res, *raw, gpu_va, heap_ty, initial_state) };
    S_OK
}

extern "system" fn dev_create_fence(
    this: *mut DeviceX,
    initial_value: u64,
    flags: u32,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let d = unsafe { &*this };
    let mut real_fence: *mut c_void = std::ptr::null_mut();
    type FnTy =
        unsafe extern "system" fn(*mut c_void, u64, u32, *const Guid, *mut *mut c_void) -> HRESULT;
    let hr = unsafe {
        com_slot::<FnTy>(d.real_device, 36)(
            d.real_device,
            initial_value,
            flags & 3,
            &FENCE_IIDS[0],
            &mut real_fence,
        )
    };
    let iid_str = unsafe { iid.as_ref() }.map_or_else(String::new, |g| g.format_guid());
    if hr < 0 {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateFence",
            hr,
            &format!("init={initial_value} flags={flags:#x} iid={iid_str}"),
        );
        unsafe { *out = std::ptr::null_mut() };
        return hr;
    }
    if !is_guid_in(iid, &FENCE_IIDS) {
        boot_trace_hr(
            "dx12xs_pc",
            "DeviceX::CreateFence",
            E_NOINTERFACE,
            &format!("init={initial_value} E_NOINTERFACE iid={iid_str}"),
        );
        unsafe { real_release(real_fence) };
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }
    dev_add_ref(this);
    let f = Box::new(FenceX {
        vtable: FENCE_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        value: AtomicU64::new(initial_value),
        last_signaled: AtomicU64::new(initial_value),
        flags,
        has_gpu_va_reader: AtomicBool::new(false),
        waiter_active: AtomicBool::new(false),
        parent_dev: this,
        real_fence,
    });
    let wrapped = Box::into_raw(f).cast();
    unsafe { *out = wrapped };
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateFence",
        S_OK,
        &format!("init={initial_value} flags={flags:#x} out={wrapped:?}"),
    );
    S_OK
}

extern "system" fn dev_get_removed_reason(this: *mut DeviceX) -> HRESULT {
    let real = unsafe { &*this }.real_device;
    let hr = query_real_removed_reason(real);
    if hr != S_OK {
        boot_trace_hr("dx12xs_pc", "DeviceX::GetDeviceRemovedReason", hr, "");
    }
    hr
}

extern "system" fn dev_get_copyable_footprints(
    this: *mut DeviceX,
    desc: *const ResourceDescRaw,
    first_sub: u32,
    num_sub: u32,
    base_offset: u64,
    layouts: *mut c_void,
    num_rows: *mut u32,
    row_sizes: *mut u64,
    total_bytes: *mut u64,
) {
    let Some(raw) = (unsafe { desc.as_ref() }) else {
        return;
    };
    let clean = sanitize_resource_desc(raw);
    let real = unsafe { &*this }.real_device;
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        *const ResourceDescRaw,
        u32,
        u32,
        u64,
        *mut c_void,
        *mut u32,
        *mut u64,
        *mut u64,
    );
    unsafe {
        com_slot::<FnTy>(real, 38)(
            real,
            &clean,
            first_sub,
            num_sub,
            base_offset,
            layouts,
            num_rows,
            row_sizes,
            total_bytes,
        )
    }
}

extern "system" fn dev_create_query_heap(
    this: *mut DeviceX,
    desc: *const c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    let d = unsafe { &*this };
    let real = d.real_device;
    type FnTy =
        unsafe extern "system" fn(*mut c_void, *const c_void, *const Guid, *mut *mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(real, 39)(real, desc, iid, out) };
    let (ty, cnt) = unsafe { desc.cast::<[u32; 2]>().as_ref().map_or((0, 0), |v| (v[0], v[1])) };
    boot_trace_hr(
        "dx12xs_pc",
        "DeviceX::CreateQueryHeap",
        hr,
        &format!("type={ty} count={cnt}"),
    );
    if hr < 0 {
        log_if_device_removed(real, "DeviceX::CreateQueryHeap", hr);
        drain_info_queue(d.info_queue, "CreateQueryHeap");
    }
    hr
}

#[repr(C)]
struct SignatureDescRaw {
    byte_stride: u32,
    num_argument_descs: u32,
    p_argument_descs: *const [u32; 4],
    node_mask: u32,
}

#[repr(C)]
pub struct CommandSignatureX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    #[allow(dead_code)]
    stride: u32,
    #[allow(dead_code)]
    arguments: Vec<[u32; 4]>,
    parent_dev: *mut DeviceX,
    real_signature: *mut c_void,
}

extern "system" fn sig_qi(
    this: *mut CommandSignatureX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &SIGNATURE_IIDS) {
        sig_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn sig_add_ref(this: *mut CommandSignatureX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn sig_release(this: *mut CommandSignatureX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        if !b.real_signature.is_null() {
            unsafe { real_release(b.real_signature) };
        }
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn sig_get_device(
    this: *mut CommandSignatureX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn sig_noop_hr(_this: *mut CommandSignatureX) -> HRESULT {
    S_OK
}

static SIGNATURE_VTABLE: Table<12> = {
    let mut t = fill_missing::<KIND_SIGNATURE, 12>();
    t[0] = sig_qi as *const c_void;
    t[1] = sig_add_ref as *const c_void;
    t[2] = sig_release as *const c_void;
    t[3] = sig_noop_hr as *const c_void;
    t[4] = sig_noop_hr as *const c_void;
    t[5] = sig_noop_hr as *const c_void;
    t[6] = sig_noop_hr as *const c_void;
    t[7] = sig_get_device as *const c_void;
    Table(t)
};

extern "system" fn dev_create_command_signature(
    this: *mut DeviceX,
    desc: *const c_void,
    root_sig: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(sig_desc) = (unsafe { desc.cast::<SignatureDescRaw>().as_ref() }) else {
        unsafe { *out = std::ptr::null_mut() };
        return E_INVALIDARG;
    };
    if sig_desc.p_argument_descs.is_null() && sig_desc.num_argument_descs > 0 {
        unsafe { *out = std::ptr::null_mut() };
        return E_INVALIDARG;
    }
    if !is_guid_in(iid, &SIGNATURE_IIDS) {
        unsafe { *out = std::ptr::null_mut() };
        return E_NOINTERFACE;
    }

    let count = if sig_desc.p_argument_descs.is_null() {
        0
    } else {
        (sig_desc.num_argument_descs as usize).min(256)
    };
    let mut arguments = Vec::with_capacity(count);
    for i in 0..count {
        arguments.push(unsafe { sig_desc.p_argument_descs.add(i).read_unaligned() });
    }
    let has_xbox_arg = arguments.iter().any(|a| a[0] >= 10);

    let mut real_sig: *mut c_void = std::ptr::null_mut();
    if !has_xbox_arg {
        let real = unsafe { &*this }.real_device;
        type FnTy = unsafe extern "system" fn(
            *mut c_void,
            *const c_void,
            *mut c_void,
            *const Guid,
            *mut *mut c_void,
        ) -> HRESULT;
        let hr = unsafe {
            com_slot::<FnTy>(real, 41)(real, desc, root_sig, &SIGNATURE_IIDS[0], &mut real_sig)
        };
        if hr < 0 {
            real_sig = std::ptr::null_mut();
        }
    }

    if real_sig.is_null() {
        let arg_types: Vec<u32> = arguments.iter().map(|a| a[0]).collect();
        boot_trace(
            "dx12xs_pc",
            "DeviceX::CreateCommandSignature(xbox-wrap)",
            &format!("stride={} args={arg_types:?}", sig_desc.byte_stride),
        );
    }

    dev_add_ref(this);
    let wrapped = Box::new(CommandSignatureX {
        vtable: SIGNATURE_VTABLE.0.as_ptr(),
        bits: 0,
        refs: AtomicU32::new(1),
        stride: sig_desc.byte_stride,
        arguments,
        parent_dev: this,
        real_signature: real_sig,
    });
    unsafe { *out = Box::into_raw(wrapped).cast() };
    S_OK
}

extern "system" fn dev_noop_ok(_this: *mut DeviceX) -> HRESULT {
    S_OK
}

extern "system" fn dev_ext_notimpl(
    _this: *mut DeviceX,
    _desc: *const c_void,
    _iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    E_NOTIMPL
}

extern "system" fn dev_create_sampler_x(
    this: *mut DeviceX,
    desc: *const c_void,
    cpu: u64,
) {
    dev_create_sampler(this, desc, cpu);
}

extern "system" fn dev_create_placed_view_x(
    _this: *mut DeviceX,
    _res: *mut c_void,
    _desc: *const c_void,
    _cpu: u64,
) -> HRESULT {
    S_OK
}

extern "system" fn dev_set_frame_interval_x(
    this: *mut DeviceX,
    _output: *mut c_void,
    length_us: u32,
    _period: u32,
    _flags: u32,
) -> HRESULT {
    let us = if length_us == 0 { 16_667 } else { length_us };
    unsafe { &*this }.frame_interval_us.store(us, Ordering::Relaxed);
    boot_trace("dx12xs_pc", "DeviceX::SetFrameIntervalX", &format!("us={us}"));
    S_OK
}

extern "system" fn dev_schedule_frame_event_x(
    _this: *mut DeviceX,
    _kind: u32,
    _offset: u32,
    _list: *const c_void,
    _flags: u32,
) -> HRESULT {
    S_OK
}

extern "system" fn dev_wait_frame_event_x(
    this: *mut DeviceX,
    kind: u32,
    timeout_ms: u32,
    _list: *mut c_void,
    _flags: u32,
    token_out: *mut u64,
) -> HRESULT {
    let d = unsafe { &*this };
    let _ = FRAME_START.elapsed();
    if timeout_ms > 0 && timeout_ms != u32::MAX {
        std::thread::sleep(Duration::from_millis(u64::from(timeout_ms.min(16))));
    }
    if kind == 0 && !token_out.is_null() {
        let tok = d.frame_token.fetch_add(1, Ordering::Relaxed);
        unsafe { token_out.write_unaligned(tok) };
    }
    S_OK
}

extern "system" fn dev_get_frame_statistics_x(
    _this: *mut DeviceX,
    _token: u64,
    _kinds: u32,
    count_out: *mut u32,
    _stats_out: *mut u8,
) -> HRESULT {
    if !count_out.is_null() {
        unsafe { count_out.write_unaligned(0) };
    }
    S_OK
}

const DEVICE_VTABLE: Table<160> = {
    let mut t = fill_missing::<KIND_DEVICE, 160>();
    t[0] = dev_query_interface as *const c_void;
    t[1] = dev_add_ref as *const c_void;
    t[2] = dev_release as *const c_void;
    t[3] = dev_get_private_data as *const c_void;
    t[4] = dev_set_private_data as *const c_void;
    t[5] = dev_set_private_data_iface as *const c_void;
    t[6] = dev_set_name as *const c_void;
    t[7] = dev_get_node_count as *const c_void;
    t[8] = dev_create_command_queue as *const c_void;
    t[9] = dev_create_command_allocator as *const c_void;
    t[10] = dev_create_graphics_pso as *const c_void;
    t[11] = dev_create_compute_pso as *const c_void;
    t[12] = dev_create_command_list as *const c_void;
    t[13] = dev_check_feature_support as *const c_void;
    t[14] = dev_create_descriptor_heap as *const c_void;
    t[15] = dev_get_desc_inc_size as *const c_void;
    t[16] = dev_create_root_signature as *const c_void;
    t[17] = dev_create_cbv as *const c_void;
    t[18] = dev_create_srv as *const c_void;
    t[19] = dev_create_uav as *const c_void;
    t[20] = dev_create_rtv as *const c_void;
    t[21] = dev_create_dsv as *const c_void;
    t[22] = dev_create_sampler as *const c_void;
    t[23] = dev_copy_descriptors as *const c_void;
    t[24] = dev_copy_descriptors_simple as *const c_void;
    t[25] = dev_get_alloc_info as *const c_void;
    t[26] = dev_get_custom_heap_props as *const c_void;
    t[27] = dev_create_committed_resource as *const c_void;
    t[28] = dev_create_heap as *const c_void;
    t[29] = dev_create_placed_resource as *const c_void;
    t[36] = dev_create_fence as *const c_void;
    t[37] = dev_get_removed_reason as *const c_void;
    t[38] = dev_get_copyable_footprints as *const c_void;
    t[39] = dev_create_query_heap as *const c_void;
    t[41] = dev_create_command_signature as *const c_void;
    // Console block (44..=82)
    t[48] = dev_create_command_queue_x as *const c_void;         // 0x180
    t[49] = dev_noop_ok as *const c_void;                        // 0x188
    t[50] = dev_noop_ok as *const c_void;                        // 0x190
    t[55] = dev_ext_notimpl as *const c_void;                    // 0x1b8
    t[57] = dev_ext_notimpl as *const c_void;                    // 0x1c8
    t[61] = dev_create_sampler_x as *const c_void;               // 0x1e8
    t[62] = dev_create_compute_pso_x as *const c_void;           // 0x1f0
    t[67] = dev_ext_notimpl as *const c_void;                    // 0x218
    t[69] = dev_noop_ok as *const c_void;                        // 0x228 SetDebugErrorFilter
    t[70] = dev_create_placed_view_x as *const c_void;           // 0x230
    t[71] = dev_create_placed_view_x as *const c_void;           // 0x238
    t[73] = dev_create_command_list_x as *const c_void;          // 0x248
    t[74] = dev_noop_ok as *const c_void;                        // 0x250 RegisterPagePoolX
    t[75] = dev_noop_ok as *const c_void;                        // 0x258 UnregisterPagePoolX
    t[76] = dev_create_committed_resource_x as *const c_void;    // 0x260
    t[78] = dev_set_frame_interval_x as *const c_void;           // 0x270
    t[79] = dev_schedule_frame_event_x as *const c_void;         // 0x278
    t[80] = dev_wait_frame_event_x as *const c_void;             // 0x280
    t[81] = dev_get_frame_statistics_x as *const c_void;         // 0x288
    // Shifted ID3D12Device1..11 (+39)
    t[86] = dev_create_pipeline_state_stream as *const c_void;   // 0x2b0
    t[101] = dev_ext_notimpl as *const c_void;                   // 0x328 CreateStateObject
    t[108] = dev_get_alloc_info2 as *const c_void;               // 0x360
    t[119] = dev_noop_ok as *const c_void;                       // 0x3b8
    t[127] = dev_create_committed_resource3 as *const c_void;    // 0x3f8
    t[132] = dev_noop_ok as *const c_void;                       // 0x420
    t[133] = dev_create_resource_at_address_x as *const c_void;  // 0x428
    Table(t)
};

// ============================================================================
// DescriptorHeapX / PipelineX / ResourceX / HeapX
// ============================================================================

#[repr(C)]
pub struct DescriptorHeapX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    desc: DescriptorHeapDesc,
    cpu_start: u64,
    gpu_start: u64,
    owned_mem: Option<(*mut u8, Layout)>,
    parent_dev: *mut DeviceX,
    real_heap: *mut c_void,
}

extern "system" fn dheap_qi(
    this: *mut DescriptorHeapX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DESC_HEAP_IIDS) {
        dheap_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dheap_add_ref(this: *mut DescriptorHeapX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn dheap_release(this: *mut DescriptorHeapX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        if let Some((ptr, layout)) = b.owned_mem {
            unsafe { dealloc(ptr, layout) };
        }
        unsafe { real_release(b.real_heap) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn dheap_get_device(
    this: *mut DescriptorHeapX,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn dheap_get_desc(this: *mut DescriptorHeapX, out: *mut DescriptorHeapDesc) {
    if !out.is_null() {
        unsafe { out.write((&*this).desc) };
    }
}
/// Scalar `u64` return in `RAX` (`RCX = this` ONLY).
extern "system" fn dheap_cpu_start(this: *mut DescriptorHeapX) -> u64 {
    let h = unsafe { &*this };
    static LOGS: AtomicU32 = AtomicU32::new(0);
    let n = LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        boot_trace(
            "dx12xs_pc",
            "DescriptorHeapX::GetCPUDescriptorHandleForHeapStart",
            &format!(
                "#{n} this={this:?} ty={} num={} flags={:#x} cpu={:#x}",
                h.desc.ty, h.desc.num_descriptors, h.desc.flags, h.cpu_start
            ),
        );
    }
    h.cpu_start
}
/// Scalar `u64` return in `RAX` (`RCX = this` ONLY).
extern "system" fn dheap_gpu_start(this: *mut DescriptorHeapX) -> u64 {
    let h = unsafe { &*this };
    static LOGS: AtomicU32 = AtomicU32::new(0);
    let n = LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        boot_trace(
            "dx12xs_pc",
            "DescriptorHeapX::GetGPUDescriptorHandleForHeapStart",
            &format!(
                "#{n} this={this:?} ty={} num={} flags={:#x} gpu={:#x}",
                h.desc.ty, h.desc.num_descriptors, h.desc.flags, h.gpu_start
            ),
        );
    }
    h.gpu_start
}

static DESC_HEAP_VTABLE: Table<12> = Table([
    dheap_qi as *const c_void,
    dheap_add_ref as *const c_void,
    dheap_release as *const c_void,
    missing_slot::<KIND_DESC_HEAP, 3> as *const c_void,
    missing_slot::<KIND_DESC_HEAP, 4> as *const c_void,
    missing_slot::<KIND_DESC_HEAP, 5> as *const c_void,
    missing_slot::<KIND_DESC_HEAP, 6> as *const c_void,
    dheap_get_device as *const c_void,
    dheap_get_desc as *const c_void,
    dheap_cpu_start as *const c_void,
    dheap_gpu_start as *const c_void,
    missing_slot::<KIND_DESC_HEAP, 11> as *const c_void,
]);

/// `>= 0x40` bytes, 16-byte aligned, zeroed at `+0x10..+0x30` for inline SSE loads at `0x00032786`.
#[repr(C, align(16))]
pub struct PipelineX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    inline_zero: [u64; 4], // +0x10..+0x30
    parent_dev: *mut DeviceX,
    real_pso: *mut c_void,
    used_fallback_rs: bool,
    compute_rs_override: *mut c_void,
    diag_dsv_fmt: u32,
    diag_rtv0_fmt: u32,
    diag_depth_en: u32,
    diag_depth_func: u32,
    diag_vs_hash: u64,
    diag_ps_hash: u64,
}

const _: () = assert!(size_of::<PipelineX>() >= 0x40);
const _: () = assert!(align_of::<PipelineX>() == 16);

extern "system" fn pso_qi(this: *mut PipelineX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &PIPELINE_IIDS) {
        pso_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn pso_add_ref(this: *mut PipelineX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn pso_release(this: *mut PipelineX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        unsafe { real_release(b.real_pso) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn pso_get_device(this: *mut PipelineX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn pso_cached_blob(_this: *mut PipelineX, _out: *mut *mut c_void) -> HRESULT {
    E_NOTIMPL
}

static PIPELINE_VTABLE: Table<10> = Table([
    pso_qi as *const c_void,
    pso_add_ref as *const c_void,
    pso_release as *const c_void,
    missing_slot::<KIND_PIPELINE, 3> as *const c_void,
    missing_slot::<KIND_PIPELINE, 4> as *const c_void,
    missing_slot::<KIND_PIPELINE, 5> as *const c_void,
    missing_slot::<KIND_PIPELINE, 6> as *const c_void,
    pso_get_device as *const c_void,
    pso_cached_blob as *const c_void,
    missing_slot::<KIND_PIPELINE, 9> as *const c_void,
]);

#[repr(C)]
pub struct ResourceX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    desc: ResourceDescRaw,
    xmem_alloc: Option<(usize, u64)>,
    gpu_va: u64,
    heap_ty: u32,
    cpu_map_buf: Mutex<Option<usize>>,
    parent_dev: *mut DeviceX,
    real_resource: *mut c_void,
}

extern "system" fn res_qi(this: *mut ResourceX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &RESOURCE_IIDS) {
        res_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn res_add_ref(this: *mut ResourceX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn res_release(this: *mut ResourceX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        unregister_gpu_buffer_va(b.gpu_va);
        remove_tracked_resource_state(b.real_resource);
        if let Some((ptr, attrs)) = b.xmem_alloc {
            if let Some((_, xm_free)) = resolve_xmem_fns() {
                unsafe { xm_free(ptr as *mut c_void, attrs) };
            }
        }
        if let Some(addr) = *b.cpu_map_buf.lock().unwrap_or_else(|e| e.into_inner()) {
            if addr != 0 {
                unsafe {
                    windows_sys::Win32::System::Memory::VirtualFree(
                        addr as *mut c_void,
                        0,
                        windows_sys::Win32::System::Memory::MEM_RELEASE,
                    );
                }
            }
        }
        unsafe { real_release(b.real_resource) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn res_get_device(this: *mut ResourceX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
fn resource_shadow_bytes(desc: &ResourceDescRaw) -> usize {
    let min_bytes = if desc.dimension != 1 {
        let w_pad = desc.width.max(1).next_multiple_of(64);
        let h_pad = u64::from(desc.height.max(1)).next_multiple_of(64);
        let d = u64::from(desc.depth_or_array.max(1));
        let bpp = format_bpp(desc.format).max(8);
        w_pad
            .saturating_mul(h_pad)
            .saturating_mul(d)
            .saturating_mul(bpp)
            .saturating_mul(2)
    } else {
        0
    };
    estimate_resource_footprint(desc)[0]
        .max(min_bytes)
        .next_multiple_of(65536)
        .clamp(65536, 64 * 1024 * 1024) as usize
}

fn ensure_resource_cpu_shadow(r: &ResourceX) -> *mut c_void {
    let mut guard = r.cpu_map_buf.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(addr) = *guard {
        return addr as *mut c_void;
    }
    let bytes = resource_shadow_bytes(&r.desc);
    let ptr = unsafe {
        windows_sys::Win32::System::Memory::VirtualAlloc(
            std::ptr::null(),
            bytes,
            windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE,
            windows_sys::Win32::System::Memory::PAGE_READWRITE,
        )
    };
    if !ptr.is_null() {
        *guard = Some(ptr as usize);
    }
    ptr
}

extern "system" fn res_map(
    this: *mut ResourceX,
    sub: u32,
    range: *const c_void,
    data: *mut *mut c_void,
) -> HRESULT {
    if this.is_null() {
        return E_INVALIDARG;
    }
    let r = unsafe { &*this };
    // Xbox UMA allows CPU Map() on DEFAULT heaps (heap_ty == 1), whereas Win32 PC D3D12 forbids
    // Map on D3D12_HEAP_TYPE_DEFAULT (#822). Provide a stable CPU shadow backing buffer instead.
    if r.heap_ty != 2 && r.heap_ty != 3 {
        if !data.is_null() {
            let bytes = resource_shadow_bytes(&r.desc);
            let ptr = ensure_resource_cpu_shadow(r);
            unsafe { *data = ptr };
            static LOGS: AtomicU32 = AtomicU32::new(0);
            let n = LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 8 {
                boot_trace(
                    "dx12xs_pc",
                    "ResourceX::Map(default-shadow)",
                    &format!(
                        "#{n} heap_ty={} dim={} w={} bytes={bytes:#x} ptr={ptr:?}",
                        r.heap_ty, r.desc.dimension, r.desc.width
                    ),
                );
            }
        }
        return S_OK;
    }
    let real = r.real_resource;
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const c_void, *mut *mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(real, 8)(real, sub, range, data) };
    let mapped_null = !data.is_null() && unsafe { *data }.is_null();
    if hr < 0 || mapped_null {
        if !data.is_null() {
            let bytes = resource_shadow_bytes(&r.desc);
            let ptr = ensure_resource_cpu_shadow(r);
            unsafe { *data = ptr };
            static FALLBACK_LOGS: AtomicU32 = AtomicU32::new(0);
            let n = FALLBACK_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 16 {
                boot_trace(
                    "dx12xs_pc",
                    "ResourceX::Map(fallback-shadow)",
                    &format!(
                        "#{n} hr={:#010x} heap_ty={} dim={} w={} h={} fmt={} sub={sub} bytes={bytes:#x}",
                        hr as u32, r.heap_ty, r.desc.dimension, r.desc.width, r.desc.height, r.desc.format
                    ),
                );
            }
        }
        return S_OK;
    }
    hr
}
extern "system" fn res_unmap(this: *mut ResourceX, sub: u32, range: *const c_void) {
    if this.is_null() {
        return;
    }
    let r = unsafe { &*this };
    if (r.heap_ty != 2 && r.heap_ty != 3)
        || r.cpu_map_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    {
        return;
    }
    let real = r.real_resource;
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const c_void);
    unsafe { com_slot::<FnTy>(real, 9)(real, sub, range) };
}
extern "system" fn res_get_desc(this: *mut ResourceX, out: *mut ResourceDescRaw) {
    if !out.is_null() {
        unsafe { out.write((&*this).desc) };
    }
}
extern "system" fn res_gpu_va(this: *mut ResourceX) -> u64 {
    if this.is_null() {
        return 0;
    }
    let r = unsafe { &*this };
    if r.desc.dimension != 1 {
        if let Some((ptr, _)) = r.xmem_alloc {
            return ptr as u64;
        }
        if r.gpu_va != 0 {
            return r.gpu_va;
        }
        let bytes = resource_shadow_bytes(&r.desc);
        let ptr = ensure_resource_cpu_shadow(r);
        static TEX_VA_LOGS: AtomicU32 = AtomicU32::new(0);
        static TEX_256_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = TEX_VA_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        let is_256 = r.desc.width == 256 && r.desc.height == 256;
        let log_256 = is_256 && TEX_256_LOGS.fetch_add(1, Ordering::Relaxed) < 16;
        if n <= 32 || log_256 {
            boot_trace(
                "dx12xs_pc",
                "ResourceX::GetGPUVirtualAddress(tex-shadow)",
                &format!(
                    "#{n} dim={} w={} h={} mips={} fmt={} bytes={bytes:#x} ptr={ptr:?}",
                    r.desc.dimension, r.desc.width, r.desc.height, r.desc.mip_levels, r.desc.format
                ),
            );
        }
        return ptr as u64;
    }
    let real = r.real_resource;
    type FnTy = unsafe extern "system" fn(*mut c_void) -> u64;
    unsafe { com_slot::<FnTy>(real, 11)(real) }
}

static RESOURCE_VTABLE: Table<16> = {
    let mut t = fill_missing::<KIND_RESOURCE, 16>();
    t[0] = res_qi as *const c_void;
    t[1] = res_add_ref as *const c_void;
    t[2] = res_release as *const c_void;
    t[7] = res_get_device as *const c_void;
    t[8] = res_map as *const c_void;
    t[9] = res_unmap as *const c_void;
    t[10] = res_get_desc as *const c_void;
    t[11] = res_gpu_va as *const c_void;
    Table(t)
};

#[repr(C)]
pub struct HeapX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    desc: [u64; 5],
    parent_dev: *mut DeviceX,
    real_heap: *mut c_void,
}

extern "system" fn heap_qi(this: *mut HeapX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &HEAP_IIDS) {
        heap_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn heap_add_ref(this: *mut HeapX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn heap_release(this: *mut HeapX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        unsafe { real_release(b.real_heap) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn heap_get_device(this: *mut HeapX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn heap_get_desc(this: *mut HeapX, out: *mut [u64; 5]) {
    if !out.is_null() {
        unsafe { out.write((&*this).desc) };
    }
}

static HEAP_VTABLE: Table<10> = {
    let mut t = fill_missing::<KIND_HEAP, 10>();
    t[0] = heap_qi as *const c_void;
    t[1] = heap_add_ref as *const c_void;
    t[2] = heap_release as *const c_void;
    t[7] = heap_get_device as *const c_void;
    t[8] = heap_get_desc as *const c_void;
    Table(t)
};

// ============================================================================
// QueueX / AllocatorX / FenceX / ListX
// ============================================================================

#[repr(C)]
pub struct QueueX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    kind: u32,
    desc: PcQueueDesc,
    parent_dev: *mut DeviceX,
    real_queue: *mut c_void,
    timing_fence: *mut c_void,
    timing_seq: AtomicU64,
    pending_seq: AtomicU64,
    pending_submit_qpc: AtomicU64,
    present_tick: AtomicU64,
    present_ctx: Mutex<Option<crate::presenter::PresentContext>>,
}

const _: () = assert!(std::mem::offset_of!(QueueX, kind) == 0x10);

fn sample_queue_gpu_timing(q: &QueueX) {
    if q.timing_fence.is_null() {
        return;
    }
    let pending = q.pending_seq.load(Ordering::Acquire);
    if pending == 0 {
        return;
    }
    type GetCompletedFn = unsafe extern "system" fn(*mut c_void) -> u64;
    let completed = unsafe { com_slot::<GetCompletedFn>(q.timing_fence, 8)(q.timing_fence) };
    if completed >= pending {
        let submit_qpc = q.pending_submit_qpc.load(Ordering::Relaxed);
        let now = shim_common::telemetry::qpc_now();
        let freq = shim_common::telemetry::qpc_freq();
        if now > submit_qpc && submit_qpc > 0 {
            let gpu_us = ((now - submit_qpc) as u128 * 1_000_000 / freq as u128).min(5_000_000) as u32;
            shim_common::telemetry::record_gpu_duration_us(gpu_us);
        }
        let _ = q
            .pending_seq
            .compare_exchange(pending, 0, Ordering::AcqRel, Ordering::Relaxed);
    }
}

extern "system" fn queue_qi(this: *mut QueueX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &QUEUE_IIDS) {
        queue_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn queue_add_ref(this: *mut QueueX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn queue_release(this: *mut QueueX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        if !b.timing_fence.is_null() {
            unsafe { real_release(b.timing_fence) };
        }
        unsafe { real_release(b.real_queue) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn queue_get_device(this: *mut QueueX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn queue_execute(this: *mut QueueX, count: u32, lists: *const *mut ListX) {
    if count == 0 || lists.is_null() {
        return;
    }
    let q = unsafe { &*this };
    shim_common::telemetry::record_submit_start();
    sample_queue_gpu_timing(q);
    let mut unclosed = 0u32;
    let mut real_lists = Vec::with_capacity(count as usize);
    for i in 0..(count as usize) {
        let l = unsafe { lists.add(i).read_unaligned() };
        if l.is_null() {
            real_lists.push(std::ptr::null_mut());
        } else {
            let lr = unsafe { &*l };
            if !lr.closed.load(Ordering::Acquire) {
                unclosed += 1;
            }
            real_lists.push(lr.real_list);
        }
    }
    static EXEC_CALLS: AtomicU32 = AtomicU32::new(0);
    let call_n = EXEC_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    let parent = unsafe { &*q.parent_dev };
    let real_dev = parent.real_device;
    let pre = query_real_removed_reason(real_dev);
    if call_n <= 16 || unclosed > 0 {
        boot_trace(
            "dx12xs_pc",
            "QueueX::ExecuteCommandLists",
            &format!(
                "#{call_n} kind={} count={count} unclosed={unclosed} pre_reason={:#010x} real_lists={real_lists:?}",
                q.kind, pre as u32
            ),
        );
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const *mut c_void);
    if !q.timing_fence.is_null() && call_n <= 8 && count > 1 {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
        for (idx, &rl) in real_lists.iter().enumerate() {
            unsafe { com_slot::<FnTy>(q.real_queue, 10)(q.real_queue, 1, &rl) };
            let sync_seq = q.timing_seq.fetch_add(1, Ordering::Relaxed) + 1;
            type SigFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
            let sig_hr = unsafe { com_slot::<SigFn>(q.real_queue, 14)(q.real_queue, q.timing_fence, sync_seq) };
            if sig_hr >= 0 {
                let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
                if !ev.is_null() {
                    type SetEvFn = unsafe extern "system" fn(*mut c_void, u64, *mut c_void) -> HRESULT;
                    if unsafe { com_slot::<SetEvFn>(q.timing_fence, 9)(q.timing_fence, sync_seq, ev) } >= 0 {
                        unsafe { WaitForSingleObject(ev, 5000) };
                    }
                    unsafe { CloseHandle(ev) };
                }
            }
            drain_info_queue(parent.info_queue, "ExecuteCommandLists(split)");
            let split_reason = query_real_removed_reason(real_dev);
            boot_trace_hr(
                "dx12xs_pc",
                "QueueX::ExecuteCommandLists(split)",
                split_reason,
                &format!(
                    "#{call_n}[{idx}/{count}] list={rl:?} sync_seq={sync_seq} sig_hr={sig_hr:#010x} reason={:#010x}",
                    split_reason as u32
                ),
            );
            if split_reason != S_OK {
                dump_failed_batch_lists(call_n, q.kind, count, lists, unclosed, pre, split_reason);
            }
        }
    } else {
        unsafe { com_slot::<FnTy>(q.real_queue, 10)(q.real_queue, count, real_lists.as_ptr()) };
        drain_info_queue(parent.info_queue, "ExecuteCommandLists");
        let post = query_real_removed_reason(real_dev);
        if post != S_OK || call_n <= 12 {
            boot_trace_hr(
                "dx12xs_pc",
                "QueueX::ExecuteCommandLists(post)",
                post,
                &format!(
                    "caller=QueueX::ExecuteCommandLists#{call_n} kind={} count={count} unclosed={unclosed} pre_reason={:#010x} post_reason={:#010x}",
                    q.kind, pre as u32, post as u32
                ),
            );
        }
        if post != S_OK {
            dump_failed_batch_lists(call_n, q.kind, count, lists, unclosed, pre, post);
        }

        if !q.timing_fence.is_null() && call_n <= 12 {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
            let sync_seq = q.timing_seq.fetch_add(1, Ordering::Relaxed) + 1;
            type SigFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
            let sig_hr = unsafe { com_slot::<SigFn>(q.real_queue, 14)(q.real_queue, q.timing_fence, sync_seq) };
            if sig_hr >= 0 {
                let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
                if !ev.is_null() {
                    type SetEvFn = unsafe extern "system" fn(*mut c_void, u64, *mut c_void) -> HRESULT;
                    if unsafe { com_slot::<SetEvFn>(q.timing_fence, 9)(q.timing_fence, sync_seq, ev) } >= 0 {
                        unsafe { WaitForSingleObject(ev, 5000) };
                    }
                    unsafe { CloseHandle(ev) };
                }
            }
            drain_info_queue(parent.info_queue, "ExecuteCommandLists(post_sync)");
            let post_sync = query_real_removed_reason(real_dev);
            boot_trace_hr(
                "dx12xs_pc",
                "QueueX::ExecuteCommandLists(post_sync)",
                post_sync,
                &format!("#{call_n} kind={} count={count} sync_seq={sync_seq} sig_hr={sig_hr:#010x}", q.kind),
            );
        } else if !q.timing_fence.is_null() && q.pending_seq.load(Ordering::Relaxed) == 0 {
            let next = q.timing_seq.fetch_add(1, Ordering::Relaxed) + 1;
            q.pending_submit_qpc
                .store(shim_common::telemetry::qpc_now(), Ordering::Relaxed);
            if q.pending_seq
                .compare_exchange(0, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                type SigFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
                let _ = unsafe { com_slot::<SigFn>(q.real_queue, 14)(q.real_queue, q.timing_fence, next) };
            }
        }
    }
}
extern "system" fn queue_execute_x(
    this: *mut QueueX,
    count: u32,
    lists: *const *mut ListX,
    _token: u64,
    _flags: u32,
) {
    queue_execute(this, count, lists);
}
extern "system" fn queue_marker(_this: *mut QueueX, _meta: u32, _data: *const c_void, _size: u32) {}
fn ensure_fence_gpu_va_waiter(fence: *mut FenceX) {
    if fence.is_null() {
        return;
    }
    let f = unsafe { &*fence };
    type GetCompFn = unsafe extern "system" fn(*mut c_void) -> u64;
    let completed = unsafe { com_slot::<GetCompFn>(f.real_fence, 8)(f.real_fence) };
    f.value.fetch_max(completed, Ordering::Release);
    if f.last_signaled.load(Ordering::Acquire) <= completed {
        return;
    }
    if f.waiter_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    fence_add_ref(fence);
    let fence_addr = fence as usize;
    let spawn_res = std::thread::Builder::new()
        .name("lucias-fence-gpu-va".into())
        .spawn(move || {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
            let fx = unsafe { &*(fence_addr as *const FenceX) };
            let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            loop {
                let done = unsafe { com_slot::<GetCompFn>(fx.real_fence, 8)(fx.real_fence) };
                fx.value.fetch_max(done, Ordering::Release);
                let target = fx.last_signaled.load(Ordering::Acquire);
                if target <= done {
                    fx.waiter_active.store(false, Ordering::Release);
                    if fx.last_signaled.load(Ordering::Acquire) <= done {
                        break;
                    }
                    if fx
                        .waiter_active
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                if !ev.is_null() {
                    type SetEvFn =
                        unsafe extern "system" fn(*mut c_void, u64, *mut c_void) -> HRESULT;
                    let hr = unsafe {
                        com_slot::<SetEvFn>(fx.real_fence, 9)(fx.real_fence, target, ev)
                    };
                    if hr >= 0 {
                        unsafe { WaitForSingleObject(ev, 2000) };
                    } else {
                        fx.waiter_active.store(false, Ordering::Release);
                        break;
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            if !ev.is_null() {
                unsafe { CloseHandle(ev) };
            }
            fence_release(fence_addr as *mut FenceX);
        });
    if spawn_res.is_err() {
        f.waiter_active.store(false, Ordering::Release);
        fence_release(fence);
    }
}

extern "system" fn queue_signal(this: *mut QueueX, fence: *mut FenceX, val: u64) -> HRESULT {
    if fence.is_null() {
        return E_INVALIDARG;
    }
    let q = unsafe { &*this };
    let f = unsafe { &*fence };
    // Never advance `f.value` ahead of GPU completion (`queue_signal` is asynchronous GPU work).
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(q.real_queue, 14)(q.real_queue, f.real_fence, val) };
    if hr >= 0 {
        f.last_signaled.fetch_max(val, Ordering::AcqRel);
        if f.has_gpu_va_reader.load(Ordering::Acquire) {
            ensure_fence_gpu_va_waiter(fence);
        }
    }
    static SIG_CALLS: AtomicU32 = AtomicU32::new(0);
    let n = SIG_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if hr < 0 || n <= 8 {
        boot_trace_hr(
            "dx12xs_pc",
            "QueueX::Signal",
            hr,
            &format!("#{n} kind={} val={val}", q.kind),
        );
    }
    if hr < 0 {
        log_if_device_removed(unsafe { &*q.parent_dev }.real_device, "QueueX::Signal", hr);
    }
    hr
}
extern "system" fn queue_wait(this: *mut QueueX, fence: *mut FenceX, val: u64) -> HRESULT {
    if fence.is_null() {
        return E_INVALIDARG;
    }
    let q = unsafe { &*this };
    let f = unsafe { &*fence };
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u64) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(q.real_queue, 15)(q.real_queue, f.real_fence, val) };
    static WAIT_CALLS: AtomicU32 = AtomicU32::new(0);
    let n = WAIT_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if hr < 0 || n <= 16 {
        boot_trace_hr("dx12xs_pc", "QueueX::Wait", hr, &format!("#{n} kind={} val={val}", q.kind));
    }
    if hr < 0 {
        log_if_device_removed(unsafe { &*q.parent_dev }.real_device, "QueueX::Wait", hr);
    }
    hr
}
extern "system" fn queue_timestamp_freq(this: *mut QueueX, out: *mut u64) -> HRESULT {
    let q = unsafe { &*this };
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut u64) -> HRESULT;
    unsafe { com_slot::<FnTy>(q.real_queue, 16)(q.real_queue, out) }
}
extern "system" fn queue_desc(this: *mut QueueX, out: *mut PcQueueDesc) {
    if !out.is_null() {
        unsafe { out.write((&*this).desc) };
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct PresentPlanePrefixRaw {
    token: u64,
    count: u32,
    _pad: u32,
    resources: *const *mut ResourceX,
}

fn is_readable_bytes(ptr: *const c_void, bytes: usize) -> bool {
    if ptr.is_null() || bytes == 0 {
        return false;
    }
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, VirtualQuery};
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let vq = unsafe { VirtualQuery(ptr, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
    let prot = mbi.Protect & 0xFF;
    let readable = matches!(prot, 0x02 | 0x04 | 0x08 | 0x20 | 0x40) && (mbi.Protect & 0x101) == 0;
    if vq == 0 || mbi.State != MEM_COMMIT || !readable {
        return false;
    }
    let end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
    (ptr as usize).saturating_add(bytes) <= end
}

extern "system" fn queue_present_x(
    this: *mut QueueX,
    plane_count: u32,
    planes: *const c_void,
    _params: *const c_void,
) -> HRESULT {
    let q = unsafe { &*this };
    sample_queue_gpu_timing(q);
    let tick = q.present_tick.fetch_add(1, Ordering::Relaxed) + 1;

    let mut tok = 0u64;
    let mut cnt = 0u32;
    let mut r0: *mut ResourceX = std::ptr::null_mut();
    let mut real_r0: *mut c_void = std::ptr::null_mut();
    let mut r0_desc: Option<ResourceDescRaw> = None;
    let mut candidates: Vec<(*mut c_void, ResourceDescRaw, u32)> = Vec::new();
    let mut plane_detail = String::new();
    if plane_count > 0 && !planes.is_null() {
        let p0 = unsafe { planes.cast::<PresentPlanePrefixRaw>().read_unaligned() };
        tok = p0.token;
        cnt = p0.count;
        if p0.count > 0 && !p0.resources.is_null() {
            for i in 0..(p0.count as usize).min(4) {
                let res_ptr = unsafe { p0.resources.add(i).read_unaligned() };
                if !res_ptr.is_null() {
                    let r_ref = unsafe { &*res_ptr };
                    if i == 0 {
                        r0 = res_ptr;
                        real_r0 = r_ref.real_resource;
                        r0_desc = Some(r_ref.desc);
                    }
                    candidates.push((r_ref.real_resource, r_ref.desc, get_tracked_resource_state(r_ref.real_resource)));
                    if tick <= 4 {
                        plane_detail.push_str(&format!(
                            " p0[{i}]=({:?},{}x{},fmt={})",
                            r_ref.real_resource, r_ref.desc.width, r_ref.desc.height, r_ref.desc.format
                        ));
                    }
                }
            }
        }
        if plane_count > 1 {
            // Retail D3D12XBOX_PRESENT_PLANE_PARAMETERS stride is 72 bytes.
            let p1_ptr = unsafe { planes.cast::<u8>().add(72).cast::<PresentPlanePrefixRaw>() };
            if is_readable_bytes(p1_ptr.cast(), size_of::<PresentPlanePrefixRaw>()) {
                let p1 = unsafe { p1_ptr.read_unaligned() };
                if tick <= 4 {
                    plane_detail.push_str(&format!(" p1.cnt={}", p1.count));
                }
                if p1.count > 0 && is_readable_bytes(p1.resources.cast(), size_of::<*mut ResourceX>()) {
                    for i in 0..(p1.count as usize).min(4) {
                        let ptr_at = unsafe { p1.resources.add(i) };
                        if !is_readable_bytes(ptr_at.cast(), size_of::<*mut ResourceX>()) {
                            break;
                        }
                        let res_ptr = unsafe { ptr_at.read_unaligned() };
                        if !res_ptr.is_null() && is_readable_bytes(res_ptr.cast(), size_of::<ResourceX>()) {
                            let r_ref = unsafe { &*res_ptr };
                            candidates.push((
                                r_ref.real_resource,
                                r_ref.desc,
                                get_tracked_resource_state(r_ref.real_resource),
                            ));
                            if tick <= 4 {
                                plane_detail.push_str(&format!(
                                    " p1[{i}]=({:?},{}x{},fmt={})",
                                    r_ref.real_resource, r_ref.desc.width, r_ref.desc.height, r_ref.desc.format
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Prefer 4K scene plane (3840x2160) when both 4K and 1080p resources are present; keep other as alt_dump.
    let mut chosen_idx = 0usize;
    if let Some((idx4k, _)) = candidates
        .iter()
        .enumerate()
        .find(|(_, (_, d, _))| d.dimension == 3 && d.width >= 3840 && d.height >= 2160)
    {
        chosen_idx = idx4k;
    }
    if let Some((res, desc, _)) = candidates.get(chosen_idx).copied() {
        real_r0 = res;
        r0_desc = Some(desc);
    }
    let alt_dump = candidates
        .iter()
        .enumerate()
        .find(|(idx, (res, _, _))| *idx != chosen_idx && *res != real_r0)
        .map(|(_, &item)| item);

    let mut present_hr: Option<HRESULT> = None;
    let mut did_copy = false;
    if q.kind == 0 && !q.parent_dev.is_null() {
        let mut ctx_guard = q.present_ctx.lock().unwrap_or_else(|e| e.into_inner());
        if ctx_guard.is_none() && !CLEAR_RTV_MASK.no_present_init {
            let (req_w, req_h, req_fmt) = r0_desc
                .as_ref()
                .filter(|d| d.dimension == 3 && d.width >= 64 && d.height >= 64)
                .map_or((1920, 1080, 28), |d| (d.width as u32, d.height, d.format));
            let parent_dev = unsafe { &*q.parent_dev };
            *ctx_guard = crate::presenter::PresentContext::new(
                parent_dev.real_device,
                parent_dev.info_queue,
                req_w,
                req_h,
                req_fmt,
            );
        }
        if let Some(ctx) = ctx_guard.as_mut() {
            let cur_state = get_tracked_resource_state(real_r0);
            let copy_src = if CLEAR_RTV_MASK.no_present_copy {
                std::ptr::null_mut()
            } else {
                real_r0
            };
            let (hr, copied) = ctx.present_plane(
                q.real_queue,
                copy_src,
                r0_desc.as_ref(),
                cur_state,
                alt_dump,
                tick,
            );
            present_hr = Some(hr);
            did_copy = copied;
        }
    }

    if tick <= 4 {
        let plane_info = if plane_count > 0 && !planes.is_null() {
            format!("tok={tok:#x} cnt={cnt} r0={r0:?} real={real_r0:?}{plane_detail}")
        } else {
            String::from("none")
        };
        boot_trace(
            "dx12xs_pc",
            "QueueX::PresentX",
            &format!(
                "tick={tick} planes={plane_count} ptr={planes:?} [{plane_info}] target_hwnd={:#x} hud_hwnd={:#x} sc_hr={:?} copy={did_copy}",
                shim_common::telemetry::target_hwnd(),
                crate::overlay::current_hud_hwnd(),
                present_hr.map(|h| format!("{h:#010x}"))
            ),
        );
    }
    if (tick == 1 || tick.is_multiple_of(30)) && !q.parent_dev.is_null() {
        sample_vram_usage(unsafe { &*q.parent_dev }.dxgi_adapter3);
    }
    shim_common::telemetry::record_frame_present();
    crate::overlay::notify_present_tick();
    S_OK
}
extern "system" fn queue_noop_hr(_this: *mut QueueX) -> HRESULT {
    S_OK
}

const fn build_queue_table(newer: bool) -> [*const c_void; 36] {
    let mut t = fill_missing::<KIND_QUEUE, 36>();
    t[0] = queue_qi as *const c_void;
    t[1] = queue_add_ref as *const c_void;
    t[2] = queue_release as *const c_void;
    t[7] = queue_get_device as *const c_void;
    t[10] = queue_execute as *const c_void;
    t[11] = queue_marker as *const c_void;
    t[12] = queue_marker as *const c_void;
    t[13] = queue_marker as *const c_void;
    let shift = if newer { 2 } else { 0 };
    t[14 + shift] = queue_signal as *const c_void;
    t[15 + shift] = queue_wait as *const c_void;
    t[16 + shift] = queue_timestamp_freq as *const c_void;
    t[21 + shift] = queue_noop_hr as *const c_void; // Suspend
    t[22 + shift] = queue_noop_hr as *const c_void; // Resume
    t[26 + shift] = queue_desc as *const c_void;
    t[29 + shift] = queue_noop_hr as *const c_void; // CopyPageMappingsBatchX
    t[30 + shift] = queue_present_x as *const c_void;
    t[32 + shift] = queue_noop_hr as *const c_void; // Signal2X
    t[33 + shift] = queue_execute_x as *const c_void;
    t
}

static QUEUE_VTABLE: Table<36> = Table(build_queue_table(false));
static NEWER_QUEUE_VTABLE: Table<36> = Table(build_queue_table(true));

#[repr(C)]
pub struct AllocatorX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    parent_dev: *mut DeviceX,
    real_alloc: *mut c_void,
}

extern "system" fn alloc_qi(this: *mut AllocatorX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &ALLOCATOR_IIDS) {
        alloc_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn alloc_add_ref(this: *mut AllocatorX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn alloc_release(this: *mut AllocatorX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        unsafe { real_release(b.real_alloc) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn alloc_get_device(this: *mut AllocatorX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn alloc_reset(this: *mut AllocatorX) -> HRESULT {
    let real = unsafe { &*this }.real_alloc;
    type FnTy = unsafe extern "system" fn(*mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(real, 8)(real) };
    static ALLOC_RST_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = ALLOC_RST_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 128 || hr < 0 {
        boot_trace_hr("dx12xs_pc", "AllocatorX::Reset", hr, &format!("#{n} alloc={this:?}"));
    }
    hr
}
extern "system" fn alloc_noop_hr(_this: *mut AllocatorX) -> HRESULT {
    S_OK
}

static ALLOCATOR_VTABLE: Table<10> = Table([
    alloc_qi as *const c_void,
    alloc_add_ref as *const c_void,
    alloc_release as *const c_void,
    missing_slot::<KIND_ALLOCATOR, 3> as *const c_void,
    missing_slot::<KIND_ALLOCATOR, 4> as *const c_void,
    missing_slot::<KIND_ALLOCATOR, 5> as *const c_void,
    missing_slot::<KIND_ALLOCATOR, 6> as *const c_void,
    alloc_get_device as *const c_void,
    alloc_reset as *const c_void,
    alloc_noop_hr as *const c_void,
]);

#[repr(C)]
pub struct FenceX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    value: AtomicU64,
    last_signaled: AtomicU64,
    flags: u32,
    has_gpu_va_reader: AtomicBool,
    waiter_active: AtomicBool,
    parent_dev: *mut DeviceX,
    real_fence: *mut c_void,
}

extern "system" fn fence_qi(this: *mut FenceX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &FENCE_IIDS) {
        fence_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn fence_add_ref(this: *mut FenceX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn fence_release(this: *mut FenceX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        unsafe { real_release(b.real_fence) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn fence_get_device(this: *mut FenceX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn fence_get_completed(this: *mut FenceX) -> u64 {
    let f = unsafe { &*this };
    type FnTy = unsafe extern "system" fn(*mut c_void) -> u64;
    let real_v = unsafe { com_slot::<FnTy>(f.real_fence, 8)(f.real_fence) };
    f.value.fetch_max(real_v, Ordering::Release);
    static FENCE_COMP_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = FENCE_COMP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 {
        boot_trace("dx12xs_pc", "FenceX::GetCompletedValue", &format!("#{n} val={real_v}"));
    }
    real_v
}
extern "system" fn fence_set_event(this: *mut FenceX, val: u64, event: *mut c_void) -> HRESULT {
    let f = unsafe { &*this };
    type FnTy = unsafe extern "system" fn(*mut c_void, u64, *mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(f.real_fence, 9)(f.real_fence, val, event) };
    static FENCE_EV_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = FENCE_EV_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || hr < 0 {
        boot_trace_hr("dx12xs_pc", "FenceX::SetEventOnCompletion", hr, &format!("#{n} val={val}"));
    }
    hr
}
extern "system" fn fence_signal(this: *mut FenceX, val: u64) -> HRESULT {
    let f = unsafe { &*this };
    f.last_signaled.fetch_max(val, Ordering::AcqRel);
    f.value.store(val, Ordering::Release);
    type FnTy = unsafe extern "system" fn(*mut c_void, u64) -> HRESULT;
    unsafe { com_slot::<FnTy>(f.real_fence, 10)(f.real_fence, val) }
}
extern "system" fn fence_flags(this: *mut FenceX) -> u32 {
    unsafe { &*this }.flags
}
extern "system" fn fence_gpu_va(this: *mut FenceX) -> u64 {
    let f = unsafe { &*this };
    f.has_gpu_va_reader.store(true, Ordering::Release);
    ensure_fence_gpu_va_waiter(this);
    static FENCE_VA_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = FENCE_VA_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 {
        boot_trace(
            "dx12xs_pc",
            "FenceX::GetGpuVirtualAddress",
            &format!(
                "#{n} fence={this:?} val={} signaled={}",
                f.value.load(Ordering::Acquire),
                f.last_signaled.load(Ordering::Acquire)
            ),
        );
    }
    (&raw const f.value) as u64
}

static FENCE_VTABLE: Table<24> = {
    let mut t = fill_missing::<KIND_FENCE, 24>();
    t[0] = fence_qi as *const c_void;
    t[1] = fence_add_ref as *const c_void;
    t[2] = fence_release as *const c_void;
    t[7] = fence_get_device as *const c_void;
    t[8] = fence_get_completed as *const c_void;
    t[9] = fence_set_event as *const c_void;
    t[10] = fence_signal as *const c_void;
    t[11] = fence_flags as *const c_void;
    t[12] = fence_gpu_va as *const c_void;
    Table(t)
};

type ListOpsRing = ([(&'static str, u64, u64); 16], usize);

#[repr(C)]
pub struct ListX {
    vtable: *const *const c_void,
    bits: u32,
    refs: AtomicU32,
    kind: u32,
    put: [u64; 5],
    _xbox_pad: [u32; 1384],
    parent_dev: *mut DeviceX,
    real_list: *mut c_void,
    closed: AtomicBool,
    has_real_pso: AtomicBool,
    cur_pso_used_fallback: AtomicBool,
    last_cmp_pso_upgrade: AtomicUsize,
    uploads: Mutex<Vec<(usize, Layout)>>,
    recent_ops: Mutex<ListOpsRing>,
    last_pso: AtomicUsize,
    last_gfx_rs: AtomicUsize,
    last_vb_count: AtomicU32,
    last_rtv_count: AtomicU32,
}

const _: () = assert!(std::mem::offset_of!(ListX, put) == 0x18);
const _: () = assert!(size_of::<ListX>() >= 0x600);

fn push_op_ring(ring: &mut ListOpsRing, op: &'static str, a0: u64, a1: u64) {
    let idx = ring.1 % 16;
    ring.0[idx] = (op, a0, a1);
    ring.1 = ring.1.wrapping_add(1);
}

fn format_ops_ring(ring: &ListOpsRing) -> String {
    use std::fmt::Write;
    let total = ring.1;
    let count = total.min(16);
    let start = total.saturating_sub(count);
    let mut s = String::new();
    for seq in start..total {
        let (op, a0, a1) = ring.0[seq % 16];
        if op.is_empty() {
            continue;
        }
        if !s.is_empty() {
            s.push_str(" | ");
        }
        let _ = write!(&mut s, "{op}({a0:#x},{a1:#x})");
    }
    if s.is_empty() {
        String::from("<empty>")
    } else {
        s
    }
}

fn clear_list_ops(l: &ListX) {
    let mut guard = l.recent_ops.lock().unwrap_or_else(|e| e.into_inner());
    guard.0 = [("", 0, 0); 16];
    guard.1 = 0;
}

fn record_list_op(this: *mut ListX, op: &'static str, a0: u64, a1: u64) {
    if this.is_null() {
        return;
    }
    let l = unsafe { &*this };
    let mut guard = l.recent_ops.lock().unwrap_or_else(|e| e.into_inner());
    push_op_ring(&mut guard, op, a0, a1);
}

fn dump_failed_batch_lists(
    call_n: u32,
    q_kind: u32,
    count: u32,
    lists: *const *mut ListX,
    unclosed: u32,
    pre_reason: HRESULT,
    post_reason: HRESULT,
) {
    static FAIL_DUMPS: AtomicU32 = AtomicU32::new(0);
    let dump_n = FAIL_DUMPS.fetch_add(1, Ordering::Relaxed) + 1;
    if dump_n > 8 || lists.is_null() {
        return;
    }
    for i in 0..(count as usize) {
        let l = unsafe { lists.add(i).read_unaligned() };
        let (real_l, list_kind, closed, ops) = if l.is_null() {
            (std::ptr::null_mut(), 0, false, String::from("<null>"))
        } else {
            let lr = unsafe { &*l };
            let guard = lr.recent_ops.lock().unwrap_or_else(|e| e.into_inner());
            (
                lr.real_list,
                lr.kind,
                lr.closed.load(Ordering::Acquire),
                format_ops_ring(&guard),
            )
        };
        boot_trace_hr(
            "dx12xs_pc",
            "QueueX::ExecuteCommandLists(fail_list)",
            post_reason,
            &format!(
                "batch=#{call_n}[{i}/{count}] kind={q_kind} list={real_l:?} list_kind={list_kind} closed={closed} unclosed={unclosed} pre={:#010x} post={:#010x} ops=[{ops}]",
                pre_reason as u32, post_reason as u32
            ),
        );
    }
}

fn free_list_uploads(uploads: &Mutex<Vec<(usize, Layout)>>) {
    let mut guard = uploads.lock().unwrap_or_else(|e| e.into_inner());
    for (addr, layout) in guard.drain(..) {
        if addr != 0 {
            unsafe { dealloc(addr as *mut u8, layout) };
        }
    }
}

extern "system" fn list_qi(this: *mut ListX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &LIST_IIDS) {
        list_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn list_add_ref(this: *mut ListX) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn list_release(this: *mut ListX) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        free_list_uploads(&b.uploads);
        unsafe { real_release(b.real_list) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn list_get_device(this: *mut ListX, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    dev_query_interface(unsafe { &*this }.parent_dev, iid, out)
}
extern "system" fn list_get_type(this: *mut ListX) -> u32 {
    unsafe { &*this }.kind
}
extern "system" fn list_close(this: *mut ListX) -> HRESULT {
    let l = unsafe { &*this };
    if l.closed.swap(true, Ordering::AcqRel) {
        return S_OK;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(l.real_list, 9)(l.real_list) };
    record_list_op(this, "Close", hr as u32 as u64, u64::from(l.kind));
    static CLOSE_CALLS: AtomicU32 = AtomicU32::new(0);
    let n = CLOSE_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if hr < 0 || n <= 128 {
        boot_trace_hr("dx12xs_pc", "ListX::Close", hr, &format!("#{n} list={:?} kind={}", l.real_list, l.kind));
    }
    if hr < 0 {
        log_if_device_removed(unsafe { &*l.parent_dev }.real_device, "ListX::Close", hr);
    }
    hr
}
extern "system" fn list_reset(this: *mut ListX, alloc: *mut AllocatorX, pso: *mut PipelineX) -> HRESULT {
    if alloc.is_null() {
        return E_INVALIDARG;
    }
    let l = unsafe { &*this };
    let real_alloc = unsafe { &*alloc }.real_alloc;
    let real_pso = if pso.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*pso }.real_pso
    };
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> HRESULT;
    let hr = unsafe { com_slot::<FnTy>(l.real_list, 10)(l.real_list, real_alloc, real_pso) };
    static RESET_CALLS: AtomicU32 = AtomicU32::new(0);
    let rn = RESET_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if hr >= 0 {
        l.closed.store(false, Ordering::Release);
        l.has_real_pso.store(!real_pso.is_null(), Ordering::Release);
        l.cur_pso_used_fallback.store(
            !pso.is_null() && unsafe { &*pso }.used_fallback_rs,
            Ordering::Release,
        );
        free_list_uploads(&l.uploads);
        clear_list_ops(l);
        l.last_pso.store(real_pso as usize, Ordering::Relaxed);
        l.last_gfx_rs.store(0, Ordering::Relaxed);
        l.last_vb_count.store(0, Ordering::Relaxed);
        l.last_rtv_count.store(0, Ordering::Relaxed);
        if rn <= 128 {
            boot_trace_hr(
                "dx12xs_pc",
                "ListX::Reset",
                hr,
                &format!("#{rn} list={:?} kind={} alloc={alloc:?} pso={pso:?}", l.real_list, l.kind),
            );
        }
    } else {
        boot_trace_hr(
            "dx12xs_pc",
            "ListX::Reset",
            hr,
            &format!("#{rn} list={:?} kind={} alloc={alloc:?} pso={pso:?}", l.real_list, l.kind),
        );
        log_if_device_removed(unsafe { &*l.parent_dev }.real_device, "ListX::Reset", hr);
    }
    hr
}
extern "system" fn list_set_pso(this: *mut ListX, pso: *mut PipelineX) {
    if this.is_null() || pso.is_null() {
        return;
    }
    let l = unsafe { &*this };
    if l.closed.load(Ordering::Acquire) {
        return;
    }
    let p_ref = unsafe { &*pso };
    let real_pso = p_ref.real_pso;
    l.has_real_pso.store(!real_pso.is_null(), Ordering::Release);
    l.cur_pso_used_fallback
        .store(p_ref.used_fallback_rs, Ordering::Release);
    l.last_cmp_pso_upgrade
        .store(p_ref.compute_rs_override as usize, Ordering::Release);
    static SET_PSO_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = SET_PSO_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    static S13_PSO_LOGS: AtomicU32 = AtomicU32::new(0);
    let s13_n = if crate::read_app_state() == Some(13) {
        S13_PSO_LOGS.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        999
    };
    if n <= 32 || s13_n <= 16 {
        boot_trace(
            "dx12xs_pc",
            "ListX::SetPipelineState",
            &format!(
                "#{n}(s13:{s13_n}) list={:?} pso={pso:?} real_pso={real_pso:?} fb={} rtv0={} dsv={} depth_en={} depth_fn={} vs={:#018x} ps={:#018x}",
                l.real_list, p_ref.used_fallback_rs, p_ref.diag_rtv0_fmt, p_ref.diag_dsv_fmt, p_ref.diag_depth_en, p_ref.diag_depth_func, p_ref.diag_vs_hash, p_ref.diag_ps_hash
            ),
        );
    }
    if !real_pso.is_null() {
        l.last_pso.store(real_pso as usize, Ordering::Relaxed);
        record_list_op(this, "SetPSO", real_pso as u64, u64::from(p_ref.used_fallback_rs));
        let real = l.real_list;
        type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void);
        unsafe { com_slot::<FnTy>(real, 25)(real, real_pso) };
    }
}
static TOTAL_DRAW_INSTANCED: AtomicU64 = AtomicU64::new(0);
pub(crate) static TOTAL_DRAW_INDEXED: AtomicU64 = AtomicU64::new(0);
static TOTAL_DISPATCH: AtomicU64 = AtomicU64::new(0);
static TOTAL_EXEC_INDIRECT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn gpu_draw_totals() -> (u64, u64, u64, u64) {
    (
        TOTAL_DRAW_INSTANCED.load(Ordering::Relaxed),
        TOTAL_DRAW_INDEXED.load(Ordering::Relaxed),
        TOTAL_DISPATCH.load(Ordering::Relaxed),
        TOTAL_EXEC_INDIRECT.load(Ordering::Relaxed),
    )
}

extern "system" fn list_execute_indirect(
    this: *mut ListX,
    sig: *mut CommandSignatureX,
    max_command_count: u32,
    arg_buffer: *mut ResourceX,
    arg_buffer_offset: u64,
    count_buffer: *mut ResourceX,
    count_buffer_offset: u64,
) {
    if this.is_null() || sig.is_null() {
        return;
    }
    let Some(real) = list_open_with_pso(this, "ExecuteIndirect", "") else {
        return;
    };
    let real_sig = unsafe { &*sig }.real_signature;
    if real_sig.is_null() {
        return;
    }
    let real_arg = if arg_buffer.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*arg_buffer }.real_resource
    };
    let real_cnt = if count_buffer.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { &*count_buffer }.real_resource
    };
    trace_list_gpu_op(real, "ExecuteIndirect", &format!("sig={real_sig:?} max={max_command_count} arg={real_arg:?}"));
    record_list_op(this, "ExecuteIndirect", real_sig as u64, u64::from(max_command_count));
    TOTAL_EXEC_INDIRECT.fetch_add(1, Ordering::Relaxed);
    type FnTy = unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        u32,
        *mut c_void,
        u64,
        *mut c_void,
        u64,
    );
    unsafe {
        com_slot::<FnTy>(real, 59)(
            real,
            real_sig,
            max_command_count,
            real_arg,
            arg_buffer_offset,
            real_cnt,
            count_buffer_offset,
        );
    }
}
extern "system" fn list_reset_x(
    this: *mut ListX,
    alloc: *mut AllocatorX,
    pso: *mut PipelineX,
    _flags: u32,
) -> HRESULT {
    list_reset(this, alloc, pso)
}
#[inline]
fn list_open_real(this: *mut ListX) -> Option<*mut c_void> {
    if this.is_null() {
        return None;
    }
    let l = unsafe { &*this };
    if l.closed.load(Ordering::Acquire) {
        return None;
    }
    Some(l.real_list)
}
extern "system" fn list_clear_state(this: *mut ListX, pso: *mut PipelineX) {
    let Some(real) = list_open_real(this) else { return; };
    let real_pso = if pso.is_null() { std::ptr::null_mut() } else { unsafe { &*pso }.real_pso };
    let l = unsafe { &*this };
    l.has_real_pso.store(!real_pso.is_null(), Ordering::Release);
    l.cur_pso_used_fallback.store(
        !pso.is_null() && unsafe { &*pso }.used_fallback_rs,
        Ordering::Release,
    );
    static CS_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = CS_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 64 {
        boot_trace("dx12xs_pc", "ListX::ClearState", &format!("#{n} list={real:?} pso={pso:?} real_pso={real_pso:?}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void);
    unsafe { com_slot::<FnTy>(real, 11)(real, real_pso) };
}
#[inline]
fn list_open_with_pso(this: *mut ListX, op: &str, detail: &str) -> Option<*mut c_void> {
    let real = list_open_real(this)?;
    let l = unsafe { &*this };
    if !l.has_real_pso.load(Ordering::Acquire) {
        static SKIP_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = SKIP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 8 {
            boot_trace("dx12xs_pc", "ListX::skip_no_pso", &format!("#{n} op={op} {detail}"));
        }
        return None;
    }
    if l.cur_pso_used_fallback.load(Ordering::Acquire) {
        static MISMATCH_LOGS: AtomicU32 = AtomicU32::new(0);
        let n = MISMATCH_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 16 {
            boot_trace("dx12xs_pc", "ListX::SKIP_MISMATCH_DISPATCH", &format!("#{n} op={op} {detail}"));
        }
        return None;
    }
    static EXEC_OP_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = EXEC_OP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        boot_trace("dx12xs_pc", "ListX::draw_or_dispatch", &format!("#{n} op={op} kind={} {detail}", l.kind));
    }
    Some(real)
}
extern "system" fn list_draw_instanced(this: *mut ListX, vtx_cnt: u32, inst_cnt: u32, start_vtx: u32, start_inst: u32) {
    let Some(real) = list_open_with_pso(
        this,
        "DrawInstanced",
        &format!("vtx={vtx_cnt} inst={inst_cnt} start_vtx={start_vtx}"),
    ) else {
        return;
    };
    record_list_op(this, "DrawInstanced", u64::from(vtx_cnt), u64::from(inst_cnt));
    let draw_n = TOTAL_DRAW_INSTANCED.fetch_add(1, Ordering::Relaxed) + 1;
    if draw_n == 40_000 {
        static LATE_DRAW_LOGGED: AtomicBool = AtomicBool::new(false);
        if !LATE_DRAW_LOGGED.swap(true, Ordering::AcqRel) {
            let l = unsafe { &*this };
            boot_trace(
                "dx12xs_pc",
                "ListX::late_draw_40000",
                &format!(
                    "list={real:?} pso={:#x} gfx_rs={:#x} vb_count={} rtv_count={} vertex_count={vtx_cnt} instance_count={inst_cnt}",
                    l.last_pso.load(Ordering::Relaxed),
                    l.last_gfx_rs.load(Ordering::Relaxed),
                    l.last_vb_count.load(Ordering::Relaxed),
                    l.last_rtv_count.load(Ordering::Relaxed),
                ),
            );
        }
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, u32, u32);
    unsafe { com_slot::<FnTy>(real, 12)(real, vtx_cnt, inst_cnt, start_vtx, start_inst) };
}
extern "system" fn list_draw_indexed(this: *mut ListX, idx_cnt: u32, inst_cnt: u32, start_idx: u32, base_vtx: i32, start_inst: u32) {
    let Some(real) = list_open_with_pso(
        this,
        "DrawIndexedInstanced",
        &format!("idx={idx_cnt} inst={inst_cnt} start_idx={start_idx}"),
    ) else {
        return;
    };
    static DRAW_IDX_LOGS: AtomicU32 = AtomicU32::new(0);
    let log_n = DRAW_IDX_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if log_n <= 16 {
        let l = unsafe { &*this };
        let pso = l.last_pso.load(Ordering::Relaxed);
        let rs = l.last_gfx_rs.load(Ordering::Relaxed);
        let vb = l.last_vb_count.load(Ordering::Relaxed);
        let rtv = l.last_rtv_count.load(Ordering::Relaxed);
        let ops = {
            let g = l.recent_ops.lock().unwrap_or_else(|e| e.into_inner());
            format_ops_ring(&g)
        };
        boot_trace(
            "dx12xs_pc",
            "ListX::DrawIndexed",
            &format!("#{log_n} list={this:?} idx={idx_cnt} inst={inst_cnt} start_idx={start_idx} base_vtx={base_vtx} start_inst={start_inst} pso={pso:#x} rs={rs:#x} vb={vb} rtv={rtv} ops=[{ops}]"),
        );
    }
    record_list_op(this, "DrawIndexed", u64::from(idx_cnt), u64::from(inst_cnt));
    TOTAL_DRAW_INDEXED.fetch_add(1, Ordering::Relaxed);
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, u32, i32, u32);
    unsafe { com_slot::<FnTy>(real, 13)(real, idx_cnt, inst_cnt, start_idx, base_vtx, start_inst) };
}
extern "system" fn list_dispatch(this: *mut ListX, x: u32, y: u32, z: u32) {
    let Some(real) = list_open_with_pso(this, "Dispatch", &format!("tg={x}x{y}x{z}")) else { return; };
    record_list_op(this, "Dispatch", (u64::from(x) << 32) | u64::from(y), u64::from(z));
    TOTAL_DISPATCH.fetch_add(1, Ordering::Relaxed);
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, u32);
    unsafe { com_slot::<FnTy>(real, 14)(real, x, y, z) };
}
fn trace_list_gpu_op(list_real: *mut c_void, op: &str, details: &str) {
    static GPU_OP_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = GPU_OP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 48 {
        boot_trace("dx12xs_pc", "ListX::gpu_op", &format!("#{n} list={list_real:?} op={op} {details}"));
    }
}
extern "system" fn list_copy_buffer_region(this: *mut ListX, dst: *mut ResourceX, dst_off: u64, src: *mut ResourceX, src_off: u64, bytes: u64) {
    let Some(real) = list_open_real(this) else { return; };
    if dst.is_null() || src.is_null() { return; }
    let real_dst = unsafe { &*dst }.real_resource;
    let real_src = unsafe { &*src }.real_resource;
    if real_dst.is_null() || real_src.is_null() { return; }
    trace_list_gpu_op(real, "CopyBufferRegion", &format!("dst={real_dst:?}+{dst_off} src={real_src:?}+{src_off} bytes={bytes}"));
    record_list_op(this, "CopyBuffer", real_dst as u64, bytes);
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u64, *mut c_void, u64, u64);
    unsafe { com_slot::<FnTy>(real, 15)(real, real_dst, dst_off, real_src, src_off, bytes) };
}
#[repr(C)]
#[derive(Clone, Copy)]
struct TextureCopyLocationRaw {
    resource: *mut ResourceX,
    ty: u32,
    _pad: u32,
    payload: [u64; 4],
}
extern "system" fn list_copy_texture_region(
    this: *mut ListX,
    dst: *const TextureCopyLocationRaw,
    dst_x: u32,
    dst_y: u32,
    dst_z: u32,
    src: *const TextureCopyLocationRaw,
    src_box: *const c_void,
) {
    let Some(real) = list_open_real(this) else { return; };
    if dst.is_null() || src.is_null() { return; }
    let mut dst_c = unsafe { dst.read_unaligned() };
    let mut src_c = unsafe { src.read_unaligned() };
    if dst_c.resource.is_null() || src_c.resource.is_null() { return; }
    dst_c.resource = unsafe { &*dst_c.resource }.real_resource.cast();
    src_c.resource = unsafe { &*src_c.resource }.real_resource.cast();
    if dst_c.resource.is_null() || src_c.resource.is_null() { return; }
    trace_list_gpu_op(real, "CopyTextureRegion", &format!("dst={:?}({dst_x},{dst_y},{dst_z}) src={:?}", dst_c.resource, src_c.resource));
    record_list_op(this, "CopyTexture", dst_c.resource as u64, src_c.resource as u64);
    type FnTy = unsafe extern "system" fn(*mut c_void, *const TextureCopyLocationRaw, u32, u32, u32, *const TextureCopyLocationRaw, *const c_void);
    unsafe { com_slot::<FnTy>(real, 16)(real, &dst_c, dst_x, dst_y, dst_z, &src_c, src_box) };
}
extern "system" fn list_copy_resource(this: *mut ListX, dst: *mut ResourceX, src: *mut ResourceX) {
    let Some(real) = list_open_real(this) else { return; };
    if dst.is_null() || src.is_null() { return; }
    let real_dst = unsafe { &*dst }.real_resource;
    let real_src = unsafe { &*src }.real_resource;
    if real_dst.is_null() || real_src.is_null() { return; }
    trace_list_gpu_op(real, "CopyResource", &format!("dst={real_dst:?} src={real_src:?}"));
    record_list_op(this, "CopyResource", real_dst as u64, real_src as u64);
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void);
    unsafe { com_slot::<FnTy>(real, 17)(real, real_dst, real_src) };
}
extern "system" fn list_resolve_subresource(this: *mut ListX, dst: *mut ResourceX, dst_sub: u32, src: *mut ResourceX, src_sub: u32, fmt: u32) {
    let Some(real) = list_open_real(this) else { return; };
    if dst.is_null() || src.is_null() { return; }
    let real_dst = unsafe { &*dst }.real_resource;
    let real_src = unsafe { &*src }.real_resource;
    if real_dst.is_null() || real_src.is_null() { return; }
    trace_list_gpu_op(real, "ResolveSubresource", &format!("dst={real_dst:?}[{dst_sub}] src={real_src:?}[{src_sub}] fmt={fmt}"));
    record_list_op(this, "ResolveSub", real_dst as u64, real_src as u64);
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut c_void, u32, u32);
    unsafe { com_slot::<FnTy>(real, 19)(real, real_dst, dst_sub, real_src, src_sub, map_xbox_dxgi_format(fmt)) };
}
extern "system" fn list_ia_set_topology(this: *mut ListX, topo: u32) {
    let Some(real) = list_open_real(this) else { return; };
    let pc_topo = sanitize_primitive_topology(topo);
    static TOPO_LOGS: AtomicU32 = AtomicU32::new(0);
    if TOPO_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
        boot_trace(
            "dx12xs_pc",
            "ListX::IASetPrimitiveTopology",
            &format!("list={real:?} raw_topo={topo} pc_topo={pc_topo}"),
        );
    }
    if DIAG_SKIP.ia {
        return;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32);
    unsafe { com_slot::<FnTy>(real, 20)(real, pc_topo) };
}
extern "system" fn list_rs_set_viewports(this: *mut ListX, count: u32, vps: *const c_void) {
    let Some(real) = list_open_real(this) else { return; };
    if count > 0 && !vps.is_null() {
        let f = unsafe { vps.cast::<[f32; 6]>().read_unaligned() };
        record_list_op(this, "SetVP", ((f[2] as u64) << 32) | (f[3] as u32 as u64), u64::from(count));
    } else {
        record_list_op(this, "SetVP", 0, u64::from(count));
    }
    static VP_LOGS: AtomicU32 = AtomicU32::new(0);
    static VP_LATE_LOGS: AtomicU32 = AtomicU32::new(0);
    let log_vp = VP_LOGS.fetch_add(1, Ordering::Relaxed) < 64
        || (TOTAL_DRAW_INDEXED.load(Ordering::Relaxed) > 0 && VP_LATE_LOGS.fetch_add(1, Ordering::Relaxed) < 16);
    if log_vp {
        let vp0 = if count > 0 && !vps.is_null() {
            let f = unsafe { vps.cast::<[f32; 6]>().read_unaligned() };
            format!("({},{},{}x{},d={}..{})", f[0], f[1], f[2], f[3], f[4], f[5])
        } else {
            String::from("none")
        };
        boot_trace("dx12xs_pc", "ListX::RSSetViewports", &format!("list={real:?} count={count} vp0={vp0}"));
    }
    if DIAG_SKIP.rs_vp {
        return;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const c_void);
    unsafe { com_slot::<FnTy>(real, 21)(real, count, vps) };
}
extern "system" fn list_rs_set_scissors(this: *mut ListX, count: u32, rects: *const c_void) {
    let Some(real) = list_open_real(this) else { return; };
    if count > 0 && !rects.is_null() {
        let r = unsafe { rects.cast::<[i32; 4]>().read_unaligned() };
        record_list_op(this, "SetScissor", ((r[2] as u64) << 32) | (r[3] as u32 as u64), ((r[0] as u64) << 32) | (r[1] as u32 as u64));
    } else {
        record_list_op(this, "SetScissor", 0, u64::from(count));
    }
    static SC_LOGS: AtomicU32 = AtomicU32::new(0);
    if SC_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        let r0 = if count > 0 && !rects.is_null() {
            let r = unsafe { rects.cast::<[i32; 4]>().read_unaligned() };
            format!("[{},{},{},{}]", r[0], r[1], r[2], r[3])
        } else {
            String::from("none")
        };
        boot_trace("dx12xs_pc", "ListX::RSSetScissorRects", &format!("list={real:?} count={count} r0={r0}"));
    }
    if DIAG_SKIP.rs_vp {
        return;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const c_void);
    unsafe { com_slot::<FnTy>(real, 22)(real, count, rects) };
}
extern "system" fn list_om_set_blend_factor(this: *mut ListX, factor: *const f32) {
    let Some(real) = list_open_real(this) else { return; };
    static BF_LOGS: AtomicU32 = AtomicU32::new(0);
    if BF_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::OMSetBlendFactor", &format!("list={real:?} ptr={factor:?}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *const f32);
    unsafe { com_slot::<FnTy>(real, 23)(real, factor) };
}
extern "system" fn list_om_set_stencil_ref(this: *mut ListX, stencil_ref: u32) {
    let Some(real) = list_open_real(this) else { return; };
    static SR_LOGS: AtomicU32 = AtomicU32::new(0);
    if SR_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::OMSetStencilRef", &format!("list={real:?} ref={stencil_ref:#x}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32);
    unsafe { com_slot::<FnTy>(real, 24)(real, stencil_ref) };
}
#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceBarrierRaw {
    ty: u32,
    flags: u32,
    u: [u64; 3],
}
extern "system" fn list_resource_barrier(this: *mut ListX, num_barriers: u32, barriers: *const ResourceBarrierRaw) {
    let Some(real) = list_open_real(this) else { return; };
    if num_barriers == 0 || barriers.is_null() { return; }
    static BARRIER_LOGS: AtomicU32 = AtomicU32::new(0);
    let mut out = Vec::with_capacity((num_barriers as usize).min(64));
    for i in 0..(num_barriers as usize).min(64) {
        let mut b = unsafe { barriers.add(i).read_unaligned() };
        match b.ty {
            0 => {
                if b.u[0] == 0 { continue; }
                let real_res = unsafe { &*(b.u[0] as *const ResourceX) }.real_resource;
                if real_res.is_null() { continue; }
                let sub = (b.u[1] & 0xFFFF_FFFF) as u32;
                let before = (b.u[1] >> 32) as u32;
                let after = (b.u[2] & 0xFFFF_FFFF) as u32;
                let n = BARRIER_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 128 {
                    boot_trace(
                        "dx12xs_pc",
                        "ListX::ResourceBarrier",
                        &format!("#{n} list={real:?} ty=0 res={real_res:?} sub={sub:#x} {before:#x}->{after:#x}"),
                    );
                }
                set_tracked_resource_state(real_res, after);
                b.u[0] = real_res as u64;
                out.push(b);
            }
            1 => {
                if b.u[0] != 0 {
                    let r0 = unsafe { &*(b.u[0] as *const ResourceX) }.real_resource;
                    if r0.is_null() { continue; }
                    b.u[0] = r0 as u64;
                }
                if b.u[1] != 0 {
                    let r1 = unsafe { &*(b.u[1] as *const ResourceX) }.real_resource;
                    if r1.is_null() { continue; }
                    b.u[1] = r1 as u64;
                }
                let n = BARRIER_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 128 {
                    boot_trace(
                        "dx12xs_pc",
                        "ListX::ResourceBarrier",
                        &format!("#{n} list={real:?} ty=1(ALIAS) r0={:#x} r1={:#x}", b.u[0], b.u[1]),
                    );
                }
                out.push(b);
            }
            2 => {
                if b.u[0] != 0 {
                    let r = unsafe { &*(b.u[0] as *const ResourceX) }.real_resource;
                    if r.is_null() { continue; }
                    b.u[0] = r as u64;
                }
                let n = BARRIER_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 128 {
                    boot_trace(
                        "dx12xs_pc",
                        "ListX::ResourceBarrier",
                        &format!("#{n} list={real:?} ty=2(UAV) r={:#x}", b.u[0]),
                    );
                }
                out.push(b);
            }
            _ => {}
        }
    }
    if !out.is_empty() && !DIAG_SKIP.barriers {
        record_list_op(
            this,
            "Barrier",
            out[0].u[0],
            (out.len() as u64) << 32 | (out[0].u[2] & 0xFFFF_FFFF),
        );
        type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const ResourceBarrierRaw);
        unsafe { com_slot::<FnTy>(real, 26)(real, out.len() as u32, out.as_ptr()) };
    }
}
extern "system" fn list_begin_query(this: *mut ListX, qh: *mut c_void, ty: u32, index: u32) {
    let Some(real) = list_open_real(this) else { return; };
    if qh.is_null() { return; }
    static Q_LOGS: AtomicU32 = AtomicU32::new(0);
    if Q_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
        boot_trace("dx12xs_pc", "ListX::BeginQuery", &format!("list={real:?} qh={qh:?} ty={ty} idx={index}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32);
    unsafe { com_slot::<FnTy>(real, 52)(real, qh, ty, index) };
}
extern "system" fn list_end_query(this: *mut ListX, qh: *mut c_void, ty: u32, index: u32) {
    let Some(real) = list_open_real(this) else { return; };
    if qh.is_null() { return; }
    static Q_LOGS: AtomicU32 = AtomicU32::new(0);
    if Q_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
        boot_trace("dx12xs_pc", "ListX::EndQuery", &format!("list={real:?} qh={qh:?} ty={ty} idx={index}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32);
    unsafe { com_slot::<FnTy>(real, 53)(real, qh, ty, index) };
}
extern "system" fn list_resolve_query_data(
    this: *mut ListX,
    qh: *mut c_void,
    ty: u32,
    start_index: u32,
    num_queries: u32,
    dst: *mut ResourceX,
    dst_offset: u64,
) {
    let Some(real) = list_open_real(this) else { return; };
    if qh.is_null() || dst.is_null() { return; }
    let real_dst = unsafe { &*dst }.real_resource;
    if real_dst.is_null() { return; }
    static Q_LOGS: AtomicU32 = AtomicU32::new(0);
    if Q_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
        boot_trace(
            "dx12xs_pc",
            "ListX::ResolveQueryData",
            &format!("list={real:?} qh={qh:?} ty={ty} start={start_index} num={num_queries} dst={real_dst:?}+{dst_offset}"),
        );
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, u32, *mut c_void, u64);
    unsafe { com_slot::<FnTy>(real, 54)(real, qh, ty, start_index, num_queries, real_dst, dst_offset) };
}
extern "system" fn list_set_descriptor_heaps(
    this: *mut ListX,
    count: u32,
    heaps: *const *mut DescriptorHeapX,
) {
    let Some(real) = list_open_real(this) else { return; };
    if count == 0 || heaps.is_null() {
        return;
    }
    let mut real_heaps = [std::ptr::null_mut::<c_void>(); 4];
    let mut heap_descs = String::new();
    let mut n = 0usize;
    for i in 0..(count as usize) {
        let h = unsafe { heaps.add(i).read_unaligned() };
        if !h.is_null() && n < real_heaps.len() {
            let hr = unsafe { &*h };
            if !hr.real_heap.is_null() && (hr.desc.flags & 1) != 0 {
                if !heap_descs.is_empty() {
                    heap_descs.push(',');
                }
                heap_descs.push_str(&format!(
                    "{:?}(ty={},num={},flg={:#x})",
                    hr.real_heap, hr.desc.ty, hr.desc.num_descriptors, hr.desc.flags
                ));
                real_heaps[n] = hr.real_heap;
                n += 1;
            }
        }
    }
    if n > 0 {
        static DH_LOGS: AtomicU32 = AtomicU32::new(0);
        let ln = DH_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if ln <= 128 {
            boot_trace(
                "dx12xs_pc",
                "ListX::SetDescriptorHeaps",
                &format!("#{ln} list={real:?} n={n} [{heap_descs}]"),
            );
        }
        if !DIAG_SKIP.heaps {
            type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const *mut c_void);
            unsafe { com_slot::<FnTy>(real, 28)(real, n as u32, real_heaps.as_ptr()) };
        }
    }
}
fn bind_synthetic_b0_for_root_sig(this: *mut ListX, real_list: *mut c_void, root_sig: *mut c_void, is_compute: bool) {
    if this.is_null() || root_sig.is_null() {
        return;
    }
    let l = unsafe { &*this };
    if l.parent_dev.is_null() {
        return;
    }
    let d = unsafe { &*l.parent_dev };
    let synth_slots = d
        .synthetic_rs_slots
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(root_sig as usize))
        .copied();
    if let Some(slots) = synth_slots {
        let va = ensure_null_cb_gpu_va(d);
        let cbv_slot = if is_compute { 37 } else { 38 };
        let srv_slot = if is_compute { 39 } else { 40 };
        static B0_LOGS: AtomicU32 = AtomicU32::new(0);
        let bn = B0_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
        if bn <= 32 {
            boot_trace(
                "dx12xs_pc",
                "ListX::bind_synth_rs",
                &format!(
                    "#{bn} list={real_list:?} rs={root_sig:?} b0={:?} t255={:?} compute={is_compute} va={va:#x} skip={}",
                    slots.b0_slot, slots.t255_s1_slot, DIAG_SKIP.bind_b0
                ),
            );
        }
        if va != 0 && !DIAG_SKIP.bind_b0 {
            type ViewFn = unsafe extern "system" fn(*mut c_void, u32, u64);
            if let Some(b0_idx) = slots.b0_slot {
                unsafe { com_slot::<ViewFn>(real_list, cbv_slot)(real_list, b0_idx, va) };
            }
            if let Some(t255_idx) = slots.t255_s1_slot {
                unsafe { com_slot::<ViewFn>(real_list, srv_slot)(real_list, t255_idx, va) };
            }
        }
    }
}
extern "system" fn list_set_compute_root_sig(this: *mut ListX, root_sig: *mut c_void) {
    let Some(real) = list_open_real(this) else { return; };
    let l = unsafe { &*this };
    let use_rs = if l.last_cmp_pso_upgrade.load(Ordering::Acquire) != 0 && !l.parent_dev.is_null() {
        let d = unsafe { &*l.parent_dev };
        d.compute_rs_upgrades
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(root_sig as usize))
            .copied()
            .map_or(root_sig, |up| up as *mut c_void)
    } else {
        root_sig
    };
    record_list_op(this, "SetCmpRS", use_rs as u64, 0);
    static CRS_LOGS: AtomicU32 = AtomicU32::new(0);
    let ln = CRS_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if ln <= 128 {
        boot_trace("dx12xs_pc", "ListX::SetComputeRootSignature", &format!("#{ln} list={real:?} rs={use_rs:?} orig={root_sig:?}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void);
    unsafe { com_slot::<FnTy>(real, 29)(real, use_rs) };
    bind_synthetic_b0_for_root_sig(this, real, root_sig, true);
}
extern "system" fn list_set_graphics_root_sig(this: *mut ListX, root_sig: *mut c_void) {
    let Some(real) = list_open_real(this) else { return; };
    unsafe { &*this }
        .last_gfx_rs
        .store(root_sig as usize, Ordering::Relaxed);
    record_list_op(this, "SetGfxRS", root_sig as u64, 0);
    static GRS_LOGS: AtomicU32 = AtomicU32::new(0);
    let ln = GRS_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if ln <= 128 {
        boot_trace("dx12xs_pc", "ListX::SetGraphicsRootSignature", &format!("#{ln} list={real:?} rs={root_sig:?}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut c_void);
    unsafe { com_slot::<FnTy>(real, 30)(real, root_sig) };
    bind_synthetic_b0_for_root_sig(this, real, root_sig, false);
}
extern "system" fn list_set_compute_root_table(this: *mut ListX, param: u32, base_gpu: u64) {
    let Some(real) = list_open_real(this) else { return; };
    let pc_gpu = translate_gpu_handle(base_gpu);
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::SetComputeRootDescriptorTable", &format!("list={real:?} p={param} xb={base_gpu:#x} pc={pc_gpu:?}"));
    }
    let Some(pc_gpu) = pc_gpu else { return; };
    record_list_op(this, "SetGfxTbl", u64::from(param), pc_gpu);
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u64);
    unsafe { com_slot::<FnTy>(real, 31)(real, param, pc_gpu) };
}
extern "system" fn list_set_graphics_root_table(this: *mut ListX, param: u32, base_gpu: u64) {
    let Some(real) = list_open_real(this) else { return; };
    let pc_gpu = translate_gpu_handle(base_gpu);
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::SetGraphicsRootDescriptorTable", &format!("list={real:?} p={param} xb={base_gpu:#x} pc={pc_gpu:?}"));
    }
    let Some(pc_gpu) = pc_gpu else { return; };
    record_list_op(this, "SetGfxTbl", u64::from(param), pc_gpu);
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u64);
    unsafe { com_slot::<FnTy>(real, 32)(real, param, pc_gpu) };
}
extern "system" fn list_set_compute_root_const(this: *mut ListX, param: u32, data: u32, off: u32) {
    let Some(real) = list_open_real(this) else { return; };
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::SetComputeRoot32BitConstant", &format!("list={real:?} p={param} data={data:#x} off={off}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, u32);
    unsafe { com_slot::<FnTy>(real, 33)(real, param, data, off) };
}
extern "system" fn list_set_graphics_root_const(this: *mut ListX, param: u32, data: u32, off: u32) {
    let Some(real) = list_open_real(this) else { return; };
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::SetGraphicsRoot32BitConstant", &format!("list={real:?} p={param} data={data:#x} off={off}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, u32);
    unsafe { com_slot::<FnTy>(real, 34)(real, param, data, off) };
}
extern "system" fn list_set_compute_root_consts(this: *mut ListX, param: u32, cnt: u32, data: *const c_void, off: u32) {
    let Some(real) = list_open_real(this) else { return; };
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::SetComputeRoot32BitConstants", &format!("list={real:?} p={param} cnt={cnt} off={off}"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, *const c_void, u32);
    unsafe { com_slot::<FnTy>(real, 35)(real, param, cnt, data, off) };
}
extern "system" fn list_set_graphics_root_consts(this: *mut ListX, param: u32, cnt: u32, data: *const c_void, off: u32) {
    let Some(real) = list_open_real(this) else { return; };
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        let vals = if !data.is_null() && cnt > 0 {
            let n = (cnt as usize).min(4);
            (0..n)
                .map(|i| format!("{:#x}", unsafe { data.cast::<u32>().add(i).read_unaligned() }))
                .collect::<Vec<_>>()
                .join(",")
        } else {
            String::new()
        };
        boot_trace("dx12xs_pc", "ListX::SetGraphicsRoot32BitConstants", &format!("list={real:?} p={param} cnt={cnt} off={off} vals=[{vals}]"));
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, *const c_void, u32);
    unsafe { com_slot::<FnTy>(real, 36)(real, param, cnt, data, off) };
}
fn forward_root_gpu_va(this: *mut ListX, pc_slot: usize, param: u32, va: u64) {
    let Some(real) = list_open_real(this) else { return; };
    let ok = va != 0 && find_registered_gpu_buffer(va, 4);
    static LOGS: AtomicU32 = AtomicU32::new(0);
    if LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::SetRootView", &format!("list={real:?} slot={pc_slot} p={param} va={va:#x} ok={ok}"));
    }
    if ok {
        type FnTy = unsafe extern "system" fn(*mut c_void, u32, u64);
        unsafe { com_slot::<FnTy>(real, pc_slot)(real, param, va) };
    }
}
extern "system" fn list_set_compute_root_cbv(this: *mut ListX, param: u32, va: u64) {
    forward_root_gpu_va(this, 37, param, va);
}
extern "system" fn list_set_graphics_root_cbv(this: *mut ListX, param: u32, va: u64) {
    forward_root_gpu_va(this, 38, param, va);
}
extern "system" fn list_set_compute_root_srv(this: *mut ListX, param: u32, va: u64) {
    forward_root_gpu_va(this, 39, param, va);
}
extern "system" fn list_set_graphics_root_srv(this: *mut ListX, param: u32, va: u64) {
    forward_root_gpu_va(this, 40, param, va);
}
extern "system" fn list_set_compute_root_uav(this: *mut ListX, param: u32, va: u64) {
    forward_root_gpu_va(this, 41, param, va);
}
extern "system" fn list_set_graphics_root_uav(this: *mut ListX, param: u32, va: u64) {
    forward_root_gpu_va(this, 42, param, va);
}
extern "system" fn list_ia_set_index_buffer(this: *mut ListX, view: *const [u64; 2]) {
    let Some(real) = list_open_real(this) else { return; };
    let v = if view.is_null() { [0u64; 2] } else { unsafe { view.read_unaligned() } };
    let va = v[0];
    let size = (v[1] & 0xFFFF_FFFF) as u32;
    let fmt = (v[1] >> 32) as u32;
    static IB_LOGS: AtomicU32 = AtomicU32::new(0);
    if IB_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::IASetIndexBuffer", &format!("list={real:?} null={} va={va:#x} size={size} fmt={fmt}", view.is_null()));
    }
    if DIAG_SKIP.ia {
        return;
    }
    if view.is_null() {
        type FnTy = unsafe extern "system" fn(*mut c_void, *const [u64; 2]);
        unsafe { com_slot::<FnTy>(real, 43)(real, std::ptr::null()) };
        return;
    }
    if va == 0 {
        // PC D3D12 treats BufferLocation=0 with non-zero SizeInBytes or invalid Format as invalid/TDR risk.
        let zero = [0u64; 2];
        type FnTy = unsafe extern "system" fn(*mut c_void, *const [u64; 2]);
        unsafe { com_slot::<FnTy>(real, 43)(real, &zero) };
        return;
    }
    if find_registered_gpu_buffer(va, 4) {
        type FnTy = unsafe extern "system" fn(*mut c_void, *const [u64; 2]);
        unsafe { com_slot::<FnTy>(real, 43)(real, view) };
    } else {
        let l = unsafe { &*this };
        if !l.parent_dev.is_null() {
            let d = unsafe { &*l.parent_dev };
            let sz = size as usize;
            if let Some(pc_va) = upload_cpu_slice_to_gpu_va(d, va, sz, sz.next_multiple_of(16), 16) {
                static UMA_IB_LOGS: AtomicU32 = AtomicU32::new(0);
                let n = UMA_IB_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 16 {
                    boot_trace(
                        "dx12xs_pc",
                        "ListX::IASetIndexBuffer(uma-upload)",
                        &format!("#{n} list={real:?} xb={va:#x} pc={pc_va:#x} size={size} fmt={fmt}"),
                    );
                }
                let patched = [pc_va, v[1]];
                type FnTy = unsafe extern "system" fn(*mut c_void, *const [u64; 2]);
                unsafe { com_slot::<FnTy>(real, 43)(real, &patched) };
            }
        }
    }
}
extern "system" fn list_ia_set_vertex_buffers(this: *mut ListX, start: u32, count: u32, views: *const [u64; 2]) {
    let Some(real) = list_open_real(this) else { return; };
    if count == 0 || views.is_null() {
        unsafe { &*this }.last_vb_count.store(0, Ordering::Relaxed);
        static VB_EMPTY_LOGS: AtomicU32 = AtomicU32::new(0);
        if VB_EMPTY_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
            boot_trace("dx12xs_pc", "ListX::IASetVertexBuffers", &format!("list={real:?} start={start} count={count} empty=true"));
        }
        if !DIAG_SKIP.ia {
            type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, *const [u64; 2]);
            unsafe { com_slot::<FnTy>(real, 44)(real, start, count, views) };
        }
        return;
    }
    let l = unsafe { &*this };
    let n_views = (count as usize).min(16);
    let mut patched = [[0u64; 2]; 16];
    let mut all_ok = true;
    let mut used_uma = false;
    let mut reg_status = true;
    for (i, dst) in patched.iter_mut().enumerate().take(n_views) {
        let v = unsafe { views.add(i).read_unaligned() };
        *dst = v;
        if v[0] != 0 && !find_registered_gpu_buffer(v[0], 4) {
            reg_status = false;
            let sz = (v[1] & 0xFFFF_FFFF) as usize;
            let stride = (v[1] >> 32) as u32;
            let uploaded = if !l.parent_dev.is_null() {
                let d = unsafe { &*l.parent_dev };
                upload_cpu_slice_to_gpu_va(d, v[0], sz, sz.next_multiple_of(16), 16)
            } else {
                None
            };
            if let Some(pc_va) = uploaded {
                dst[0] = pc_va;
                used_uma = true;
                static UMA_VB_LOGS: AtomicU32 = AtomicU32::new(0);
                let n = UMA_VB_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                static LARGE_VB_LOGS: AtomicU32 = AtomicU32::new(0);
                let large_n = if sz > 4080 {
                    LARGE_VB_LOGS.fetch_add(1, Ordering::Relaxed) + 1
                } else {
                    999
                };
                if n <= 8 || large_n <= 8 {
                    let preview = if sz >= 16 {
                        let f = unsafe { (v[0] as *const [f32; 4]).read_unaligned() };
                        format!(" f0=[{:.3},{:.3},{:.3},{:.3}]", f[0], f[1], f[2], f[3])
                    } else {
                        String::new()
                    };
                    boot_trace(
                        "dx12xs_pc",
                        "ListX::IASetVertexBuffers(uma-upload)",
                        &format!("#{n}(L{large_n}) list={real:?} slot={i} xb={:#x} pc={pc_va:#x} size={sz} stride={stride}{preview}", v[0]),
                    );
                }
            } else {
                all_ok = false;
            }
        }
    }
    static VB_LOGS: AtomicU32 = AtomicU32::new(0);
    if VB_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        let v0 = unsafe { views.read_unaligned() };
        let sz = (v0[1] & 0xFFFF_FFFF) as u32;
        let stride = (v0[1] >> 32) as u32;
        boot_trace(
            "dx12xs_pc",
            "ListX::IASetVertexBuffers",
            &format!(
                "list={real:?} start={start} count={count} registered={reg_status} uma={used_uma} ok={all_ok} v0=[{:#x},{sz},{stride}]",
                v0[0]
            ),
        );
    }
    if DIAG_SKIP.ia || !all_ok {
        return;
    }
    l.last_vb_count.store(n_views as u32, Ordering::Relaxed);
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, u32, *const [u64; 2]);
    unsafe { com_slot::<FnTy>(real, 44)(real, start, n_views as u32, patched.as_ptr()) };
}
extern "system" fn list_om_set_render_targets(
    this: *mut ListX,
    num_rtvs: u32,
    rtvs: *const u64,
    single_handle: i32,
    dsv: *const u64,
) {
    let Some(real) = list_open_real(this) else { return; };
    let mut pc_rtvs = [0u64; 8];
    let rtv_count = num_rtvs.min(8) as usize;
    let rtv_ptr = if rtv_count > 0 && !rtvs.is_null() {
        if single_handle != 0 {
            let Some(pc) = translate_cpu_handle_for_ty(unsafe { *rtvs }, Some(2)) else {
                return;
            };
            ensure_list_view_state(real, pc, 0x4); // D3D12_RESOURCE_STATE_RENDER_TARGET
            pc_rtvs[0] = pc;
        } else {
            for (i, pc_slot) in pc_rtvs.iter_mut().enumerate().take(rtv_count) {
                let h = unsafe { rtvs.add(i).read_unaligned() };
                let Some(pc) = translate_cpu_handle_for_ty(h, Some(2)) else {
                    return;
                };
                ensure_list_view_state(real, pc, 0x4);
                *pc_slot = pc;
            }
        }
        pc_rtvs.as_ptr()
    } else {
        std::ptr::null()
    };
    let pc_dsv;
    let dsv_ptr = if !dsv.is_null() {
        let Some(pc) = translate_cpu_handle_for_ty(unsafe { *dsv }, Some(3)) else {
            return;
        };
        ensure_list_view_state(real, pc, 0x10); // D3D12_RESOURCE_STATE_DEPTH_WRITE
        pc_dsv = pc;
        &raw const pc_dsv
    } else {
        std::ptr::null()
    };
    static OM_LOGS: AtomicU32 = AtomicU32::new(0);
    static OM_LATE_LOGS: AtomicU32 = AtomicU32::new(0);
    let log_om = OM_LOGS.fetch_add(1, Ordering::Relaxed) < 128
        || (TOTAL_DRAW_INDEXED.load(Ordering::Relaxed) > 0 && OM_LATE_LOGS.fetch_add(1, Ordering::Relaxed) < 16);
    if log_om {
        boot_trace(
            "dx12xs_pc",
            "ListX::OMSetRenderTargets",
            &format!(
                "list={real:?} num_rtvs={num_rtvs} single={single_handle} rtv0={:#x} dsv={:#x}",
                pc_rtvs[0],
                if dsv_ptr.is_null() { 0 } else { unsafe { *dsv_ptr } }
            ),
        );
    }
    if DIAG_SKIP.om_rt {
        return;
    }
    unsafe { &*this }
        .last_rtv_count
        .store(num_rtvs.min(8), Ordering::Relaxed);
    let first_view = if num_rtvs > 0 {
        pc_rtvs[0]
    } else if !dsv_ptr.is_null() {
        unsafe { *dsv_ptr }
    } else {
        0
    };
    record_list_op(
        this,
        "OMSetRT",
        (u64::from(num_rtvs) << 32) | u64::from(!dsv_ptr.is_null()),
        first_view,
    );
    type FnTy = unsafe extern "system" fn(*mut c_void, u32, *const u64, i32, *const u64);
    unsafe { com_slot::<FnTy>(real, 46)(real, num_rtvs.min(8), rtv_ptr, single_handle, dsv_ptr) };
}
extern "system" fn list_clear_dsv(
    this: *mut ListX,
    dsv: u64,
    flags: u32,
    depth: f32,
    stencil: u8,
    num_rects: u32,
    rects: *const c_void,
) {
    let Some(real) = list_open_real(this) else { return; };
    let Some(pc_dsv) = translate_cpu_handle_for_ty(dsv, Some(3)) else {
        return;
    };
    ensure_list_view_state(real, pc_dsv, 0x10); // D3D12_RESOURCE_STATE_DEPTH_WRITE
    trace_list_gpu_op(real, "ClearDSV", &format!("dsv={pc_dsv:#x}"));
    record_list_op(this, "ClearDSV", pc_dsv, u64::from(flags));
    type FnTy = unsafe extern "system" fn(*mut c_void, u64, u32, f32, u8, u32, *const c_void);
    unsafe { com_slot::<FnTy>(real, 47)(real, pc_dsv, flags, depth, stencil, num_rects, rects) };
}
fn validate_clear_rects(num_rects: u32, rects: *const c_void) -> (u32, *const c_void, Option<[i32; 4]>, bool) {
    if num_rects == 0 {
        return (0, std::ptr::null(), None, false);
    }
    if rects.is_null() || num_rects > 64 {
        return (0, std::ptr::null(), None, true);
    }
    let rect_ptr = rects.cast::<[i32; 4]>();
    let first = unsafe { rect_ptr.read_unaligned() };
    for i in 0..num_rects as usize {
        let [l, t, r, b] = unsafe { rect_ptr.add(i).read_unaligned() };
        if r <= l || b <= t || r > 16384 || b > 16384 || l < 0 || t < 0 {
            return (0, std::ptr::null(), Some(first), true);
        }
    }
    (num_rects, rects, Some(first), false)
}

extern "system" fn list_clear_rtv(
    this: *mut ListX,
    rtv: u64,
    color_rgba: *const [f32; 4],
    num_rects: u32,
    rects: *const c_void,
) {
    let Some(real) = list_open_real(this) else { return; };
    if color_rgba.is_null() {
        return;
    }
    let Some(pc_rtv) = translate_cpu_handle_for_ty(rtv, Some(2)) else {
        return;
    };
    ensure_list_view_state(real, pc_rtv, 0x4); // D3D12_RESOURCE_STATE_RENDER_TARGET
    let res_key = VIEW_TO_RESOURCE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&pc_rtv)
        .copied()
        .unwrap_or(0);
    let rgba = unsafe { color_rgba.read_unaligned() };
    let (use_num_rects, use_rects, rect0, sanitized) = validate_clear_rects(num_rects, rects);
    static CLEAR_RTV_CALLS: AtomicU32 = AtomicU32::new(0);
    let call_idx = CLEAR_RTV_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    let masked = (CLEAR_RTV_MASK.skip_3 && call_idx == 3)
        || (CLEAR_RTV_MASK.skip_4 && call_idx == 4)
        || (CLEAR_RTV_MASK.skip_after_2 && call_idx > 2);
    let rect_str = match rect0 {
        Some([l, t, r, b]) => format!("[{l},{t},{r},{b}]"),
        None => String::from("none"),
    };
    let san_tag = if sanitized { " sanitized_rects" } else { "" };
    let mask_tag = if masked { " masked" } else { "" };
    let msg = format!(
        "call=#{call_idx} rtv={pc_rtv:#x} res={res_key:#x} rgba=[{:.3},{:.3},{:.3},{:.3}] nrects={num_rects} rect0={rect_str}{san_tag}{mask_tag}",
        rgba[0], rgba[1], rgba[2], rgba[3]
    );
    trace_list_gpu_op(real, "ClearRTV", &msg);
    if sanitized {
        static SAN_LOGS: AtomicU32 = AtomicU32::new(0);
        if SAN_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
            boot_trace("dx12xs_pc", "ListX::ClearRTV_sanitized_rects", &msg);
        }
    }
    if masked {
        static MASK_LOGS: AtomicU32 = AtomicU32::new(0);
        if MASK_LOGS.fetch_add(1, Ordering::Relaxed) < 32 {
            boot_trace("dx12xs_pc", "ListX::ClearRTV_masked", &msg);
        }
        return;
    }
    if DIAG_SKIP.clear_rtv {
        return;
    }
    record_list_op(this, "ClearRTV", pc_rtv, res_key as u64);
    type FnTy = unsafe extern "system" fn(*mut c_void, u64, *const [f32; 4], u32, *const c_void);
    unsafe { com_slot::<FnTy>(real, 48)(real, pc_rtv, &rgba, use_num_rects, use_rects) };
}
extern "system" fn list_trace_noop<const SLOT: usize>(_this: *mut ListX) {
    static NOOP_LOGS: AtomicU32 = AtomicU32::new(0);
    if NOOP_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
        boot_trace("dx12xs_pc", "ListX::noop_slot", &format!("slot={SLOT}"));
    }
}
extern "system" fn list_noop_hr(_this: *mut ListX) -> HRESULT {
    S_OK
}
extern "system" fn list_trace_write_wait<const TAG: u8>(
    _this: *mut ListX,
    a1: u64,
    a2: u64,
    a3: u64,
) {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
    static OP_LOGS: [AtomicU32; 4] = [
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
    ];
    let idx = usize::from(TAG.min(3));
    let n = OP_LOGS[idx].fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 {
        let name = match TAG {
            0 => "Write32",
            1 => "Write64",
            2 => "Wait32",
            _ => "Wait64",
        };
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let vq = unsafe { VirtualQuery(a1 as *const c_void, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
        let vq_info = if vq != 0 {
            format!("vq_state={:#x} vq_prot={:#x} vq_ty={:#x}", mbi.State, mbi.Protect, mbi.Type)
        } else {
            String::from("vq=0")
        };
        boot_trace(
            "dx12xs_pc",
            "ListX::mem_sync",
            &format!("#{n} op={name} va={a1:#x} val={a2:#x} flags_or_cmp={a3:#x} {vq_info}"),
        );
    }
}
extern "system" fn list_alloc_upload(this: *mut ListX, size: u64, align: u64) -> *mut c_void {
    if this.is_null() {
        return std::ptr::null_mut();
    }
    let align_usize = usize::try_from(align).unwrap_or(0).max(16);
    if !align_usize.is_power_of_two() || size > 64 * 1024 * 1024 {
        return std::ptr::null_mut();
    }
    let bytes = usize::try_from(size.max(16)).unwrap_or(16);
    let Ok(layout) = Layout::from_size_align(bytes, align_usize) else {
        return std::ptr::null_mut();
    };
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { &*this }
        .uploads
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((ptr as usize, layout));
    static LOGS: AtomicU32 = AtomicU32::new(0);
    let n = LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 {
        boot_trace(
            "dx12xs_pc",
            "ListX::AllocateUpload",
            &format!("#{n} size={size} align={align_usize} ptr={ptr:?}"),
        );
    }
    ptr.cast()
}

const fn build_list_table(newer: bool) -> [*const c_void; 160] {
    let mut t = fill_missing::<KIND_LIST, 160>();
    t[0] = list_qi as *const c_void;
    t[1] = list_add_ref as *const c_void;
    t[2] = list_release as *const c_void;
    t[7] = list_get_device as *const c_void;
    t[8] = list_get_type as *const c_void;
    t[9] = list_close as *const c_void;
    t[10] = list_reset as *const c_void;
    t[11] = list_clear_state as *const c_void;
    t[12] = list_draw_instanced as *const c_void;
    t[13] = list_draw_indexed as *const c_void;
    t[14] = list_dispatch as *const c_void;
    t[15] = list_copy_buffer_region as *const c_void;
    t[16] = list_copy_texture_region as *const c_void;
    t[17] = list_copy_resource as *const c_void;
    t[18] = list_trace_noop::<18> as *const c_void;
    t[19] = list_resolve_subresource as *const c_void;
    t[20] = list_ia_set_topology as *const c_void;
    t[21] = list_rs_set_viewports as *const c_void;
    t[22] = list_rs_set_scissors as *const c_void;
    t[23] = list_om_set_blend_factor as *const c_void;
    t[24] = list_om_set_stencil_ref as *const c_void;
    t[25] = list_set_pso as *const c_void;
    t[26] = list_resource_barrier as *const c_void;
    t[27] = list_trace_noop::<27> as *const c_void;
    t[28] = list_begin_query as *const c_void;
    t[29] = list_end_query as *const c_void;
    t[30] = list_resolve_query_data as *const c_void;
    t[31] = list_trace_noop::<31> as *const c_void;
    t[32] = list_set_descriptor_heaps as *const c_void;
    t[33] = list_set_compute_root_sig as *const c_void;
    t[34] = list_set_graphics_root_sig as *const c_void;
    t[35] = list_set_compute_root_table as *const c_void;
    t[36] = list_set_graphics_root_table as *const c_void;
    t[37] = list_set_compute_root_const as *const c_void;
    t[38] = list_set_graphics_root_const as *const c_void;
    t[39] = list_set_compute_root_consts as *const c_void;
    t[40] = list_set_graphics_root_consts as *const c_void;
    t[41] = list_set_compute_root_cbv as *const c_void;
    t[42] = list_set_graphics_root_cbv as *const c_void;
    t[43] = list_set_compute_root_srv as *const c_void;
    t[44] = list_set_graphics_root_srv as *const c_void;
    t[45] = list_set_compute_root_uav as *const c_void;
    t[46] = list_set_graphics_root_uav as *const c_void;
    t[47] = list_ia_set_index_buffer as *const c_void;
    t[48] = list_ia_set_vertex_buffers as *const c_void;
    t[49] = list_trace_noop::<49> as *const c_void;
    t[50] = list_om_set_render_targets as *const c_void;
    t[51] = list_clear_dsv as *const c_void;
    t[52] = list_clear_rtv as *const c_void;
    t[53] = list_trace_noop::<53> as *const c_void;
    t[54] = list_trace_noop::<54> as *const c_void;
    t[56] = list_trace_noop::<56> as *const c_void;
    t[57] = list_trace_noop::<57> as *const c_void;
    t[58] = list_trace_noop::<58> as *const c_void;
    let shift = if newer { 2 } else { 0 };
    t[59 + shift] = list_execute_indirect as *const c_void;    // ExecuteIndirect
    t[60 + shift] = list_trace_noop::<60> as *const c_void;    // CopyMemory
    t[68 + shift] = list_trace_noop::<68> as *const c_void;    // DepthBounds
    t[69 + shift] = list_trace_write_wait::<0> as *const c_void; // Write32
    t[70 + shift] = list_trace_write_wait::<1> as *const c_void; // Write64
    t[71 + shift] = list_trace_write_wait::<2> as *const c_void; // Wait32
    t[72 + shift] = list_trace_write_wait::<3> as *const c_void; // Wait64
    t[73 + shift] = list_trace_noop::<73> as *const c_void;    // PixelShaderDepthOrder (0x258 on newer)
    t[78 + shift] = list_trace_noop::<78> as *const c_void;    // DispatchX
    t[83 + shift] = list_trace_noop::<83> as *const c_void;    // CopyTextureRegionX
    t[84 + shift] = list_trace_noop::<84> as *const c_void;    // CopyResourceX
    t[98 + shift] = list_trace_noop::<98> as *const c_void;    // DispatchMeshX
    t[99 + shift] = list_trace_noop::<99> as *const c_void;    // DriverHint
    t[124 + shift] = list_trace_noop::<124> as *const c_void;  // ShadingRate (0x3f0 on newer)
    t[127 + shift] = list_trace_noop::<127> as *const c_void;  // DispatchMesh
    t[129 + shift] = list_trace_noop::<129> as *const c_void;  // PipelineSync top (0x418)
    t[130 + shift] = list_trace_noop::<130> as *const c_void;  // PipelineSync bottom (0x420)
    t[137 + shift] = list_reset_x as *const c_void; // ResetX (0x458)
    if newer {
        t[142] = list_noop_hr as *const c_void;    // 0x470
        t[146] = list_trace_noop::<146> as *const c_void;      // 0x490 Enhanced Barrier
        t[148] = list_alloc_upload as *const c_void; // 0x4a0 AllocateUpload
    }
    t
}

static LIST_VTABLE: Table<160> = Table(build_list_table(false));
static NEWER_LIST_VTABLE: Table<160> = Table(build_list_table(true));

// ============================================================================
// DXGI Proxy (`IDXGIDevice` -> `IDXGIAdapter` -> `IDXGIFactory` / `IDXGIOutput`)
// ============================================================================

#[repr(C)]
struct DxgiDeviceProxy {
    vtable: *const *const c_void,
    refs: AtomicU32,
    parent_dev: *mut DeviceX,
}
#[repr(C)]
struct DxgiAdapterProxy {
    vtable: *const *const c_void,
    refs: AtomicU32,
    parent_dev: *mut DeviceX,
}
#[repr(C)]
struct DxgiFactoryProxy {
    vtable: *const *const c_void,
    refs: AtomicU32,
    parent_dev: *mut DeviceX,
}
#[repr(C)]
struct DxgiOutputProxy {
    vtable: *const *const c_void,
    refs: AtomicU32,
    parent_dev: *mut DeviceX,
}

#[repr(C)]
struct DxgiAdapterDesc {
    description: [u16; 128],
    vendor_id: u32,
    device_id: u32,
    subsys_id: u32,
    revision: u32,
    dedicated_video_memory: usize,
    dedicated_system_memory: usize,
    shared_system_memory: usize,
    adapter_luid: [u32; 2],
}

static DXGI_MODULE: OnceLock<usize> = OnceLock::new();
fn host_dxgi() -> HMODULE {
    let addr = *DXGI_MODULE.get_or_init(|| {
        let name: Vec<u16> = "dxgi.dll\0".encode_utf16().collect();
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

extern "system" fn dxgi_dev_qi(this: *mut DxgiDeviceProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let p = unsafe { &*this };
    if is_device_iid(iid) {
        return dev_query_interface(p.parent_dev, iid, out);
    }
    if is_guid_in(iid, &DXGI_DEVICE_IIDS) {
        dxgi_dev_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dxgi_dev_add_ref(this: *mut DxgiDeviceProxy) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn dxgi_dev_release(this: *mut DxgiDeviceProxy) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn dxgi_dev_get_parent(this: *mut DxgiDeviceProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DXGI_ADAPTER_IIDS) {
        let p = unsafe { &*this };
        dev_add_ref(p.parent_dev);
        let adp = Box::new(DxgiAdapterProxy {
            vtable: DXGI_ADAPTER_VTABLE.0.as_ptr(),
            refs: AtomicU32::new(1),
            parent_dev: p.parent_dev,
        });
        unsafe { *out = Box::into_raw(adp).cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dxgi_dev_get_adapter(this: *mut DxgiDeviceProxy, out: *mut *mut c_void) -> HRESULT {
    dxgi_dev_get_parent(this, &DXGI_ADAPTER_IIDS[0], out)
}

static DXGI_DEVICE_VTABLE: Table<16> = {
    let mut t = fill_missing::<KIND_DXGI, 16>();
    t[0] = dxgi_dev_qi as *const c_void;
    t[1] = dxgi_dev_add_ref as *const c_void;
    t[2] = dxgi_dev_release as *const c_void;
    t[6] = dxgi_dev_get_parent as *const c_void;
    t[7] = dxgi_dev_get_adapter as *const c_void;
    Table(t)
};

extern "system" fn dxgi_adp_qi(this: *mut DxgiAdapterProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DXGI_ADAPTER_IIDS) {
        dxgi_adp_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dxgi_adp_add_ref(this: *mut DxgiAdapterProxy) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn dxgi_adp_release(this: *mut DxgiAdapterProxy) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn dxgi_adp_get_parent(this: *mut DxgiAdapterProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DXGI_FACTORY_IIDS) {
        let p = unsafe { &*this };
        dev_add_ref(p.parent_dev);
        let fac = Box::new(DxgiFactoryProxy {
            vtable: DXGI_FACTORY_VTABLE.0.as_ptr(),
            refs: AtomicU32::new(1),
            parent_dev: p.parent_dev,
        });
        unsafe { *out = Box::into_raw(fac).cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dxgi_adp_enum_outputs(
    this: *mut DxgiAdapterProxy,
    index: u32,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if index != 0 {
        unsafe { *out = std::ptr::null_mut() };
        return DXGI_ERROR_NOT_FOUND;
    }
    let p = unsafe { &*this };
    dev_add_ref(p.parent_dev);
    let obj = Box::new(DxgiOutputProxy {
        vtable: DXGI_OUTPUT_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
        parent_dev: p.parent_dev,
    });
    unsafe { *out = Box::into_raw(obj).cast() };
    S_OK
}
extern "system" fn dxgi_adp_get_desc(_this: *mut DxgiAdapterProxy, out: *mut DxgiAdapterDesc) -> HRESULT {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let mut desc = DxgiAdapterDesc {
        description: [0; 128],
        vendor_id: 0x10DE,
        device_id: 0x2484,
        subsys_id: 0,
        revision: 0,
        dedicated_video_memory: 8 * 1024 * 1024 * 1024,
        dedicated_system_memory: 0,
        shared_system_memory: 8 * 1024 * 1024 * 1024,
        adapter_luid: [1, 0],
    };
    let name: Vec<u16> = "NVIDIA GeForce RTX 3070\0".encode_utf16().collect();
    desc.description[..name.len()].copy_from_slice(&name);

    let dxgi = host_dxgi();
    if !dxgi.is_null() {
        if let Some(create_fac) = unsafe { GetProcAddress(dxgi, c"CreateDXGIFactory1".as_ptr().cast()) } {
            type CreateFacFn = unsafe extern "system" fn(*const Guid, *mut *mut c_void) -> HRESULT;
            let f: CreateFacFn = unsafe { std::mem::transmute(create_fac) };
            let mut fac: *mut c_void = std::ptr::null_mut();
            if unsafe { f(&DXGI_FACTORY_IIDS[1], &mut fac) } >= 0 && !fac.is_null() {
                type EnumFn = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> HRESULT;
                let mut adp: *mut c_void = std::ptr::null_mut();
                if unsafe { com_slot::<EnumFn>(fac, 7)(fac, 0, &mut adp) } >= 0 && !adp.is_null() {
                    type DescFn = unsafe extern "system" fn(*mut c_void, *mut DxgiAdapterDesc) -> HRESULT;
                    let _ = unsafe { com_slot::<DescFn>(adp, 8)(adp, &mut desc) };
                    unsafe { real_release(adp) };
                }
                unsafe { real_release(fac) };
            }
        }
    }
    unsafe { out.write(desc) };
    S_OK
}
extern "system" fn dxgi_adp_check_iface(
    _this: *mut DxgiAdapterProxy,
    _guid: *const Guid,
    _umd: *mut i64,
) -> HRESULT {
    DXGI_ERROR_UNSUPPORTED
}

static DXGI_ADAPTER_VTABLE: Table<16> = {
    let mut t = fill_missing::<KIND_DXGI, 16>();
    t[0] = dxgi_adp_qi as *const c_void;
    t[1] = dxgi_adp_add_ref as *const c_void;
    t[2] = dxgi_adp_release as *const c_void;
    t[6] = dxgi_adp_get_parent as *const c_void;
    t[7] = dxgi_adp_enum_outputs as *const c_void;
    t[8] = dxgi_adp_get_desc as *const c_void;
    t[9] = dxgi_adp_check_iface as *const c_void;
    Table(t)
};

extern "system" fn dxgi_fac_qi(this: *mut DxgiFactoryProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DXGI_FACTORY_IIDS) {
        dxgi_fac_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dxgi_fac_add_ref(this: *mut DxgiFactoryProxy) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn dxgi_fac_release(this: *mut DxgiFactoryProxy) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn dxgi_fac_enum_adapters(
    this: *mut DxgiFactoryProxy,
    index: u32,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if index != 0 {
        unsafe { *out = std::ptr::null_mut() };
        return DXGI_ERROR_NOT_FOUND;
    }
    let p = unsafe { &*this };
    dev_add_ref(p.parent_dev);
    let adp = Box::new(DxgiAdapterProxy {
        vtable: DXGI_ADAPTER_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
        parent_dev: p.parent_dev,
    });
    unsafe { *out = Box::into_raw(adp).cast() };
    S_OK
}
extern "system" fn dxgi_fac_make_window_assoc(_this: *mut DxgiFactoryProxy, hwnd: *mut c_void, flags: u32) -> HRESULT {
    boot_trace(
        "dx12xs_pc",
        "DxgiFactory::MakeWindowAssociation",
        &format!("hwnd={hwnd:?} flags={flags:#x}"),
    );
    if !hwnd.is_null() && shim_common::telemetry::target_hwnd() == 0 {
        shim_common::telemetry::set_target_hwnd(hwnd as usize);
    }
    crate::overlay::ensure_started();
    S_OK
}

static DXGI_FACTORY_VTABLE: Table<20> = {
    let mut t = fill_missing::<KIND_DXGI, 20>();
    t[0] = dxgi_fac_qi as *const c_void;
    t[1] = dxgi_fac_add_ref as *const c_void;
    t[2] = dxgi_fac_release as *const c_void;
    t[7] = dxgi_fac_enum_adapters as *const c_void;
    t[8] = dxgi_fac_make_window_assoc as *const c_void;
    t[12] = dxgi_fac_enum_adapters as *const c_void;
    Table(t)
};

extern "system" fn dxgi_out_qi(this: *mut DxgiOutputProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DXGI_OUTPUT_IIDS) {
        dxgi_out_add_ref(this);
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn dxgi_out_add_ref(this: *mut DxgiOutputProxy) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}
extern "system" fn dxgi_out_release(this: *mut DxgiOutputProxy) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let b = unsafe { Box::from_raw(this) };
        dev_release(b.parent_dev);
    }
    left
}
extern "system" fn dxgi_out_get_parent(this: *mut DxgiOutputProxy, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if is_guid_in(iid, &DXGI_ADAPTER_IIDS) {
        let p = unsafe { &*this };
        dev_add_ref(p.parent_dev);
        let adp = Box::new(DxgiAdapterProxy {
            vtable: DXGI_ADAPTER_VTABLE.0.as_ptr(),
            refs: AtomicU32::new(1),
            parent_dev: p.parent_dev,
        });
        unsafe { *out = Box::into_raw(adp).cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}

#[repr(C)]
struct DxgiModeDesc {
    width: u32,
    height: u32,
    refresh_num: u32,
    refresh_den: u32,
    format: u32,
    scanline_ordering: u32,
    scaling: u32,
    flags: u32,
}
const _: () = assert!(size_of::<DxgiModeDesc>() == 32);

#[repr(C)]
struct DxgiOutputDesc {
    device_name: [u16; 32],
    desktop_left: i32,
    desktop_top: i32,
    desktop_right: i32,
    desktop_bottom: i32,
    attached_to_desktop: i32,
    rotation: u32,
    monitor: isize,
}

extern "system" fn dxgi_out_get_desc(_this: *mut DxgiOutputProxy, out: *mut DxgiOutputDesc) -> HRESULT {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let (w, h) = shim_common::telemetry::configured_resolution();
    let mut name = [0u16; 32];
    for (dst, src) in name.iter_mut().zip(r"\\.\DISPLAY1".encode_utf16()) {
        *dst = src;
    }
    unsafe {
        out.write(DxgiOutputDesc {
            device_name: name,
            desktop_left: 0,
            desktop_top: 0,
            desktop_right: w as i32,
            desktop_bottom: h as i32,
            attached_to_desktop: 1,
            rotation: 1, // DXGI_MODE_ROTATION_IDENTITY
            monitor: 1,
        });
    }
    S_OK
}

extern "system" fn dxgi_out_get_modes(
    _this: *mut DxgiOutputProxy,
    format: u32,
    _flags: u32,
    count: *mut u32,
    out: *mut DxgiModeDesc,
) -> HRESULT {
    if count.is_null() {
        return E_INVALIDARG;
    }
    if out.is_null() {
        unsafe { *count = 1 };
        return S_OK;
    }
    if unsafe { *count } < 1 {
        unsafe { *count = 1 };
        return DXGI_ERROR_MORE_DATA;
    }
    let (w, h) = shim_common::telemetry::configured_resolution();
    unsafe {
        *count = 1;
        out.write(DxgiModeDesc {
            width: w,
            height: h,
            refresh_num: 60,
            refresh_den: 1,
            format,
            scanline_ordering: 1,
            scaling: 0,
            flags: 0,
        });
    }
    S_OK
}

static DXGI_OUTPUT_VTABLE: Table<32> = {
    let mut t = fill_missing::<KIND_DXGI, 32>();
    t[0] = dxgi_out_qi as *const c_void;
    t[1] = dxgi_out_add_ref as *const c_void;
    t[2] = dxgi_out_release as *const c_void;
    t[6] = dxgi_out_get_parent as *const c_void;
    t[7] = dxgi_out_get_desc as *const c_void;
    t[8] = dxgi_out_get_modes as *const c_void;
    t[21] = dxgi_out_get_modes as *const c_void; // Xbox GetDisplayModeList @ 0xa8
    Table(t)
};

#[cfg(test)]
mod display_pool_tests {
    use super::*;

    #[test]
    fn xbox_display_bytes_satisfy_series_x_and_series_s_pool_slack_bounds() {
        let mk = |w: u64, h: u32| ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: w,
            height: h,
            depth_or_array: 1,
            mip_levels: 1,
            format: 28, // R8G8B8A8_UNORM (4 bpp)
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 1,
        };
        let uhd = compute_xbox_display_bytes(&mk(3840, 2160));
        let fhd = compute_xbox_display_bytes(&mk(1920, 1080));
        assert_eq!(uhd, 0x1FF_0000);
        assert_eq!(fhd, 0x83_0000);

        let sx_pool = 0x0400_0000usize;
        let sx_used = 2 * uhd;
        assert!(sx_used <= sx_pool && (sx_pool - sx_used) <= 0x1F_FFFF);

        let ss_pool = 0x0520_0000usize;
        let ss_used = 2 * uhd + 2 * fhd;
        assert!(ss_used <= ss_pool && (ss_pool - ss_used) <= 0x1F_FFFF);
    }

    #[test]
    fn shader_visible_cbv_srv_uav_heap_over_1m_clamps_and_translates() {
        shim_common::telemetry::use_temp_telemetry_json_for_tests();
        let params = crate::D3D12XboxCreateDeviceParams {
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
        assert_eq!(
            crate::D3D12XboxCreateDevice(
                std::ptr::null_mut(),
                &params,
                &IID_ID3D12DEVICE11,
                &mut dev
            ),
            S_OK
        );

        #[repr(C)]
        struct PlacedDesc {
            desc: DescriptorHeapDesc,
            placement: HeapPlacement,
        }
        let num = 1_245_184u32;
        let mut backing = vec![0u8; 4096];
        let pdesc = PlacedDesc {
            desc: DescriptorHeapDesc {
                ty: 0,
                num_descriptors: num,
                flags: 1, // SHADER_VISIBLE
                node_mask: 0,
            },
            placement: HeapPlacement {
                address: backing.as_mut_ptr() as u64,
                size: u64::from(num) * 32,
            },
        };
        let mut heap_obj: *mut c_void = std::ptr::null_mut();
        let hr = dev_create_descriptor_heap(
            dev.cast(),
            (&raw const pdesc).cast(),
            &DESC_HEAP_IIDS[0],
            &mut heap_obj,
        );
        assert_eq!(hr, S_OK);
        assert!(!heap_obj.is_null());
        let h_ref = unsafe { &*heap_obj.cast::<DescriptorHeapX>() };
        assert!(!h_ref.real_heap.is_null(), "1.24M heap must clamp to 1M on Win32");

        // Index 0 and clamped index >= 1,000,000 both translate cleanly into real_heap range.
        let pc_0 = translate_cpu_handle_for_ty(h_ref.cpu_start, Some(0)).expect("index 0 must translate");
        let pc_over = translate_cpu_handle_for_ty(h_ref.cpu_start + 1_100_000 * 32, Some(0))
            .expect("clamped index must translate");
        assert!(pc_over > pc_0);

        // Verify GetDescriptorHandleIncrementSize(ty=4) returns 0 cleanly without host error,
        // and CreateConstantBufferView with unaligned size 128 + raw Xbox VA falls back cleanly.
        assert_eq!(dev_get_desc_inc_size(dev.cast(), 4), 0);
        let fake_cbv = CbvDescRaw {
            buffer_location: 0x9_48a0_1b00,
            size_in_bytes: 128,
            _pad: 0,
        };
        dev_create_cbv(dev.cast(), (&raw const fake_cbv).cast(), h_ref.cpu_start);
        let d_ref = unsafe { &*dev.cast::<DeviceX>() };
        assert_eq!(query_real_removed_reason(d_ref.real_device), S_OK);

        // Verify AllocatorX slot 9, ListX::SetDescriptorHeaps (slot 32), Close (slot 9),
        // and ResetX (slot 139 on ID3D12Device11) reopen the real D3D12 command list cleanly.
        let mut alloc_obj: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            dev_create_command_allocator(dev.cast(), 0, &ALLOCATOR_IIDS[0], &mut alloc_obj),
            S_OK
        );
        assert_eq!(
            alloc_noop_hr(alloc_obj.cast()),
            S_OK,
            "AllocatorX slot 9 must succeed"
        );
        let mut list_obj: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            dev_create_command_list(
                dev.cast(),
                0,
                0,
                alloc_obj.cast(),
                std::ptr::null_mut(),
                &LIST_IIDS[0],
                &mut list_obj
            ),
            S_OK
        );
        let mut heap_ptr = h_ref as *const DescriptorHeapX as *mut DescriptorHeapX;
        list_set_descriptor_heaps(list_obj.cast(), 1, &raw mut heap_ptr);
        assert_eq!(list_close(list_obj.cast()), S_OK, "first ListX::Close must succeed");
        let l_vtbl = unsafe { *list_obj.cast::<*const *const c_void>() };
        type ResetXFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void, u32) -> HRESULT;
        let reset_x: ResetXFn = unsafe { std::mem::transmute(*l_vtbl.add(139)) };
        assert_eq!(
            unsafe { reset_x(list_obj, alloc_obj, std::ptr::null_mut(), 0) },
            S_OK,
            "ListX::ResetX must reopen real command list"
        );
        assert_eq!(
            list_close(list_obj.cast()),
            S_OK,
            "second ListX::Close after ResetX must succeed (not E_FAIL)"
        );
        // Verify closing an already-closed list and recording while closed are safely ignored.
        assert_eq!(list_close(list_obj.cast()), S_OK);
        list_draw_instanced(list_obj.cast(), 3, 1, 0, 0);

        // Verify GetResourceAllocationInfo2 handles 72-byte ResourceDesc1 stride and populates each1,
        // and GetResourceAllocationInfo never returns u64::MAX even for an invalid format/dimension.
        let desc1s = [
            ResourceDesc1Raw {
                desc: ResourceDescRaw {
                    dimension: 3, // TEXTURE2D
                    alignment: 0,
                    width: 128,
                    height: 128,
                    depth_or_array: 1,
                    mip_levels: 1,
                    format: 28, // R8G8B8A8_UNORM
                    sample_count: 1,
                    sample_quality: 0,
                    layout: 0,
                    flags: 1, // ALLOW_RENDER_TARGET
                },
                mip_region: [0; 3],
                _pad: 0,
            },
            ResourceDesc1Raw {
                desc: ResourceDescRaw {
                    dimension: 1, // BUFFER
                    alignment: 0,
                    width: 4096,
                    height: 1,
                    depth_or_array: 1,
                    mip_levels: 1,
                    format: 0,
                    sample_count: 1,
                    sample_quality: 0,
                    layout: 1,
                    flags: 0,
                },
                mip_region: [0; 3],
                _pad: 0,
            },
        ];
        let mut total_info = [0u64; 2];
        let mut each_info = [AllocationInfo1Raw { offset: 0, alignment: 0, size: 0 }; 2];
        dev_get_alloc_info2(&mut total_info, dev.cast(), 1, 2, desc1s.as_ptr(), each_info.as_mut_ptr());
        assert_ne!(total_info[0], u64::MAX);
        assert!(total_info[0] >= 65536 + 4096);
        assert_eq!(each_info[0].offset, 0);
        assert!(each_info[1].offset >= each_info[0].size);
        assert_eq!(each_info[1].size, 4096);
        assert_eq!(each_info[1].alignment, 256);

        let fallback_rs = get_dxpk_fallback_root_sig(d_ref);
        assert!(!fallback_rs.is_null(), "DXPK fallback root signature must create cleanly");

        // Verify CBV_SRV_UAV handle cannot match RTV translation (#646).
        assert!(
            translate_cpu_handle_for_ty(h_ref.cpu_start, Some(2)).is_none(),
            "CBV_SRV_UAV heap handle must not translate as RTV"
        );
        assert!(translate_cpu_handle_for_ty(h_ref.cpu_start, Some(0)).is_some());

        // Verify fmt=86 (B5G5R5A1_UNORM) strips ALLOW_UNORDERED_ACCESS (#599).
        let fmt86 = sanitize_resource_desc(&ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 64,
            height: 64,
            depth_or_array: 1,
            mip_levels: 1,
            format: 86,
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 0x30_0005,
        });
        assert_eq!(fmt86.flags, 0x1, "ALLOW_UNORDERED_ACCESS must be stripped for B5G5R5A1_UNORM");

        // Verify DEFAULT heap resource Map/Unmap returns a CPU shadow buffer cleanly (#822).
        let mut default_res: *mut c_void = std::ptr::null_mut();
        let default_props = [1u32, 0, 0, 0, 0];
        let tex_desc = ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 64,
            height: 64,
            depth_or_array: 1,
            mip_levels: 1,
            format: 86,
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 0x30_0005,
        };
        assert_eq!(
            dev_create_committed_resource(
                dev.cast(),
                &default_props,
                0,
                &tex_desc,
                0,
                std::ptr::null(),
                &RESOURCE_IIDS[0],
                &mut default_res,
            ),
            S_OK
        );
        let mut mapped_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(res_map(default_res.cast(), 0, std::ptr::null(), &mut mapped_ptr), S_OK);
        assert!(!mapped_ptr.is_null(), "DEFAULT heap Map must return shadow CPU pointer");
        unsafe { mapped_ptr.cast::<u32>().write(0x1234_5678) };
        res_unmap(default_res.cast(), 0, std::ptr::null());
        unsafe {
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let r_vtbl = *default_res.cast::<*const *const c_void>();
            let r_rel: RelFn = std::mem::transmute(*r_vtbl.add(2));
            r_rel(default_res);
        }

        // Verify newer ListX slots 75 (0x258) & 126 (0x3f0) are wired as clean no-ops and
        // AllocateUpload (slot 148) returns 0x100-aligned writable memory freed on ResetX.
        type NoopSlotFn = unsafe extern "system" fn(*mut c_void, u64);
        let slot75: NoopSlotFn = unsafe { std::mem::transmute(*l_vtbl.add(75)) };
        let slot126: NoopSlotFn = unsafe { std::mem::transmute(*l_vtbl.add(126)) };
        unsafe {
            slot75(list_obj, 0);
            slot126(list_obj, 0);
        }
        let up_ptr = list_alloc_upload(list_obj.cast(), 64, 0x100);
        assert!(!up_ptr.is_null() && (up_ptr as usize).is_multiple_of(0x100));
        unsafe { up_ptr.cast::<u8>().write_bytes(0xAB, 64) };
        assert_eq!(unsafe { reset_x(list_obj, alloc_obj, std::ptr::null_mut(), 0) }, S_OK);
        assert!(
            unsafe { &(*list_obj.cast::<ListX>()).uploads }
                .lock()
                .unwrap()
                .is_empty()
        );

        // Verify DeviceX::GetFrameStatisticsX (slot 81) takes 5 args (token=1, kinds=0, &mut count, null).
        unsafe {
            let d_vtbl = *dev.cast::<*const *const c_void>();
            type FrameStatsFn = unsafe extern "system" fn(*mut c_void, u64, u32, *mut u32, *mut u8) -> HRESULT;
            let get_stats: FrameStatsFn = std::mem::transmute(*d_vtbl.add(81));
            let mut stats_count = 99u32;
            assert_eq!(get_stats(dev, 1, 0, &mut stats_count, std::ptr::null_mut()), S_OK);
            assert_eq!(stats_count, 0);
        }

        // Verify QueueX::Signal does NOT advance FenceX::GetCompletedValue ahead of real GPU fence completion.
        let mut q_obj: *mut c_void = std::ptr::null_mut();
        let q_desc = PcQueueDesc { ty: 0, priority: 0, flags: 0, node_mask: 0 };
        assert_eq!(dev_create_command_queue(dev.cast(), &q_desc, &QUEUE_IIDS[0], &mut q_obj), S_OK);
        let mut gate_fence: *mut c_void = std::ptr::null_mut();
        let mut target_fence: *mut c_void = std::ptr::null_mut();
        assert_eq!(dev_create_fence(dev.cast(), 0, 0, &FENCE_IIDS[0], &mut gate_fence), S_OK);
        assert_eq!(dev_create_fence(dev.cast(), 0, 0, &FENCE_IIDS[0], &mut target_fence), S_OK);
        assert_eq!(queue_wait(q_obj.cast(), gate_fence.cast(), 1), S_OK);
        assert_eq!(queue_signal(q_obj.cast(), target_fence.cast(), 42), S_OK);
        assert_eq!(
            fence_get_completed(target_fence.cast()),
            0,
            "queue_signal must not report GPU fence completed while GPU is blocked on gate_fence"
        );
        assert_eq!(fence_signal(gate_fence.cast(), 1), S_OK);
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
            let ev = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
            assert!(!ev.is_null());
            assert_eq!(fence_set_event(target_fence.cast(), 42, ev), S_OK);
            assert_eq!(WaitForSingleObject(ev, 5000), 0);
            CloseHandle(ev);
        }
        assert_eq!(fence_get_completed(target_fence.cast()), 42);

        // Also verify QueueX::Signal BEFORE GetGpuVirtualAddress still syncs *gpu_va cleanly!
        let mut late_va_fence: *mut c_void = std::ptr::null_mut();
        assert_eq!(dev_create_fence(dev.cast(), 0, 0, &FENCE_IIDS[0], &mut late_va_fence), S_OK);
        assert_eq!(queue_signal(q_obj.cast(), late_va_fence.cast(), 7), S_OK);
        let gpu_va_ptr = fence_gpu_va(late_va_fence.cast()) as *const AtomicU64;
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { &*gpu_va_ptr }.load(Ordering::Acquire) < 7 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(unsafe { &*gpu_va_ptr }.load(Ordering::Acquire), 7);
        fence_release(late_va_fence.cast());

        // Verify IASetIndexBuffer accepts va=0 with non-zero size/fmt cleanly (normalized to {0, 0})
        // on an open command list without causing device removal or crash.
        let bad_null_ib = [0u64, (42u64 << 32) | 128u64];
        list_ia_set_index_buffer(list_obj.cast(), &bad_null_ib);
        list_ia_set_index_buffer(list_obj.cast(), std::ptr::null());
        unsafe {
            type CloseFn = unsafe extern "system" fn(*mut c_void) -> HRESULT;
            let l_close: CloseFn = std::mem::transmute(*l_vtbl.add(9));
            assert_eq!(l_close(list_obj), S_OK);
        }

        fence_release(target_fence.cast());
        fence_release(gate_fence.cast());
        queue_release(q_obj.cast());

        unsafe {
            type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let l_rel: RelFn = std::mem::transmute(*l_vtbl.add(2));
            l_rel(list_obj);
            let a_vtbl = *alloc_obj.cast::<*const *const c_void>();
            let a_rel: RelFn = std::mem::transmute(*a_vtbl.add(2));
            a_rel(alloc_obj);
            let h_vtbl = *heap_obj.cast::<*const *const c_void>();
            let h_rel: RelFn = std::mem::transmute(*h_vtbl.add(2));
            h_rel(heap_obj);
            let d_vtbl = *dev.cast::<*const *const c_void>();
            let d_rel: RelFn = std::mem::transmute(*d_vtbl.add(2));
            d_rel(dev);
        }
    }

    #[test]
    fn diag_skip_flags_parse_all_and_subset() {
        let none = DiagSkipFlags::parse("");
        assert!(!none.clear_rtv && !none.bind_b0 && !none.om_rt && !none.ia && !none.rs_vp && !none.heaps && !none.barriers);
        let sub = DiagSkipFlags::parse(" clear_rtv , ia , barriers ");
        assert!(sub.clear_rtv && !sub.bind_b0 && !sub.om_rt && sub.ia && !sub.rs_vp && !sub.heaps && sub.barriers);
        let all = DiagSkipFlags::parse("ALL");
        assert!(all.clear_rtv && all.bind_b0 && all.om_rt && all.ia && all.rs_vp && all.heaps && all.barriers);
    }

    #[test]
    fn validate_clear_rects_sanitizes_invalid_and_keeps_valid() {
        assert_eq!(validate_clear_rects(0, std::ptr::null()), (0, std::ptr::null(), None, false));
        assert_eq!(validate_clear_rects(1, std::ptr::null()), (0, std::ptr::null(), None, true));

        let valid = [[0i32, 0, 1920, 1080]];
        let res_ok = validate_clear_rects(1, valid.as_ptr().cast());
        assert_eq!(res_ok.0, 1);
        assert_eq!(res_ok.2, Some(valid[0]));
        assert!(!res_ok.3);

        let too_many = [[0i32, 0, 64, 64]; 65];
        assert!(validate_clear_rects(65, too_many.as_ptr().cast()).3);

        let bad_neg = [[-1i32, 0, 100, 100]];
        assert_eq!(validate_clear_rects(1, bad_neg.as_ptr().cast()), (0, std::ptr::null(), Some(bad_neg[0]), true));

        let bad_inverted = [[10i32, 0, 10, 100]];
        assert!(validate_clear_rects(1, bad_inverted.as_ptr().cast()).3);

        let bad_huge = [[0i32, 0, 20000, 1080]];
        assert!(validate_clear_rects(1, bad_huge.as_ptr().cast()).3);
    }

    #[test]
    fn clear_rtv_mask_flags_parse_all_tokens() {
        let empty = ClearRtvMaskFlags::parse("");
        assert!(!empty.skip_3 && !empty.skip_4 && !empty.skip_after_2 && !empty.no_present_copy && !empty.no_present_init);
        let all = ClearRtvMaskFlags::parse("skip_3, skip_4, skip_after_2, no_present_copy, no_present_init");
        assert!(all.skip_3 && all.skip_4 && all.skip_after_2 && all.no_present_copy && all.no_present_init);
    }

    #[test]
    fn sanitize_dsv_format_maps_typeless_and_xbox_depth_formats() {
        assert_eq!(sanitize_dsv_format(19), 20);
        assert_eq!(sanitize_dsv_format(39), 40);
        assert_eq!(sanitize_dsv_format(44), 45);
        assert_eq!(sanitize_dsv_format(53), 55);
        assert_eq!(sanitize_dsv_format(54), 55);
        assert_eq!(sanitize_dsv_format(118), 45);
        assert_eq!(sanitize_dsv_format(40), 40);
    }

    #[test]
    fn sanitize_primitive_topology_type_maps_undefined_and_xbox_values() {
        assert_eq!(sanitize_primitive_topology_type(0), 3);
        assert_eq!(sanitize_primitive_topology_type(1), 1);
        assert_eq!(sanitize_primitive_topology_type(2), 2);
        assert_eq!(sanitize_primitive_topology_type(3), 3);
        assert_eq!(sanitize_primitive_topology_type(4), 4);
        assert_eq!(sanitize_primitive_topology_type(5), 3);
        assert_eq!(sanitize_primitive_topology_type(19), 3);
    }

    #[test]
    fn sanitize_primitive_topology_maps_xbox_ranges_to_trianglelist() {
        assert_eq!(sanitize_primitive_topology(17), 4);
        assert_eq!(sanitize_primitive_topology(18), 4);
        assert_eq!(sanitize_primitive_topology(19), 4);
        assert_eq!(sanitize_primitive_topology(0), 4);
        assert_eq!(sanitize_primitive_topology(65), 4);
        assert_eq!(sanitize_primitive_topology(4), 4);
        assert_eq!(sanitize_primitive_topology(5), 5);
        assert_eq!(sanitize_primitive_topology(10), 10);
        assert_eq!(sanitize_primitive_topology(13), 13);
        assert_eq!(sanitize_primitive_topology(33), 33);
        assert_eq!(sanitize_primitive_topology(64), 64);
    }

    #[test]
    fn align_and_wrap_ring_offset_advances_and_wraps_cleanly() {
        let ring = 1024usize;
        assert_eq!(align_and_wrap_ring_offset(0, ring, 256, 256), Some((0, 256)));
        assert_eq!(align_and_wrap_ring_offset(257, ring, 256, 256), Some((512, 768)));
        assert_eq!(align_and_wrap_ring_offset(768, ring, 256, 256), Some((768, 1024)));
        assert_eq!(align_and_wrap_ring_offset(800, ring, 256, 256), Some((0, 256)));
        assert_eq!(align_and_wrap_ring_offset(0, ring, 2048, 16), None);
        assert_eq!(align_and_wrap_ring_offset(0, ring, 0, 16), None);
    }

    #[test]
    fn sanitize_resource_desc_remaps_writable_fmt_67_only() {
        let base = ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 1920,
            height: 1080,
            depth_or_array: 1,
            mip_levels: 1,
            format: 67,
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 0x300005,
        };
        let rw = sanitize_resource_desc(&base);
        assert_eq!(rw.format, 26);
        assert_eq!(rw.flags, 0x5);

        let rt_only = sanitize_resource_desc(&ResourceDescRaw { flags: 0x1, ..base });
        assert_eq!(rt_only.format, 26);

        let uav_only = sanitize_resource_desc(&ResourceDescRaw { flags: 0x4, ..base });
        assert_eq!(uav_only.format, 26);

        let srv_only = sanitize_resource_desc(&ResourceDescRaw { flags: 0, ..base });
        assert_eq!(srv_only.format, 67);

        let mut clear_scratch = [0u32; 5];
        let clear_in = [67u32, 0, 0, 0, 0];
        let clear_ptr = sanitize_clear_value(&rw, clear_in.as_ptr().cast(), &mut clear_scratch);
        assert!(!clear_ptr.is_null());
        assert_eq!(clear_scratch[0], 26);

        assert_eq!(map_rtv_format(67), 26);
        assert_eq!(map_rtv_format(87), 87);
    }

    #[test]
    fn list_recent_ops_ring_wraps_and_formats() {
        let mut ring = ([("", 0, 0); 16], 0usize);
        for i in 0..20u64 {
            push_op_ring(&mut ring, "Op", i, i + 100);
        }
        let s = format_ops_ring(&ring);
        assert!(!s.contains("Op(0x3,"));
        assert!(s.contains("Op(0x4,0x68)"));
        assert!(s.contains("Op(0x13,0x77)"));
    }

    #[test]
    fn resource_allows_pc_uav_rejects_depth_and_accepts_uav_textures() {
        let base = ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 512,
            height: 512,
            depth_or_array: 1,
            mip_levels: 1,
            format: 53,
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 0x80300006,
        };
        assert!(!resource_allows_pc_uav(&base));

        let uav_rt = ResourceDescRaw {
            format: 28,
            flags: 0x5,
            ..base
        };
        assert!(resource_allows_pc_uav(&uav_rt));

        let mut scratch = ViewDesc40([0; 10]);
        let ptr = sanitize_uav_fallback_desc(std::ptr::null(), &mut scratch);
        assert!(!ptr.is_null());
        assert_eq!(scratch.0[0], 42);
        assert_eq!(scratch.0[1], 1);

        let typeless_in = [53u32, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        sanitize_uav_fallback_desc(typeless_in.as_ptr().cast(), &mut scratch);
        assert_eq!(scratch.0[0], 56);
    }

    #[test]
    fn res_gpu_va_returns_writable_shadow_for_committed_texture_256x256_fmt41() {
        let mut desc = ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 256,
            height: 256,
            depth_or_array: 1,
            mip_levels: 1,
            format: 41,
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 0,
        };
        let fp_one = estimate_resource_footprint(&desc)[0];
        desc.mip_levels = 0;
        let fp_full = estimate_resource_footprint(&desc)[0];
        assert_eq!(fp_full, fp_one * 2);

        let mut res = ResourceX {
            vtable: RESOURCE_VTABLE.0.as_ptr(),
            bits: 0,
            refs: AtomicU32::new(1),
            desc,
            xmem_alloc: None,
            gpu_va: 0,
            heap_ty: 1,
            cpu_map_buf: Mutex::new(None),
            parent_dev: std::ptr::null_mut(),
            real_resource: std::ptr::null_mut(),
        };
        let va = res_gpu_va(&raw mut res);
        assert_ne!(va, 0);
        assert_eq!(va & 0xFFFF, 0);
        assert!(resource_shadow_bytes(&desc) >= 0x80000);
        unsafe {
            std::ptr::write_bytes(va as *mut u8, 0xA5, 0x80000);
            assert_eq!(*(va as *const u8), 0xA5);
            assert_eq!(*(va as *const u8).add(0x7FFFF), 0xA5);
        }
        let addr = res.cpu_map_buf.lock().unwrap().take().unwrap();
        assert_eq!(addr, va as usize);
        let freed = unsafe {
            windows_sys::Win32::System::Memory::VirtualFree(
                addr as *mut c_void,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            )
        };
        assert_ne!(freed, 0);
    }

    #[test]
    fn xbox_buffer_alloc_info_uses_256_byte_alignment() {
        let base = ResourceDescRaw {
            dimension: 1,
            alignment: 0,
            width: 256,
            height: 1,
            depth_or_array: 1,
            mip_levels: 1,
            format: 0,
            sample_count: 1,
            sample_quality: 0,
            layout: 1,
            flags: 0,
        };
        assert_eq!(xbox_buffer_alloc_info(&base), [256, 256]);
        assert_eq!(xbox_buffer_alloc_info(&ResourceDescRaw { width: 1000, ..base }), [1024, 256]);
        assert_eq!(
            xbox_buffer_alloc_info(&ResourceDescRaw {
                width: 4096,
                alignment: 4096,
                ..base
            }),
            [4096, 4096]
        );
    }

    #[test]
    fn xbox_texture_alloc_info_matches_console_sizes() {
        let tex = ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 1,
            height: 1,
            depth_or_array: 1,
            mip_levels: 1,
            format: 28,
            sample_count: 4,
            sample_quality: 0,
            layout: 0,
            flags: 1,
        };
        assert_eq!(xbox_texture_alloc_info(&tex), [0x10000, 0x10000]);
        assert_eq!(
            xbox_texture_alloc_info(&ResourceDescRaw {
                width: 1920,
                height: 1080,
                sample_count: 1,
                ..tex
            }),
            [0x7f0000, 0x10000]
        );
        assert_eq!(
            xbox_texture_alloc_info(&ResourceDescRaw {
                width: 1280,
                height: 720,
                format: 10,
                sample_count: 1,
                ..tex
            }),
            [0x710000, 0x10000]
        );
        assert_eq!(
            xbox_texture_alloc_info(&ResourceDescRaw {
                width: 2048,
                height: 2048,
                format: 71,
                sample_count: 1,
                flags: 0,
                ..tex
            }),
            [0x200000, 0x10000]
        );
    }

    #[test]
    fn sanitize_resource_desc_remaps_writable_fmt_115_only() {
        let base = ResourceDescRaw {
            dimension: 3,
            alignment: 0,
            width: 1280,
            height: 720,
            depth_or_array: 1,
            mip_levels: 1,
            format: 115,
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: 0xC00001,
        };
        let rt = sanitize_resource_desc(&base);
        assert_eq!(rt.format, 87);
        assert_eq!(rt.flags, 0x1);

        let rw = sanitize_resource_desc(&ResourceDescRaw { flags: 0x5, ..base });
        assert_eq!(rw.format, 87);
        assert_eq!(rw.flags, 0x5);

        let srv_only = sanitize_resource_desc(&ResourceDescRaw { flags: 0, ..base });
        assert_eq!(srv_only.format, 115);

        assert_eq!(map_rtv_format(115), 87);

        let mut clear_scratch = [0u32; 5];
        let clear_in = [115u32, 0, 0, 0, 0];
        let clear_ptr = sanitize_clear_value(&rt, clear_in.as_ptr().cast(), &mut clear_scratch);
        assert!(!clear_ptr.is_null());
        assert_eq!(clear_scratch[0], 87);
    }

    #[test]
    fn patch_view_desc_remapped_translates_xbox_only_format_on_any_resource() {
        let mut res = ResourceX {
            vtable: RESOURCE_VTABLE.0.as_ptr(),
            bits: 0,
            refs: AtomicU32::new(1),
            desc: ResourceDescRaw {
                dimension: 3,
                alignment: 0,
                width: 1024,
                height: 1024,
                depth_or_array: 1,
                mip_levels: 1,
                format: 118,
                sample_count: 1,
                sample_quality: 0,
                layout: 0,
                flags: 0x2,
            },
            xmem_alloc: None,
            gpu_va: 0,
            heap_ty: 1,
            cpu_map_buf: Mutex::new(None),
            parent_dev: std::ptr::null_mut(),
            real_resource: std::ptr::null_mut(),
        };
        let srv_in = [118u32, 4, 0x1688, 0, 1, 0, 0, 0, 0, 0];
        let mut scratch = ViewDesc40([0; 10]);
        let patched = patch_view_desc_remapped(&raw mut res, srv_in.as_ptr().cast(), &mut scratch);
        assert_ne!(patched, srv_in.as_ptr().cast());
        assert_eq!(scratch.0[0], 45);
        assert_eq!(scratch.0[1], 4);
        assert_eq!(scratch.0[2], 0x1688);

        let srv_119 = [119u32, 4, 0x1688, 0, 1, 0, 0, 0, 0, 0];
        let patched_119 = patch_view_desc_remapped(&raw mut res, srv_119.as_ptr().cast(), &mut scratch);
        assert_ne!(patched_119, srv_119.as_ptr().cast());
        assert_eq!(scratch.0[0], 46);

        let unchanged = [28u32, 4, 0x1688, 0, 1, 0, 0, 0, 0, 0];
        let same_ptr = patch_view_desc_remapped(&raw mut res, unchanged.as_ptr().cast(), &mut scratch);
        assert_eq!(same_ptr, unchanged.as_ptr().cast());
    }

    #[test]
    fn sanitize_uav_fallback_desc_unconditionally_clears_plane_slice() {
        let mut scratch = ViewDesc40([0; 10]);
        let r8_tex2d = [0x3eu32, 4, 0, 1, 0, 0, 0, 0, 0, 0];
        sanitize_uav_fallback_desc(r8_tex2d.as_ptr().cast(), &mut scratch);
        assert_eq!(scratch.0[0], 0x3e);
        assert_eq!(scratch.0[1], 4);
        assert_eq!(scratch.0[3], 0);

        let r8_tex2d_arr = [0x3eu32, 5, 0, 0, 0, 1, 0, 0, 0, 0];
        sanitize_uav_fallback_desc(r8_tex2d_arr.as_ptr().cast(), &mut scratch);
        assert_eq!(scratch.0[0], 0x3e);
        assert_eq!(scratch.0[1], 5);
        assert_eq!(scratch.0[4], 1);
        assert_eq!(scratch.0[5], 0);
    }
}
