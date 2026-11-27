#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, c_char, c_void};
use std::fs::File;
use std::os::windows::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use shim_common::{
    E_INVALIDARG, E_NOINTERFACE, E_POINTER, Guid, HRESULT, S_OK, VtableHeader, boot_trace,
    boot_trace_hr, read_wide_str, translate_virtual_path_str,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualAlloc, VirtualAlloc2, VirtualFree, VirtualQuery,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Xbox Scarlett `IDStorageFactoryX` / `IDStorageFactoryX2` GUID.
pub const IID_DSTORAGE_FACTORY_X: Guid = Guid::new(
    0x6295_9D11,
    0xD45F,
    0x4884,
    [0xA0, 0xA3, 0xF7, 0x86, 0x2E, 0xA2, 0x43, 0xAE],
);

/// Standard PC `IDStorageFactory` GUID.
pub const IID_DSTORAGE_FACTORY_PC: Guid = Guid::new(
    0x6924_EA0C,
    0xC3CD,
    0x4826,
    [0xB1, 0x0A, 0xF6, 0x4F, 0x4E, 0xD9, 0x27, 0xC1],
);

const IID_IUNKNOWN: Guid = Guid::new(0x0000_0000, 0x0000, 0x0000, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);

const E_PENDING: HRESULT = 0x8000_000A_u32 as i32;
const E_OUTOFMEMORY: HRESULT = 0x8007_000E_u32 as i32;
const END_OF_FILE: HRESULT = 0x8007_0026_u32 as i32;
const INVALID_DATA: HRESULT = 0x8007_000D_u32 as i32;
const MAX_DSTORAGE_REQ_BYTES: usize = 256 * 1024 * 1024;

const OPT_ZLIB: u64 = 1;
const OPT_BCPACK_MASK: u64 = 0xF << 1;
const OPT_PAGE_DESTINATION: u64 = 1 << 21;
const OPT_MEMORY_SOURCE: u64 = 1 << 22;
const PAGE_64K: usize = 64 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueueDesc {
    pub source_type: u64,
    pub capacity: u16,
    pub priority: i8,
    pub name: *const c_char,
    pub flags: u64,
}

/// Exact Xbox Scarlett `DSTORAGE_REQUEST` (`0x48` bytes, matching `victory-hle/src/modules/dstorage.rs`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DStorageRequest {
    pub options: u64,
    /// Destination VA, or `*const usize` physical page array when `OPT_PAGE_DESTINATION` is set.
    pub destination: *mut c_void,
    /// With `OPT_PAGE_DESTINATION`, low 16 bits are byte offset into the first 64 KiB page.
    pub page_offset: u64,
    pub destination_size: u32,
    /// `*const FileObject`, or memory buffer pointer when `OPT_MEMORY_SOURCE` is set.
    pub source: *const c_void,
    pub source_offset: u64,
    pub source_size: u32,
    pub intermediate_size: u32,
    pub cancellation_tag: u64,
    pub name: *const c_char,
}

const _: () = assert!(size_of::<DStorageRequest>() == 0x48);
const _: () = assert!(std::mem::offset_of!(DStorageRequest, destination) == 0x08);
const _: () = assert!(std::mem::offset_of!(DStorageRequest, source) == 0x20);

#[repr(C)]
struct FactoryObject {
    vtable: *const *const c_void,
}

#[repr(C)]
pub struct FileObject {
    vtable: *const *const c_void,
    refs: AtomicU32,
    path: String,
    file: Option<File>,
}

#[repr(C)]
pub struct StatusArrayObject {
    vtable: *const *const c_void,
    refs: AtomicU32,
    entries: Vec<AtomicI32>,
}

enum QueuedCommand {
    Read(DStorageRequest),
    Status {
        status: usize, // *mut StatusArrayObject
        index: u32,
    },
    Signal {
        fence: usize, // *mut ID3D12Fence / FenceX
        val: u64,
    },
}

#[inline]
unsafe fn com_slot<F: Copy>(obj: *mut c_void, slot: usize) -> F {
    let vtbl = unsafe { *obj.cast::<*const *const c_void>() };
    unsafe { std::mem::transmute_copy(&*vtbl.add(slot)) }
}

#[repr(C)]
pub struct QueueObject {
    vtable: *const *const c_void,
    refs: AtomicU32,
    capacity: u16,
    priority: i8,
    submitted: AtomicU64,
    has_ttdb_pending: AtomicBool,
    pending: Mutex<Vec<QueuedCommand>>,
    first_error: Mutex<Option<HRESULT>>,
}

extern "system" fn factory_missing<const SLOT: usize>(_this: *mut FactoryObject) -> HRESULT {
    boot_trace(
        "xcrd_pc",
        "IDStorageFactoryX::stub",
        &format!("slot={SLOT} (+{:#x})", SLOT * 8),
    );
    S_OK
}

extern "system" fn file_missing<const SLOT: usize>(_this: *mut FileObject) -> HRESULT {
    boot_trace(
        "xcrd_pc",
        "IDStorageFileX::stub",
        &format!("slot={SLOT} (+{:#x})", SLOT * 8),
    );
    S_OK
}

extern "system" fn queue_missing<const SLOT: usize>(_this: *mut QueueObject) -> HRESULT {
    boot_trace(
        "xcrd_pc",
        "IDStorageQueueX::stub",
        &format!("slot={SLOT} (+{:#x})", SLOT * 8),
    );
    S_OK
}

/// 16-slot Scarlett `IDStorageFactoryX2` vtable (slot 8 = `SetStagingBufferSize`, slot 10 = `CreateQueue2`).
static FACTORY_VTABLE: VtableHeader<16> = VtableHeader([
    factory_qi as *const c_void,                 // 0 (0x00) QueryInterface
    factory_add_ref as *const c_void,            // 1 (0x08) AddRef
    factory_release as *const c_void,            // 2 (0x10) Release
    factory_create_queue as *const c_void,       // 3 (0x18) CreateQueue (legacy 2020)
    factory_open_file as *const c_void,          // 4 (0x20) OpenFile
    factory_create_status_array as *const c_void,// 5 (0x28) CreateStatusArray
    factory_set_cpu_affinity as *const c_void,   // 6 (0x30) SetCpuAffinity
    factory_set_debug_flags as *const c_void,    // 7 (0x38) SetDebugFlags
    factory_set_staging_buffer_size as *const c_void, // 8 (0x40) SetStagingBufferSize
    factory_missing::<9> as *const c_void,       // 9 (0x48)
    factory_create_queue as *const c_void,       // 10 (0x50) CreateQueue (Scarlett X2)
    factory_missing::<11> as *const c_void,      // 11 (0x58)
    factory_missing::<12> as *const c_void,      // 12 (0x60)
    factory_missing::<13> as *const c_void,      // 13 (0x68)
    factory_missing::<14> as *const c_void,      // 14 (0x70)
    factory_missing::<15> as *const c_void,      // 15 (0x78)
]);

static FACTORY_SINGLETON: FactoryObject = FactoryObject {
    vtable: FACTORY_VTABLE.0.as_ptr(),
};

unsafe impl Sync for FactoryObject {}

static FILE_VTABLE: VtableHeader<8> = VtableHeader([
    generic_qi as *const c_void,
    file_add_ref as *const c_void,
    file_release as *const c_void,
    file_close as *const c_void,
    file_get_info as *const c_void,
    file_missing::<5> as *const c_void,
    file_missing::<6> as *const c_void,
    file_missing::<7> as *const c_void,
]);

static STATUS_VTABLE: VtableHeader<5> = VtableHeader([
    generic_qi as *const c_void,
    status_add_ref as *const c_void,
    status_release as *const c_void,
    status_is_complete as *const c_void,   // 3 (0x18) IsComplete
    status_get_hresult as *const c_void,   // 4 (0x20) GetHResult
]);

static QUEUE_VTABLE: VtableHeader<12> = VtableHeader([
    generic_qi as *const c_void,
    queue_add_ref as *const c_void,
    queue_release as *const c_void,
    queue_enqueue_request as *const c_void, // 3 (0x18) EnqueueRequest
    queue_enqueue_status as *const c_void,  // 4 (0x20) EnqueueStatus
    queue_enqueue_signal as *const c_void,  // 5 (0x28) EnqueueSignal
    queue_submit as *const c_void,          // 6 (0x30) Submit
    queue_cancel_tag as *const c_void,      // 7 (0x38) CancelRequestsWithTag
    queue_close as *const c_void,           // 8 (0x40) Close
    queue_missing::<9> as *const c_void,    // 9 (0x48) GetErrorEvent
    queue_missing::<10> as *const c_void,   // 10 (0x50) RetrieveErrorRecord
    queue_missing::<11> as *const c_void,   // 11 (0x58) Query
]);

type WritePhysFn = unsafe extern "system" fn(*const usize, usize, usize, *const u8, usize) -> i32;

static WRITE_PHYS_FN: OnceLock<Option<usize>> = OnceLock::new();

fn resolve_write_phys() -> Option<WritePhysFn> {
    let addr = *WRITE_PHYS_FN.get_or_init(|| {
        let wide: Vec<u16> = "xmem_pc.dll\0".encode_utf16().collect();
        let h = unsafe { GetModuleHandleW(wide.as_ptr()) };
        if h.is_null() {
            return None;
        }
        unsafe { GetProcAddress(h, c"PcXMemWritePhysicalPages".as_ptr().cast()) }
            .map(|f| f as usize)
    });
    addr.map(|a| unsafe { std::mem::transmute::<usize, WritePhysFn>(a) })
}

fn cstr_lossy(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
}

extern "system" fn factory_qi(
    this: *mut FactoryObject,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(g) = (unsafe { iid.as_ref() }) else {
        return E_INVALIDARG;
    };
    if *g == IID_IUNKNOWN || *g == IID_DSTORAGE_FACTORY_X || *g == IID_DSTORAGE_FACTORY_PC {
        unsafe { *out = this.cast() };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}

extern "system" fn factory_add_ref(_: *mut FactoryObject) -> u32 {
    1
}

extern "system" fn factory_release(_: *mut FactoryObject) -> u32 {
    1
}

extern "system" fn generic_qi(
    this: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if unsafe { iid.as_ref() } == Some(&IID_IUNKNOWN) {
        unsafe { *out = this };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}

extern "system" fn factory_set_cpu_affinity(_: *mut FactoryObject, _mask: u64) -> HRESULT {
    S_OK
}

extern "system" fn factory_set_debug_flags(_: *mut FactoryObject, _flags: u32) -> HRESULT {
    S_OK
}

extern "system" fn factory_set_staging_buffer_size(_: *mut FactoryObject, bytes: u32) -> HRESULT {
    boot_trace(
        "xcrd_pc",
        "IDStorageFactoryX::SetStagingBufferSize",
        &format!("bytes={bytes:#x}"),
    );
    S_OK
}

extern "system" fn factory_open_file(
    _: *mut FactoryObject,
    path: *const u16,
    _iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(raw_path) = (unsafe { read_wide_str(path) }) else {
        return E_INVALIDARG;
    };
    let host_path = translate_virtual_path_str(&raw_path).unwrap_or_else(|| raw_path.clone());
    match File::open(&host_path) {
        Ok(file) => {
            let obj = Box::new(FileObject {
                vtable: FILE_VTABLE.0.as_ptr(),
                refs: AtomicU32::new(1),
                path: host_path.clone(),
                file: Some(file),
            });
            let ptr = Box::into_raw(obj).cast();
            unsafe { *out = ptr };
            boot_trace_hr(
                "xcrd_pc",
                "IDStorageFactoryX::OpenFile",
                S_OK,
                &format!("raw={raw_path} host={host_path}"),
            );
            S_OK
        }
        Err(err) => {
            unsafe { *out = std::ptr::null_mut() };
            let hr = err
                .raw_os_error()
                .map_or(0x8007_0002_u32 as i32, |e| (0x8007_0000 | (e as u32 & 0xFFFF)) as i32);
            boot_trace_hr(
                "xcrd_pc",
                "IDStorageFactoryX::OpenFile",
                hr,
                &format!("raw={raw_path} host={host_path} err={err}"),
            );
            hr
        }
    }
}

extern "system" fn factory_create_status_array(
    _: *mut FactoryObject,
    capacity: u32,
    name: *const c_char,
    _iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let cap = capacity as usize;
    let obj = Box::new(StatusArrayObject {
        vtable: STATUS_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
        entries: (0..cap).map(|_| AtomicI32::new(S_OK)).collect(),
    });
    let ptr = Box::into_raw(obj).cast();
    unsafe { *out = ptr };
    boot_trace_hr(
        "xcrd_pc",
        "IDStorageFactoryX::CreateStatusArray",
        S_OK,
        &format!("cap={capacity} name={}", cstr_lossy(name)),
    );
    S_OK
}

extern "system" fn factory_create_queue(
    _: *mut FactoryObject,
    desc: *const QueueDesc,
    _iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(d) = (unsafe { desc.as_ref() }) else {
        return E_INVALIDARG;
    };
    let obj = Box::new(QueueObject {
        vtable: QUEUE_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
        capacity: d.capacity,
        priority: d.priority,
        submitted: AtomicU64::new(0),
        has_ttdb_pending: AtomicBool::new(false),
        pending: Mutex::new(Vec::new()),
        first_error: Mutex::new(None),
    });
    let ptr = Box::into_raw(obj).cast();
    unsafe { *out = ptr };
    boot_trace_hr(
        "xcrd_pc",
        "IDStorageFactoryX::CreateQueue",
        S_OK,
        &format!(
            "src={} cap={} prio={} flags={:#x} name={}",
            d.source_type,
            d.capacity,
            d.priority,
            d.flags,
            cstr_lossy(d.name)
        ),
    );
    S_OK
}

extern "system" fn file_add_ref(this: *mut FileObject) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn file_release(this: *mut FileObject) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

extern "system" fn file_close(this: *mut FileObject) {
    if !this.is_null() {
        unsafe { &mut *this }.file = None;
    }
}

extern "system" fn file_get_info(this: *mut FileObject, info: *mut u64) -> HRESULT {
    if this.is_null() || info.is_null() {
        return E_INVALIDARG;
    }
    if let Some(f) = unsafe { &*this }.file.as_ref() {
        if let Ok(meta) = f.metadata() {
            unsafe { *info = meta.len() };
            return S_OK;
        }
    }
    0x8007_0006_u32 as i32
}

extern "system" fn status_add_ref(this: *mut StatusArrayObject) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn status_release(this: *mut StatusArrayObject) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

extern "system" fn status_is_complete(this: *mut StatusArrayObject, index: u32) -> i32 {
    let arr = unsafe { &*this };
    let idx = index as usize;
    i32::from(idx < arr.entries.len() && arr.entries[idx].load(Ordering::Acquire) != E_PENDING)
}

extern "system" fn status_get_hresult(this: *mut StatusArrayObject, index: u32) -> HRESULT {
    let arr = unsafe { &*this };
    let idx = index as usize;
    if idx < arr.entries.len() {
        arr.entries[idx].load(Ordering::Acquire)
    } else {
        E_INVALIDARG
    }
}

extern "system" fn queue_add_ref(this: *mut QueueObject) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn queue_release(this: *mut QueueObject) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

fn try_alloc_zeroed(len: usize) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).ok()?;
    v.resize(len, 0);
    Some(v)
}

fn execute_request(r: &DStorageRequest) -> HRESULT {
    if r.source.is_null() || r.destination.is_null() {
        return E_INVALIDARG;
    }
    let src_len = r.source_size as usize;
    let dst_len = r.destination_size as usize;
    if dst_len == 0 {
        return S_OK;
    }
    if src_len > MAX_DSTORAGE_REQ_BYTES || dst_len > MAX_DSTORAGE_REQ_BYTES {
        static BAD_SIZE_LOGS: AtomicU32 = AtomicU32::new(0);
        if BAD_SIZE_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
            boot_trace(
                "xcrd_pc",
                "IDStorageQueueX::BAD_SIZE",
                &format!(
                    "src={src_len:#x} dst={dst_len:#x} off={:#x} options={:#x}",
                    r.source_offset, r.options
                ),
            );
        }
        return E_INVALIDARG;
    }

    // 1. Read source bytes (file or memory).
    let Some(mut raw) = try_alloc_zeroed(src_len) else {
        return E_OUTOFMEMORY;
    };
    if (r.options & OPT_MEMORY_SOURCE) != 0 {
        if src_len > 0 {
            let src_ptr = unsafe { r.source.cast::<u8>().add(r.source_offset as usize) };
            unsafe { std::ptr::copy_nonoverlapping(src_ptr, raw.as_mut_ptr(), src_len) };
        }
    } else {
        let file_obj = unsafe { &*r.source.cast::<FileObject>() };
        let Some(file) = file_obj.file.as_ref() else {
            return E_INVALIDARG;
        };
        let mut done = 0usize;
        while done < src_len {
            match file.seek_read(&mut raw[done..], r.source_offset + done as u64) {
                Ok(0) => return END_OF_FILE,
                Ok(n) => done += n,
                Err(_) => return END_OF_FILE,
            }
        }
    }

    // 2. Decompress if requested (ZLIB supported via zlib-rs).
    let payload: Vec<u8> = if (r.options & OPT_BCPACK_MASK) != 0 {
        static BCPACK_LOGS: AtomicU32 = AtomicU32::new(0);
        if BCPACK_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
            boot_trace(
                "xcrd_pc",
                "IDStorageQueueX::BCPACK_WARN",
                &format!(
                    "options={:#x} src={} dst={}",
                    r.options, r.source_size, r.destination_size
                ),
            );
        }
        raw
    } else if (r.options & OPT_ZLIB) != 0 {
        let Some(mut out) = try_alloc_zeroed(dst_len) else {
            return E_OUTOFMEMORY;
        };
        let (res, rc) =
            zlib_rs::decompress_slice(&mut out, &raw, zlib_rs::InflateConfig::default());
        if rc == zlib_rs::ReturnCode::Ok
            || (rc == zlib_rs::ReturnCode::BufError && res.len() == dst_len)
        {
            res.to_vec()
        } else {
            let mut raw_out = out;
            raw_out.fill(0);
            let (raw_res, raw_rc) = zlib_rs::decompress_slice(
                &mut raw_out,
                &raw,
                zlib_rs::InflateConfig { window_bits: -15 },
            );
            if raw_rc == zlib_rs::ReturnCode::Ok
                || (raw_rc == zlib_rs::ReturnCode::BufError && raw_res.len() == dst_len)
            {
                raw_res.to_vec()
            } else {
                static ZLIB_FAIL_LOGS: AtomicU32 = AtomicU32::new(0);
                if ZLIB_FAIL_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                    let head_hex: String = raw
                        .iter()
                        .take(16)
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    boot_trace(
                        "xcrd_pc",
                        "IDStorageQueueX::ZLIB_FAIL",
                        &format!(
                            "rc={rc:?} raw_rc={raw_rc:?} src={src_len} dst={dst_len} off={:#x} opts={:#x} inter={:#x} head={head_hex}",
                            r.source_offset, r.options, r.intermediate_size
                        ),
                    );
                }
                return INVALID_DATA;
            }
        }
    } else {
        raw
    };

    let write_len = payload.len().min(dst_len);

    // 3. Write destination (VA or physical pages via xmem_pc).
    if (r.options & OPT_PAGE_DESTINATION) != 0 {
        let byte_off = if r.page_offset < (1 << 28) {
            r.page_offset as usize
        } else {
            (r.page_offset & 0xFFFF) as usize
        };
        let page_count = (byte_off + write_len).div_ceil(PAGE_64K);
        let Some(write_phys) = resolve_write_phys() else {
            boot_trace(
                "xcrd_pc",
                "IDStorageQueueX::PAGE_DEST_NO_XMEM",
                &format!("pages={page_count} len={write_len}"),
            );
            return E_INVALIDARG;
        };
        let ok = unsafe {
            write_phys(
                r.destination.cast::<usize>(),
                page_count,
                byte_off,
                payload.as_ptr(),
                write_len,
            )
        };
        if ok == 0 {
            static PAGE_FAIL_LOGS: AtomicU32 = AtomicU32::new(0);
            if PAGE_FAIL_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                let sample_n = page_count.min(4);
                let sample_ids: Vec<String> = (0..sample_n)
                    .map(|i| format!("{:#x}", unsafe { *r.destination.cast::<usize>().add(i) }))
                    .collect();
                boot_trace(
                    "xcrd_pc",
                    "IDStorageQueueX::PAGE_DEST_FAIL",
                    &format!(
                        "dst={:?} page_off={:#x} pages={page_count} len={write_len} opts={:#x} ids=[{}]",
                        r.destination,
                        r.page_offset,
                        r.options,
                        sample_ids.join(","),
                    ),
                );
            }
            return E_INVALIDARG;
        }
    } else {
        return safe_copy_to_dst(r.destination.cast::<u8>(), &payload[..write_len]);
    }
    S_OK
}

fn safe_copy_to_dst(dst: *mut u8, src: &[u8]) -> HRESULT {
    if dst.is_null() || src.is_empty() {
        return S_OK;
    }
    static GUARD_LOGS: AtomicU32 = AtomicU32::new(0);
    static COMMIT_LOGS: AtomicU32 = AtomicU32::new(0);
    let writable_mask =
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    let mut offset = 0usize;
    while offset < src.len() {
        let cur = unsafe { dst.add(offset) };
        let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
        let q = unsafe {
            VirtualQuery(
                cur.cast(),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if q == 0 {
            if GUARD_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                boot_trace(
                    "xcrd_pc",
                    "IDStorageQueueX::DST_GUARD",
                    &format!("dst={dst:?} off={offset:#x} len={:#x} state=0", src.len()),
                );
            }
            break;
        }
        let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
        let avail = region_end.saturating_sub(cur as usize);
        if avail == 0 {
            break;
        }
        let chunk = (src.len() - offset).min(avail);
        if mbi.State == MEM_RESERVE {
            let mut committed = unsafe { VirtualAlloc(cur.cast(), chunk, MEM_COMMIT, PAGE_READWRITE) };
            if committed.is_null() {
                // `XMemVirtualAlloc` reserves 64 KiB placeholder regions (`MEM_RESERVE_PLACEHOLDER`),
                // which reject `VirtualAlloc(MEM_COMMIT)` until split + replaced via `VirtualAlloc2`.
                unsafe {
                    VirtualFree(cur.cast(), chunk, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
                }
                committed = unsafe {
                    VirtualAlloc2(
                        GetCurrentProcess(),
                        cur.cast(),
                        chunk,
                        MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                        PAGE_READWRITE,
                        std::ptr::null_mut(),
                        0,
                    )
                };
            }
            if committed.is_null() {
                if GUARD_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                    boot_trace(
                        "xcrd_pc",
                        "IDStorageQueueX::DST_GUARD",
                        &format!(
                            "dst={dst:?} off={offset:#x} len={:#x} state=MEM_RESERVE_FAIL",
                            src.len()
                        ),
                    );
                }
                break;
            }
            if COMMIT_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                boot_trace(
                    "xcrd_pc",
                    "IDStorageQueueX::DST_LAZY_COMMIT",
                    &format!("dst={cur:?} chunk={chunk:#x} off={offset:#x}"),
                );
            }
        } else if mbi.State != MEM_COMMIT || (mbi.Protect & writable_mask) == 0 {
            if GUARD_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                boot_trace(
                    "xcrd_pc",
                    "IDStorageQueueX::DST_GUARD",
                    &format!(
                        "dst={dst:?} off={offset:#x} len={:#x} state={:#x} prot={:#x}",
                        src.len(),
                        mbi.State,
                        mbi.Protect
                    ),
                );
            }
            break;
        }
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr().add(offset), cur, chunk) };
        offset += chunk;
    }
    S_OK
}

fn request_compression_label(options: u64) -> String {
    if (options & OPT_BCPACK_MASK) != 0 {
        format!("BCPACK({})", (options & OPT_BCPACK_MASK) >> 1)
    } else if (options & OPT_ZLIB) != 0 {
        String::from("ZLIB")
    } else {
        String::from("NONE")
    }
}

fn request_source_label(r: &DStorageRequest) -> String {
    if r.source.is_null() {
        String::from("null")
    } else if (r.options & OPT_MEMORY_SOURCE) != 0 {
        format!("mem={:?}", r.source)
    } else {
        let f = unsafe { &*r.source.cast::<FileObject>() };
        format!("file={:?}({})", r.source, f.path)
    }
}

fn is_ttdb_request(r: &DStorageRequest) -> bool {
    if r.source.is_null() || (r.options & OPT_MEMORY_SOURCE) != 0 {
        return false;
    }
    let lower = unsafe { &*r.source.cast::<FileObject>() }.path.to_ascii_lowercase();
    lower.contains("ttdb") || lower.contains(".ttpf")
}

extern "system" fn queue_enqueue_request(this: *mut QueueObject, req: *const DStorageRequest) {
    if this.is_null() || req.is_null() {
        return;
    }
    let q = unsafe { &*this };
    let r = unsafe { *req };
    let is_ttdb = is_ttdb_request(&r);
    if is_ttdb {
        q.has_ttdb_pending.store(true, Ordering::Release);
    }
    static ENQ_LOGS: AtomicU32 = AtomicU32::new(0);
    static TTDB_ENQ_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = ENQ_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    let should_log = n <= 32 || (is_ttdb && TTDB_ENQ_LOGS.fetch_add(1, Ordering::Relaxed) < 64);
    if should_log {
        boot_trace(
            "xcrd_pc",
            "IDStorageQueueX::EnqueueRequest",
            &format!(
                "#{n} q={this:?} src={} off={:#x} size={:#x} comp={} uncomp_size={:#x} dst={:?} page_off={:#x} opts={:#x} name={}",
                request_source_label(&r),
                r.source_offset,
                r.source_size,
                request_compression_label(r.options),
                r.destination_size,
                r.destination,
                r.page_offset,
                r.options,
                cstr_lossy(r.name),
            ),
        );
    }
    q.pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(QueuedCommand::Read(r));
}

extern "system" fn queue_enqueue_status(
    this: *mut QueueObject,
    status: *mut StatusArrayObject,
    index: u32,
) {
    if this.is_null() || status.is_null() {
        return;
    }
    let q = unsafe { &*this };
    let is_ttdb = q.has_ttdb_pending.load(Ordering::Acquire);
    static ENQ_STATUS_LOGS: AtomicU32 = AtomicU32::new(0);
    static TTDB_STATUS_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = ENQ_STATUS_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 32 || (is_ttdb && TTDB_STATUS_LOGS.fetch_add(1, Ordering::Relaxed) < 64) {
        boot_trace(
            "xcrd_pc",
            "IDStorageQueueX::EnqueueStatus",
            &format!("#{n} q={this:?} status={status:?} index={index} ttdb={is_ttdb}"),
        );
    }
    let s = unsafe { &*status };
    if (index as usize) < s.entries.len() {
        s.entries[index as usize].store(E_PENDING, Ordering::Release);
    }
    status_add_ref(status);
    q.pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(QueuedCommand::Status {
            status: status as usize,
            index,
        });
}

extern "system" fn queue_enqueue_signal(this: *mut QueueObject, fence: *mut c_void, val: u64) {
    if this.is_null() {
        return;
    }
    if !fence.is_null() {
        type AddRefFn = unsafe extern "system" fn(*mut c_void) -> u32;
        unsafe { com_slot::<AddRefFn>(fence, 1)(fence) };
    }
    static ENQ_SIG_LOGS: AtomicU32 = AtomicU32::new(0);
    let n = ENQ_SIG_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        boot_trace(
            "xcrd_pc",
            "IDStorageQueueX::EnqueueSignal",
            &format!("#{n} q={this:?} fence={fence:?} val={val}"),
        );
    }
    let q = unsafe { &*this };
    q.pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(QueuedCommand::Signal {
            fence: fence as usize,
            val,
        });
}

extern "system" fn queue_submit(this: *mut QueueObject) {
    if this.is_null() {
        return;
    }
    let q = unsafe { &*this };
    q.submitted.fetch_add(1, Ordering::Relaxed);
    let has_ttdb = q.has_ttdb_pending.swap(false, Ordering::AcqRel);
    let cmds = {
        let mut p = q.pending.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *p)
    };
    static SUBMIT_LOGS: AtomicU32 = AtomicU32::new(0);
    static TTDB_SUBMIT_LOGS: AtomicU32 = AtomicU32::new(0);
    let submit_n = SUBMIT_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if submit_n <= 32 || (has_ttdb && TTDB_SUBMIT_LOGS.fetch_add(1, Ordering::Relaxed) < 64) {
        boot_trace(
            "xcrd_pc",
            "IDStorageQueueX::Submit",
            &format!("#{submit_n} q={this:?} cmds={} ttdb={has_ttdb}", cmds.len()),
        );
    }
    static TOTAL_READ_BYTES: AtomicU64 = AtomicU64::new(0);
    static REQ_DONE_LOGS: AtomicU32 = AtomicU32::new(0);
    static ERR_DONE_LOGS: AtomicU32 = AtomicU32::new(0);
    static TTDB_REQ_DONE_LOGS: AtomicU32 = AtomicU32::new(0);
    static STATUS_DONE_LOGS: AtomicU32 = AtomicU32::new(0);
    static TTDB_STATUS_DONE_LOGS: AtomicU32 = AtomicU32::new(0);
    static SIGNAL_DONE_LOGS: AtomicU32 = AtomicU32::new(0);
    let mut last_read: Option<DStorageRequest> = None;
    let mut err_slot = q.first_error.lock().unwrap_or_else(|e| e.into_inner());
    for cmd in cmds {
        match cmd {
            QueuedCommand::Read(req) => {
                TOTAL_READ_BYTES.fetch_add(u64::from(req.destination_size), Ordering::Relaxed);
                last_read = Some(req);
                let is_ttdb = is_ttdb_request(&req);
                let hr = execute_request(&req);
                let rn = REQ_DONE_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                let log_err = hr < 0 && ERR_DONE_LOGS.fetch_add(1, Ordering::Relaxed) < 64;
                if rn <= 32
                    || log_err
                    || (is_ttdb && TTDB_REQ_DONE_LOGS.fetch_add(1, Ordering::Relaxed) < 64)
                {
                    boot_trace_hr(
                        "xcrd_pc",
                        "IDStorageQueueX::RequestComplete",
                        hr,
                        &format!(
                            "#{rn} src={} off={:#x} size={:#x} comp={} uncomp_size={:#x} dst={:?}",
                            request_source_label(&req),
                            req.source_offset,
                            req.source_size,
                            request_compression_label(req.options),
                            req.destination_size,
                            req.destination,
                        ),
                    );
                }
                if hr < 0 && err_slot.is_none() {
                    *err_slot = Some(hr);
                }
            }
            QueuedCommand::Status { status, index } => {
                let st_ptr = status as *mut StatusArrayObject;
                let s = unsafe { &*st_ptr };
                let hr = err_slot.take().unwrap_or(S_OK);
                if (index as usize) < s.entries.len() {
                    s.entries[index as usize].store(hr, Ordering::Release);
                }
                let sn = STATUS_DONE_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                if sn <= 32
                    || hr < 0
                    || (has_ttdb && TTDB_STATUS_DONE_LOGS.fetch_add(1, Ordering::Relaxed) < 64)
                {
                    boot_trace_hr(
                        "xcrd_pc",
                        "IDStorageQueueX::StatusComplete",
                        hr,
                        &format!("#{sn} q={this:?} status={st_ptr:?} index={index} ttdb={has_ttdb}"),
                    );
                }
                status_release(st_ptr);
            }
            QueuedCommand::Signal { fence, val } => {
                if fence != 0 {
                    let fence_ptr = fence as *mut c_void;
                    type SignalFn = unsafe extern "system" fn(*mut c_void, u64) -> HRESULT;
                    type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
                    let hr = unsafe { com_slot::<SignalFn>(fence_ptr, 10)(fence_ptr, val) };
                    let sign_n = SIGNAL_DONE_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
                    if sign_n <= 16 || hr < 0 {
                        boot_trace_hr(
                            "xcrd_pc",
                            "IDStorageQueueX::SignalComplete",
                            hr,
                            &format!("#{sign_n} q={this:?} fence={fence_ptr:?} val={val}"),
                        );
                    }
                    unsafe { com_slot::<ReleaseFn>(fence_ptr, 2)(fence_ptr) };
                }
            }
        }
    }
    if submit_n.is_multiple_of(500) {
        let total_mib = TOTAL_READ_BYTES.load(Ordering::Relaxed) / (1024 * 1024);
        let src_label = last_read
            .as_ref()
            .map_or_else(|| String::from("none"), request_source_label);
        boot_trace(
            "xcrd_pc",
            "IDStorageQueueX::SubmitHeartbeat",
            &format!("submit_n={submit_n} total_mib={total_mib} last_src={src_label}"),
        );
    }
}

extern "system" fn queue_cancel_tag(_: *mut QueueObject, _mask: u64, _val: u64) {}
extern "system" fn queue_close(this: *mut QueueObject) {
    queue_submit(this);
}

#[unsafe(no_mangle)]
pub extern "system" fn DStorageGetFactory(iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(g) = (unsafe { iid.as_ref() }) else {
        unsafe { *out = std::ptr::null_mut() };
        return E_INVALIDARG;
    };
    if *g == IID_DSTORAGE_FACTORY_X || *g == IID_DSTORAGE_FACTORY_PC || *g == IID_IUNKNOWN {
        unsafe { *out = (&raw const FACTORY_SINGLETON).cast_mut().cast() };
        boot_trace_hr(
            "xcrd_pc",
            "DStorageGetFactory",
            S_OK,
            &format!("iid={}", g.format_guid()),
        );
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        boot_trace_hr(
            "xcrd_pc",
            "DStorageGetFactory",
            E_NOINTERFACE,
            &format!("iid={}", g.format_guid()),
        );
        E_NOINTERFACE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dstorage_factory_opens_file_and_reads_via_queue() {
        let dir = tempfile::tempdir().unwrap();
        let test_file = dir.path().join("chunk.bin");
        std::fs::write(&test_file, b"LUCIAS_DSTORAGE").unwrap();

        let mut factory_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(DStorageGetFactory(&IID_DSTORAGE_FACTORY_X, &mut factory_ptr), S_OK);
        assert!(!factory_ptr.is_null());

        // Verify Scarlett vtable slots 8 (SetStagingBufferSize @ +0x40) and 10 (CreateQueue @ +0x50).
        let vtbl = unsafe { *factory_ptr.cast::<*const *const c_void>() };
        type SetStagingFn = unsafe extern "system" fn(*mut c_void, u32) -> HRESULT;
        type CreateQueueFn =
            unsafe extern "system" fn(*mut c_void, *const QueueDesc, *const Guid, *mut *mut c_void) -> HRESULT;
        let set_staging: SetStagingFn = unsafe { std::mem::transmute(*vtbl.add(8)) };
        let create_q_slot10: CreateQueueFn = unsafe { std::mem::transmute(*vtbl.add(10)) };
        assert_eq!(unsafe { set_staging(factory_ptr, 32 * 1024 * 1024) }, S_OK);

        let wide_path: Vec<u16> = test_file
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        let mut file_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            factory_open_file(
                factory_ptr.cast(),
                wide_path.as_ptr(),
                &IID_IUNKNOWN,
                &mut file_ptr
            ),
            S_OK
        );

        let desc = QueueDesc {
            source_type: 0,
            capacity: 32,
            priority: 0,
            name: std::ptr::null(),
            flags: 1,
        };
        let mut queue_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe { create_q_slot10(factory_ptr, &desc, &IID_IUNKNOWN, &mut queue_ptr) },
            S_OK
        );

        let mut status_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            factory_create_status_array(
                factory_ptr.cast(),
                4,
                std::ptr::null(),
                &IID_IUNKNOWN,
                &mut status_ptr
            ),
            S_OK
        );

        let mut out_buf = [0u8; 15];
        let req = DStorageRequest {
            options: 0,
            destination: out_buf.as_mut_ptr().cast(),
            page_offset: 0,
            destination_size: 15,
            source: file_ptr.cast(),
            source_offset: 0,
            source_size: 15,
            intermediate_size: 0,
            cancellation_tag: 0,
            name: std::ptr::null(),
        };
        queue_enqueue_request(queue_ptr.cast(), &req);
        queue_enqueue_status(queue_ptr.cast(), status_ptr.cast(), 0);
        // Deferred execution: still pending before Submit!
        assert_eq!(status_is_complete(status_ptr.cast(), 0), 0);
        queue_submit(queue_ptr.cast());

        assert_eq!(status_is_complete(status_ptr.cast(), 0), 1);
        assert_eq!(status_get_hresult(status_ptr.cast(), 0), S_OK);
        assert_eq!(&out_buf, b"LUCIAS_DSTORAGE");

        status_release(status_ptr.cast());
        queue_release(queue_ptr.cast());
        file_release(file_ptr.cast());
    }

    #[test]
    fn queue_enqueue_signal_invokes_fence_slot_10_on_submit() {
        #[repr(C)]
        struct MockFence {
            vtable: *const *const c_void,
            refs: AtomicU32,
            signaled: AtomicU64,
        }
        extern "system" fn mock_add_ref(this: *mut MockFence) -> u32 {
            unsafe { &*this }.refs.fetch_add(1, Ordering::SeqCst) + 1
        }
        extern "system" fn mock_release(this: *mut MockFence) -> u32 {
            unsafe { &*this }.refs.fetch_sub(1, Ordering::SeqCst) - 1
        }
        extern "system" fn mock_signal(this: *mut MockFence, val: u64) -> HRESULT {
            unsafe { &*this }.signaled.store(val, Ordering::SeqCst);
            S_OK
        }
        let mut vtbl = [std::ptr::null::<c_void>(); 11];
        vtbl[1] = mock_add_ref as *const c_void;
        vtbl[2] = mock_release as *const c_void;
        vtbl[10] = mock_signal as *const c_void;

        let mut fence = MockFence {
            vtable: vtbl.as_ptr(),
            refs: AtomicU32::new(1),
            signaled: AtomicU64::new(0),
        };
        let mut factory_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(DStorageGetFactory(&IID_DSTORAGE_FACTORY_X, &mut factory_ptr), S_OK);
        let desc = QueueDesc {
            source_type: 0,
            capacity: 32,
            priority: 0,
            name: std::ptr::null(),
            flags: 0,
        };
        let mut queue_ptr: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            factory_create_queue(factory_ptr.cast(), &desc, &IID_IUNKNOWN, &mut queue_ptr),
            S_OK
        );

        queue_enqueue_signal(queue_ptr.cast(), (&raw mut fence).cast(), 0x1234_5678);
        assert_eq!(fence.refs.load(Ordering::SeqCst), 2);
        assert_eq!(fence.signaled.load(Ordering::SeqCst), 0);

        queue_submit(queue_ptr.cast());
        assert_eq!(fence.signaled.load(Ordering::SeqCst), 0x1234_5678);
        assert_eq!(fence.refs.load(Ordering::SeqCst), 1);

        queue_release(queue_ptr.cast());
    }

    #[test]
    fn safe_copy_to_dst_commits_reserved_pages_and_guards_invalid_ptr() {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
        let base = unsafe { VirtualAlloc(std::ptr::null(), 0x20000, MEM_RESERVE, PAGE_READWRITE) };
        assert!(!base.is_null());
        let data = vec![0xABu8; 0x1000];
        assert_eq!(safe_copy_to_dst(base.cast(), &data), S_OK);
        let written = unsafe { std::slice::from_raw_parts(base.cast::<u8>(), 0x1000) };
        assert!(written.iter().all(|&b| b == 0xAB));
        assert_eq!(unsafe { VirtualFree(base, 0, MEM_RELEASE) }, 1);

        // Null and unmapped pointers must not crash.
        assert_eq!(safe_copy_to_dst(std::ptr::null_mut(), &data), S_OK);
        assert_eq!(safe_copy_to_dst(0x1000usize as *mut u8, &data), S_OK);
    }

    #[test]
    fn execute_request_rejects_oversized_source_without_abort() {
        let mut dst = [0u8; 64];
        let src = [0u8; 64];
        let req = DStorageRequest {
            options: OPT_MEMORY_SOURCE,
            destination: dst.as_mut_ptr().cast(),
            page_offset: 0,
            destination_size: 64,
            source: src.as_ptr().cast(),
            source_offset: 0,
            source_size: 0xAEC4_BAB9,
            intermediate_size: 0,
            cancellation_tag: 0,
            name: std::ptr::null(),
        };
        assert_eq!(execute_request(&req), E_INVALIDARG);
    }

    #[test]
    fn execute_request_zlib_prefix_truncation_succeeds() {
        // zlib.compress(b'A' * 12288)
        const ZLIB_12K_A: [u8; 36] = [
            0x78, 0x9c, 0xed, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0x6c,
            0xeb, 0x5f, 0xca, 0x1a, 0x1e, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0x06, 0x6c, 0xd9, 0x30, 0xb5,
        ];
        let mut dst = vec![0u8; 0x1000];
        let req = DStorageRequest {
            options: OPT_MEMORY_SOURCE | OPT_ZLIB,
            destination: dst.as_mut_ptr().cast(),
            page_offset: 0,
            destination_size: 0x1000,
            source: ZLIB_12K_A.as_ptr().cast(),
            source_offset: 0,
            source_size: ZLIB_12K_A.len() as u32,
            intermediate_size: 0,
            cancellation_tag: 0,
            name: std::ptr::null(),
        };
        assert_eq!(execute_request(&req), S_OK);
        assert!(dst.iter().all(|&b| b == b'A'));
    }
}
