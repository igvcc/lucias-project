#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_WRITE, GetProcessHeap, HeapAlloc, HeapFree,
    MEM_ADDRESS_REQUIREMENTS, MEM_COMMIT, MEM_EXTENDED_PARAMETER, MEM_PRESERVE_PLACEHOLDER,
    MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER,
    MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, MapViewOfFile3,
    MemExtendedParameterAddressRequirements, PAGE_NOACCESS, PAGE_READWRITE, SEC_RESERVE,
    UnmapViewOfFile, UnmapViewOfFile2, VirtualAlloc, VirtualAlloc2, VirtualFree,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub type BOOL = i32;

const PAGE_64K: usize = 64 * 1024;
const FRAMES_PER_64K_PAGE: usize = PAGE_64K >> 12; // 16 (4 KiB frames per 64 KiB page)
const MIB: usize = 1 << 20;
const GIB: usize = 1 << 30;

// Console XMemVirtualAlloc flags/kinds
const PAGES_2M: u32 = 0x2000_0000;
const PAGES_64K_BIT: u32 = 0x0040_0000;
const PAGES_64K: u32 = PAGES_2M | PAGES_64K_BIT;
const HOST_PROTECTION_MASK: u32 = 0x1FF;
const ADDRESS_32BIT_VMEM: u64 = 4;

// Console XMemAlloc attributes
const ALIGNMENT_SHIFT: u64 = 24;
const ALLOC_32BIT: u64 = 1 << 33;

// Default Xbox Series X title memory budget (~13.5 GiB split GPU-optimal + standard)
const DEFAULT_GPU_OPTIMAL_BUDGET: usize = 8 * GIB;
const DEFAULT_STANDARD_BUDGET: usize = 5 * GIB + 512 * MIB;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XMemPcMetrics {
    pub alloc_calls: u64,
    pub free_calls: u64,
    pub live_bytes: u64,
    pub peak_bytes: u64,
    pub virtual_alloc_calls: u64,
    pub physical_pages_allocated: u64,
    pub physical_pages_freed: u64,
    pub physical_map_calls: u64,
    pub transferred_bytes: u64,
}

static METRIC_ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static METRIC_FREE_CALLS: AtomicU64 = AtomicU64::new(0);
static METRIC_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static METRIC_PEAK_BYTES: AtomicU64 = AtomicU64::new(0);
static METRIC_VALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static METRIC_PHYS_ALLOC: AtomicU64 = AtomicU64::new(0);
static METRIC_PHYS_FREE: AtomicU64 = AtomicU64::new(0);
static METRIC_PHYS_MAP: AtomicU64 = AtomicU64::new(0);
static TRANSFERRED_BYTES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
enum BackingKind {
    Heap { raw_base: *mut c_void },
    Virtual,
}

unsafe impl Send for BackingKind {}

struct AllocEntry {
    size: usize,
    kind: BackingKind,
}

static ALLOC_TABLE: LazyLock<Mutex<HashMap<usize, AllocEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct Section {
    handle: HANDLE,
    pages: usize,
    /// Per-64KiB-page commit bitmap so already-committed pages skip redundant `VirtualAlloc(MEM_COMMIT)`.
    committed: Box<[AtomicU64]>,
}

unsafe impl Send for Section {}
unsafe impl Sync for Section {}

impl Section {
    fn commit_range(&self, first_index: usize, base: usize, len: usize) -> bool {
        let count = len / PAGE_64K;
        let end = (first_index + count).min(self.pages);
        let all_committed = (first_index..end).all(|p| {
            let word = self.committed[p / 64].load(Ordering::Acquire);
            ((word >> (p % 64)) & 1) != 0
        });
        if all_committed {
            return true;
        }
        let ptr = unsafe { VirtualAlloc(base as *const c_void, len, MEM_COMMIT, PAGE_READWRITE) };
        if ptr.is_null() {
            let err = std::io::Error::last_os_error();
            shim_common::boot_trace(
                "xmem_pc",
                "Section::commit_range_FAIL",
                &format!("base={base:#x} len={len:#x} err={err}"),
            );
            return false;
        }
        for p in first_index..end {
            self.committed[p / 64].fetch_or(1u64 << (p % 64), Ordering::AcqRel);
        }
        true
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

#[derive(Clone)]
struct PageSlice {
    section: Arc<Section>,
    index: usize,
}

struct PhysicalState {
    /// Page numbers count 4 KiB frames (multiples of 16), starting at 0x10_0000 (0 stays unused).
    next_page: usize,
    pages: HashMap<usize, PageSlice>,
    /// Mapped views: virtual_base -> (byte_len, first PageSlice).
    views: BTreeMap<usize, (usize, PageSlice)>,
    /// Placeholders left by unmapping a view of exact size `len` at `va`.
    holes: HashMap<usize, usize>,
}

static PHYS_STATE: LazyLock<Mutex<PhysicalState>> = LazyLock::new(|| {
    Mutex::new(PhysicalState {
        next_page: 0x10_0000,
        pages: HashMap::new(),
        views: BTreeMap::new(),
        holes: HashMap::new(),
    })
});

fn update_live_add(bytes: usize) {
    let cur = METRIC_LIVE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
    let mut peak = METRIC_PEAK_BYTES.load(Ordering::Relaxed);
    while cur > peak {
        match METRIC_PEAK_BYTES.compare_exchange_weak(peak, cur, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
}

fn update_live_sub(bytes: usize) {
    let _ = METRIC_LIVE_BYTES.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(bytes as u64))
    });
}

fn decode_alignment(attributes: u64) -> usize {
    let shift = ((attributes >> ALIGNMENT_SHIFT) & 0x1F) as u32;
    if shift <= 4 {
        16
    } else if shift >= 21 {
        2 * MIB
    } else {
        1usize << shift
    }
}

fn alloc_inner(size: usize, attributes: u64) -> *mut c_void {
    let req_size = size.max(1);
    let align = decode_alignment(attributes);
    let force_32bit = (attributes & ALLOC_32BIT) != 0;

    METRIC_ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);

    if force_32bit || align > 4096 {
        let mut req = MEM_ADDRESS_REQUIREMENTS {
            LowestStartingAddress: std::ptr::null_mut(),
            HighestEndingAddress: if force_32bit {
                u32::MAX as *mut c_void
            } else {
                ((1usize << 40) - 1) as *mut c_void
            },
            Alignment: if align > PAGE_64K { align } else { 0 },
        };
        let mut ext = MEM_EXTENDED_PARAMETER::default();
        ext.Anonymous1._bitfield = MemExtendedParameterAddressRequirements as u64;
        ext.Anonymous2.Pointer = (&raw mut req).cast();
        let p = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                std::ptr::null_mut(),
                req_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
                &mut ext,
                1,
            )
        };
        if !p.is_null() {
            let mut tbl = ALLOC_TABLE.lock().unwrap_or_else(|e| e.into_inner());
            tbl.insert(
                p as usize,
                AllocEntry {
                    size: req_size,
                    kind: BackingKind::Virtual,
                },
            );
            update_live_add(req_size);
        }
        return p;
    }

    // HeapAlloc path with guaranteed `align` >= 16 bytes
    let total = match req_size.checked_add(align) {
        Some(t) => t,
        None => return std::ptr::null_mut(),
    };
    let heap = unsafe { GetProcessHeap() };
    let raw = unsafe { HeapAlloc(heap, 0, total) };
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    let raw_addr = raw as usize;
    let aligned_addr = (raw_addr + align - 1) & !(align - 1);
    let user_ptr = aligned_addr as *mut c_void;

    let mut tbl = ALLOC_TABLE.lock().unwrap_or_else(|e| e.into_inner());
    tbl.insert(
        aligned_addr,
        AllocEntry {
            size: req_size,
            kind: BackingKind::Heap { raw_base: raw },
        },
    );
    update_live_add(req_size);
    user_ptr
}

fn free_inner(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    METRIC_FREE_CALLS.fetch_add(1, Ordering::Relaxed);
    let entry = {
        let mut tbl = ALLOC_TABLE.lock().unwrap_or_else(|e| e.into_inner());
        tbl.remove(&(ptr as usize))
    };
    let Some(entry) = entry else {
        return;
    };
    update_live_sub(entry.size);
    match entry.kind {
        BackingKind::Heap { raw_base } => {
            let heap = unsafe { GetProcessHeap() };
            unsafe { HeapFree(heap, 0, raw_base) };
        }
        BackingKind::Virtual => {
            unsafe { VirtualFree(ptr, 0, MEM_RELEASE) };
        }
    }
}

type XMemAllocHookFn = unsafe extern "system" fn(usize, u64) -> *mut c_void;
type XMemFreeHookFn = unsafe extern "system" fn(*mut c_void, u64);

static GAME_XMEM_HOOKS_PTR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn game_xmem_hooks() -> Option<&'static [usize; 2]> {
    let addr = *GAME_XMEM_HOOKS_PTR.get_or_init(|| unsafe {
        let exe = GetModuleHandleW(std::ptr::null());
        if exe.is_null() {
            return 0;
        }
        match GetProcAddress(exe, c"__XMemAllocationHooks__".as_ptr().cast()) {
            Some(p) => p as usize,
            None => 0,
        }
    });
    if addr == 0 {
        None
    } else {
        Some(unsafe { &*(addr as *const [usize; 2]) })
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemAlloc(size: usize, attributes: u64) -> *mut c_void {
    if let Some(hooks) = game_xmem_hooks() {
        let fn_addr = hooks[0];
        if fn_addr != 0 {
            let f: XMemAllocHookFn = unsafe { std::mem::transmute(fn_addr) };
            return unsafe { f(size, attributes) };
        }
    }
    alloc_inner(size, attributes)
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemFree(address: *mut c_void, attributes: u64) {
    if let Some(hooks) = game_xmem_hooks() {
        let fn_addr = hooks[1];
        if fn_addr != 0 {
            let f: XMemFreeHookFn = unsafe { std::mem::transmute(fn_addr) };
            unsafe { f(address, attributes) };
            return;
        }
    }
    free_inner(address);
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemAllocDefault(size: usize, attributes: u64) -> *mut c_void {
    alloc_inner(size, attributes)
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemFreeDefault(address: *mut c_void, _attributes: u64) {
    free_inner(address);
}

fn address_range_from_flags(flags: u64) -> (usize, usize) {
    if (flags & ADDRESS_32BIT_VMEM) != 0 {
        return (0, u32::MAX as usize);
    }
    let field = (flags >> 12) & 7;
    let bits = if field == 0 { 40 } else { 47 - field };
    (1usize << 32, (1usize << bits) - 1)
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemVirtualAlloc(
    base: *mut c_void,
    size: usize,
    alloc_type: u32,
    flags: u64,
    protect: u32,
) -> *mut c_void {
    METRIC_VALLOC_CALLS.fetch_add(1, Ordering::Relaxed);

    let placeholder = (alloc_type & PAGES_64K) == PAGES_64K && (alloc_type & MEM_COMMIT) == 0;
    if placeholder && (alloc_type & MEM_REPLACE_PLACEHOLDER) != 0 {
        return base;
    }

    let host_protect = if placeholder {
        PAGE_NOACCESS
    } else {
        match protect & HOST_PROTECTION_MASK {
            0 => PAGE_NOACCESS,
            p => p,
        }
    };

    let mut host_type = alloc_type & !(PAGES_2M | PAGES_64K_BIT);
    if placeholder {
        host_type |= MEM_RESERVE | MEM_RESERVE_PLACEHOLDER;
    }

    let at = if base.is_null() {
        host_type |= MEM_RESERVE;
        let (lowest, highest) = address_range_from_flags(flags);
        let align = if (alloc_type & (PAGES_2M | PAGES_64K_BIT)) == PAGES_2M {
            2 * MIB
        } else {
            0
        };
        let mut req = MEM_ADDRESS_REQUIREMENTS {
            LowestStartingAddress: lowest as *mut c_void,
            HighestEndingAddress: highest as *mut c_void,
            Alignment: align,
        };
        let mut ext = MEM_EXTENDED_PARAMETER::default();
        ext.Anonymous1._bitfield = MemExtendedParameterAddressRequirements as u64;
        ext.Anonymous2.Pointer = (&raw mut req).cast();
        unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                std::ptr::null_mut(),
                size,
                host_type,
                host_protect,
                &mut ext,
                1,
            )
        }
    } else {
        unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                base,
                size,
                host_type,
                host_protect,
                std::ptr::null_mut(),
                0,
            )
        }
    };
    if at.is_null() {
        let err = std::io::Error::last_os_error();
        shim_common::boot_trace(
            "xmem_pc",
            "XMemVirtualAlloc_FAIL",
            &format!(
                "base={base:?} size={size:#x} type={alloc_type:#x}->{host_type:#x} flags={flags:#x} prot={protect:#x}->{host_protect:#x} err={err}"
            ),
        );
    }
    at
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemAllocatePhysicalPages(
    flags: u64,
    page_count: *mut usize,
    pages_out: *mut usize,
) -> BOOL {
    if page_count.is_null() || pages_out.is_null() {
        return 0;
    }
    let count = unsafe { *page_count };
    if count == 0 {
        return 1;
    }
    let Some(byte_size) = count.checked_mul(PAGE_64K) else {
        unsafe { page_count.write(0) };
        return 0;
    };

    // Reserve-only pagefile section (`SEC_RESERVE`): zero OS commit charged up front so
    // multi-GiB console pools (e.g. 3,977 MiB Series S / 6,236 MiB Series X) always succeed
    // and only commit 64 KiB pages when mapped via `XMemMapPhysicalPages`.
    let handle = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE | SEC_RESERVE,
            ((byte_size as u64) >> 32) as u32,
            byte_size as u32,
            std::ptr::null(),
        )
    };
    if handle.is_null() {
        let err = std::io::Error::last_os_error();
        shim_common::boot_trace(
            "xmem_pc",
            "XMemAllocatePhysicalPages_FAIL",
            &format!("flags={flags:#x} count={count} bytes={byte_size:#x} err={err}"),
        );
        unsafe { page_count.write(0) };
        return 0;
    }

    let section = Arc::new(Section {
        handle,
        pages: count,
        committed: (0..count.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
    });

    let first_page = {
        let mut phys = PHYS_STATE.lock().unwrap_or_else(|e| e.into_inner());
        let first = phys.next_page;
        phys.next_page += count * FRAMES_PER_64K_PAGE;
        phys.pages.reserve(count);
        for index in 0..count {
            phys.pages.insert(
                first + index * FRAMES_PER_64K_PAGE,
                PageSlice {
                    section: Arc::clone(&section),
                    index,
                },
            );
        }
        first
    };

    for index in 0..count {
        unsafe { pages_out.add(index).write(first_page + index * FRAMES_PER_64K_PAGE) };
    }
    METRIC_PHYS_ALLOC.fetch_add(count as u64, Ordering::Relaxed);
    shim_common::boot_trace(
        "xmem_pc",
        "XMemAllocatePhysicalPages",
        &format!(
            "flags={flags:#x} count={count} mib={} first={first_page:#x} ok=1",
            byte_size / MIB
        ),
    );
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemFreePhysicalPages(page_count: usize, pages: *const usize) -> BOOL {
    if page_count == 0 {
        return 1;
    }
    if pages.is_null() {
        return 0;
    }
    let page_ids = unsafe { std::slice::from_raw_parts(pages, page_count) }.to_vec();
    let dropped: Vec<PageSlice> = {
        let mut phys = PHYS_STATE.lock().unwrap_or_else(|e| e.into_inner());
        page_ids
            .iter()
            .filter_map(|p| phys.pages.remove(p))
            .collect()
    };
    let freed = dropped.len() as u64;
    drop(dropped);
    METRIC_PHYS_FREE.fetch_add(freed, Ordering::Relaxed);
    1
}

fn map_view_run(phys: &mut PhysicalState, base: usize, len: usize, first: PageSlice) -> bool {
    let own_hole = phys.holes.remove(&base) == Some(len);
    let offset = (first.index * PAGE_64K) as u64;

    let try_map = || unsafe {
        MapViewOfFile3(
            first.section.handle,
            GetCurrentProcess(),
            base as *const c_void,
            offset,
            len,
            MEM_REPLACE_PLACEHOLDER,
            PAGE_READWRITE,
            std::ptr::null_mut(),
            0,
        )
    };

    let mut view = if own_hole {
        try_map()
    } else {
        MEMORY_MAPPED_VIEW_ADDRESS {
            Value: std::ptr::null_mut(),
        }
    };
    if view.Value as usize != base {
        let _ = unsafe {
            VirtualFree(
                base as *mut c_void,
                len,
                MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
            )
        };
        view = try_map();
    }
    if view.Value as usize != base {
        let err = std::io::Error::last_os_error();
        shim_common::boot_trace(
            "xmem_pc",
            "XMemMapPhysicalPages_FAIL",
            &format!("base={base:#x} len={len:#x} off={offset:#x} err={err}"),
        );
        return false;
    }
    if !first.section.commit_range(first.index, base, len) {
        let _ = unsafe { UnmapViewOfFile2(GetCurrentProcess(), view, MEM_PRESERVE_PLACEHOLDER) };
        return false;
    }
    phys.views.insert(base, (len, first));
    true
}

fn unmap_range(phys: &mut PhysicalState, base: usize, len: usize) {
    if len == 0 {
        return;
    }
    let end = base.saturating_add(len);
    let first_overlap = phys
        .views
        .range(..=base)
        .next_back()
        .filter(|&(at, &(size, _))| *at + size > base)
        .map(|(&at, _)| at);
    let hit: Vec<usize> = first_overlap
        .into_iter()
        .chain(phys.views.range(base + 1..end).map(|(&at, _)| at))
        .collect();

    for at in hit {
        let Some((size, slice)) = phys.views.remove(&at) else {
            continue;
        };
        let gone = unsafe {
            UnmapViewOfFile2(
                GetCurrentProcess(),
                MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: at as *mut c_void,
                },
                MEM_PRESERVE_PLACEHOLDER,
            )
        };
        if gone != 0 && at >= base && at + size <= end {
            phys.holes.insert(at, size);
        }
        if at < base {
            let _ = map_view_run(phys, at, base - at, slice.clone());
        }
        if at + size > end {
            let tail_slice = PageSlice {
                section: slice.section,
                index: slice.index + (end - at) / PAGE_64K,
            };
            let _ = map_view_run(phys, end, at + size - end, tail_slice);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemMapPhysicalPages(
    virtual_address: *mut c_void,
    page_count: usize,
    pages: *const usize,
) -> *mut c_void {
    if virtual_address.is_null() {
        return std::ptr::null_mut();
    }
    if page_count == 0 {
        return virtual_address;
    }
    let call_n = METRIC_PHYS_MAP.fetch_add(1, Ordering::Relaxed) + 1;
    let base = virtual_address as usize;
    let page_ids = (!pages.is_null())
        .then(|| unsafe { std::slice::from_raw_parts(pages, page_count) }.to_vec());

    let mut phys = PHYS_STATE.lock().unwrap_or_else(|e| e.into_inner());
    unmap_range(&mut phys, base, page_count * PAGE_64K);

    let Some(page_ids) = page_ids else {
        return virtual_address;
    };

    let slices: Vec<Option<PageSlice>> = page_ids
        .iter()
        .map(|&pid| {
            if pid == 0 {
                None
            } else {
                phys.pages.get(&pid).cloned()
            }
        })
        .collect();

    let mut i = 0usize;
    let mut runs = 0usize;
    while i < page_count {
        if page_ids[i] == 0 {
            i += 1;
            continue;
        }
        let Some(first) = slices[i].clone() else {
            shim_common::boot_trace(
                "xmem_pc",
                "XMemMapPhysicalPages_UNKNOWN_PAGE",
                &format!("va={base:#x} idx={i} page={:#x}", page_ids[i]),
            );
            return std::ptr::null_mut();
        };
        let run = 1 + slices[i + 1..]
            .iter()
            .zip(1usize..)
            .take_while(|&(sl, k)| {
                sl.as_ref().is_some_and(|s| {
                    Arc::ptr_eq(&s.section, &first.section) && s.index == first.index + k
                })
            })
            .count();
        if !map_view_run(&mut phys, base + i * PAGE_64K, run * PAGE_64K, first) {
            return std::ptr::null_mut();
        }
        runs += 1;
        i += run;
    }
    if call_n <= 16 || page_count >= 64 {
        shim_common::boot_trace(
            "xmem_pc",
            "XMemMapPhysicalPages",
            &format!("#{call_n} va={base:#x} pages={page_count} runs={runs}"),
        );
    }
    virtual_address
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemMapPhysicalPagesScatter(
    addresses: *const *mut c_void,
    page_count: usize,
    pages: *const usize,
) -> BOOL {
    if page_count == 0 {
        return 1;
    }
    if addresses.is_null() {
        return 0;
    }
    let addrs: Vec<usize> = (0..page_count)
        .map(|i| unsafe { *addresses.add(i) } as usize)
        .collect();
    let page_ids: Option<Vec<usize>> = (!pages.is_null())
        .then(|| unsafe { std::slice::from_raw_parts(pages, page_count) }.to_vec());

    METRIC_PHYS_MAP.fetch_add(1, Ordering::Relaxed);
    let mut phys = PHYS_STATE.lock().unwrap_or_else(|e| e.into_inner());
    for (i, &va) in addrs.iter().enumerate() {
        if va == 0 {
            return 0;
        }
        unmap_range(&mut phys, va, PAGE_64K);
        let pid = page_ids.as_ref().map_or(0, |v| v[i]);
        if pid == 0 {
            continue;
        }
        let Some(slice) = phys.pages.get(&pid).cloned() else {
            return 0;
        };
        if !map_view_run(&mut phys, va, PAGE_64K, slice) {
            return 0;
        }
    }
    1
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XMemWorkingSetStatistics {
    pub title_limit: usize,
    pub title_used: usize,
    pub tools_limit: usize,
    pub tools_used: usize,
    pub stack_used: u32,
    pub physical_pages: u32,
    pub gpu_optimal_limit: usize,
    pub gpu_optimal_used: usize,
    pub tools_gpu_optimal_limit: usize,
    pub tools_gpu_optimal_used: usize,
    pub kernel_pool_used: u32,
    pub kernel_pool_limit: u32,
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemGetWorkingSetStatistics(
    which: u32,
    out: *mut XMemWorkingSetStatistics,
) -> BOOL {
    shim_common::boot_trace("xmem_pc", "XMemGetWorkingSetStatistics", &format!("which={which:#x}"));
    if out.is_null() {
        return 0;
    }
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };

    let mut mem_status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe { GlobalMemoryStatusEx(&mut mem_status) };

    let total_budget = (DEFAULT_GPU_OPTIMAL_BUDGET + DEFAULT_STANDARD_BUDGET)
        .min(mem_status.ullTotalPhys as usize)
        .saturating_sub(TRANSFERRED_BYTES.load(Ordering::Relaxed));

    let stats = XMemWorkingSetStatistics {
        title_limit: total_budget,
        title_used: counters.PagefileUsage,
        gpu_optimal_limit: DEFAULT_GPU_OPTIMAL_BUDGET.min(total_budget),
        physical_pages: METRIC_PHYS_ALLOC.load(Ordering::Relaxed) as u32,
        ..Default::default()
    };
    unsafe { out.write(stats) };
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemIsToolsMemAvailable() -> BOOL {
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn XMemTransferMemory(kind: u32, size: usize) -> BOOL {
    const TITLE_TO_SYSTEM: u32 = 0;
    if size == 0 {
        return 1;
    }
    let Some(aligned) = size.checked_next_multiple_of(2 * MIB) else {
        return 0;
    };
    if kind != TITLE_TO_SYSTEM {
        return 0;
    }
    TRANSFERRED_BYTES
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            cur.checked_add(aligned)
                .filter(|&next| next <= DEFAULT_STANDARD_BUDGET)
        })
        .is_ok() as BOOL
}

#[unsafe(no_mangle)]
pub extern "system" fn PcXMemGetMetrics(out: *mut XMemPcMetrics) -> BOOL {
    if out.is_null() {
        return 0;
    }
    let metrics = XMemPcMetrics {
        alloc_calls: METRIC_ALLOC_CALLS.load(Ordering::Relaxed),
        free_calls: METRIC_FREE_CALLS.load(Ordering::Relaxed),
        live_bytes: METRIC_LIVE_BYTES.load(Ordering::Relaxed),
        peak_bytes: METRIC_PEAK_BYTES.load(Ordering::Relaxed),
        virtual_alloc_calls: METRIC_VALLOC_CALLS.load(Ordering::Relaxed),
        physical_pages_allocated: METRIC_PHYS_ALLOC.load(Ordering::Relaxed),
        physical_pages_freed: METRIC_PHYS_FREE.load(Ordering::Relaxed),
        physical_map_calls: METRIC_PHYS_MAP.load(Ordering::Relaxed),
        transferred_bytes: TRANSFERRED_BYTES.load(Ordering::Relaxed) as u64,
    };
    unsafe { out.write(metrics) };
    1
}

/// Writes `len` bytes from `data` into physical pages `pages` starting at byte `offset`
/// (used by `xcrd_pc.dll` for Scarlett `DSTORAGE_REQUEST_DESTINATION_MULTIPLE_PAGES`).
#[unsafe(no_mangle)]
pub extern "system" fn PcXMemWritePhysicalPages(
    pages: *const usize,
    page_count: usize,
    offset: usize,
    data: *const u8,
    len: usize,
) -> BOOL {
    if len == 0 {
        return 1;
    }
    if pages.is_null() || data.is_null() {
        return 0;
    }
    let Some(end) = offset.checked_add(len) else {
        return 0;
    };
    let first_page_idx = offset / PAGE_64K;
    let last_page_idx = end.div_ceil(PAGE_64K);
    if last_page_idx > page_count {
        return 0;
    }
    let page_ids = unsafe { std::slice::from_raw_parts(pages.add(first_page_idx), last_page_idx - first_page_idx) };

    // Resolve runs of consecutive slices within each section under the lock.
    let mut runs: Vec<(PageSlice, usize)> = Vec::new();
    {
        let phys = PHYS_STATE.lock().unwrap_or_else(|e| e.into_inner());
        for &pid in page_ids {
            let Some(slice) = phys.pages.get(&pid) else {
                return 0;
            };
            match runs.last_mut() {
                Some((first, n))
                    if Arc::ptr_eq(&first.section, &slice.section)
                        && slice.index == first.index + *n =>
                {
                    *n += 1;
                }
                _ => runs.push((slice.clone(), 1)),
            }
        }
    }

    let src = unsafe { std::slice::from_raw_parts(data, len) };
    let mut within = offset % PAGE_64K;
    let mut done = 0usize;
    for (first, n) in runs {
        let run_bytes = n * PAGE_64K;
        let file_off = (first.index * PAGE_64K) as u64;
        let view = unsafe {
            MapViewOfFile(
                first.section.handle,
                FILE_MAP_WRITE,
                (file_off >> 32) as u32,
                file_off as u32,
                run_bytes,
            )
        };
        if view.Value.is_null() {
            return 0;
        }
        let ok = first
            .section
            .commit_range(first.index, view.Value as usize, run_bytes);
        if !ok {
            unsafe { UnmapViewOfFile(view) };
            return 0;
        }
        let copy_len = (run_bytes - within).min(len - done);
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr().add(done),
                view.Value.cast::<u8>().add(within),
                copy_len,
            );
            UnmapViewOfFile(view);
        }
        done += copy_len;
        within = 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_set_struct_matches_console_abi() {
        assert_eq!(size_of::<XMemWorkingSetStatistics>(), 0x50);
        assert_eq!(
            std::mem::offset_of!(XMemWorkingSetStatistics, gpu_optimal_limit),
            0x28
        );
    }

    #[test]
    fn alloc_free_and_metrics_track_alignment() {
        let mut before = XMemPcMetrics::default();
        assert_eq!(PcXMemGetMetrics(&mut before), 1);

        let attrs_64k = 16u64 << ALIGNMENT_SHIFT;
        let p = XMemAlloc(4096, attrs_64k);
        assert!(!p.is_null());
        assert_eq!((p as usize) % (64 * 1024), 0);
        unsafe { p.cast::<u8>().write_bytes(0x5A, 4096) };

        let p32 = XMemAlloc(1024, ALLOC_32BIT);
        assert!(!p32.is_null());
        assert!((p32 as usize) <= u32::MAX as usize);

        let mut mid = XMemPcMetrics::default();
        assert_eq!(PcXMemGetMetrics(&mut mid), 1);
        assert!(mid.alloc_calls >= before.alloc_calls + 2);
        assert!(mid.live_bytes >= 5120);

        XMemFree(p, attrs_64k);
        XMemFree(p32, ALLOC_32BIT);
    }

    #[test]
    fn physical_pages_allocate_map_and_free() {
        let mut pages = [0usize; 2];
        let mut count = 2usize;
        assert_eq!(XMemAllocatePhysicalPages(0, &mut count, pages.as_mut_ptr()), 1);
        assert_eq!(count, 2);
        assert_ne!(pages[0], 0);
        assert_ne!(pages[1], 0);

        let va = XMemVirtualAlloc(
            std::ptr::null_mut(),
            2 * PAGE_64K,
            MEM_RESERVE | PAGES_64K,
            0,
            PAGE_READWRITE,
        );
        assert!(!va.is_null());
        assert_eq!(XMemMapPhysicalPages(va, 2, pages.as_ptr()), va);

        unsafe {
            va.cast::<u8>().write(0x7F);
            assert_eq!(va.cast::<u8>().read(), 0x7F);
        }

        assert_eq!(XMemMapPhysicalPages(va, 2, std::ptr::null()), va);
        unsafe { VirtualFree(va, 0, MEM_RELEASE) };
        assert_eq!(XMemFreePhysicalPages(2, pages.as_ptr()), 1);
    }

    #[test]
    fn large_series_s_physical_pool_reserves_lazily_and_maps_runs() {
        // 63,632 * 64 KiB = 3,977 MiB (exact Series S main GPU pool) — must succeed with SEC_RESERVE
        // without committing 4 GiB up front, and return BOOL TRUE (1) with *count unchanged.
        const SERIES_S_PAGES: usize = 63_632;
        let mut pages = vec![0usize; SERIES_S_PAGES];
        let mut count = SERIES_S_PAGES;
        assert_eq!(
            XMemAllocatePhysicalPages(0x380, &mut count, pages.as_mut_ptr()),
            1
        );
        assert_eq!(count, SERIES_S_PAGES);
        assert_ne!(pages[0], 0);
        assert_eq!(pages[0] % FRAMES_PER_64K_PAGE, 0);
        assert_eq!(
            pages[SERIES_S_PAGES - 1],
            pages[0] + (SERIES_S_PAGES - 1) * FRAMES_PER_64K_PAGE
        );

        // Map a 16-page (1 MiB) contiguous run into a placeholder VA, verify R/W, split-unmap middle, and free.
        let map_n = 16usize;
        let va = XMemVirtualAlloc(
            std::ptr::null_mut(),
            map_n * PAGE_64K,
            0x2040_2000, // MEM_RESERVE | PAGES_64K
            0x23,
            0x2004,
        );
        assert!(!va.is_null());
        assert_eq!(XMemMapPhysicalPages(va, map_n, pages.as_ptr()), va);
        unsafe {
            va.cast::<u8>().write(0xA5);
            va.cast::<u8>().add((map_n - 1) * PAGE_64K).write(0x5A);
            assert_eq!(va.cast::<u8>().read(), 0xA5);
            assert_eq!(va.cast::<u8>().add((map_n - 1) * PAGE_64K).read(), 0x5A);
        }

        // Unmap middle 4 pages (splits the 16-page view cleanly while keeping head & tail alive)
        let mid_va = unsafe { va.cast::<u8>().add(4 * PAGE_64K).cast::<c_void>() };
        assert_eq!(XMemMapPhysicalPages(mid_va, 4, std::ptr::null()), mid_va);
        unsafe {
            assert_eq!(va.cast::<u8>().read(), 0xA5);
            assert_eq!(va.cast::<u8>().add((map_n - 1) * PAGE_64K).read(), 0x5A);
        }

        // Unmap whole range and free all physical pages
        assert_eq!(XMemMapPhysicalPages(va, map_n, std::ptr::null()), va);
        unsafe { VirtualFree(va, 0, MEM_RELEASE) };
        assert_eq!(XMemFreePhysicalPages(SERIES_S_PAGES, pages.as_ptr()), 1);
    }
}
