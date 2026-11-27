#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::alloc::Layout;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use shim_common::{E_INVALIDARG, E_OUTOFMEMORY, E_POINTER, HRESULT, S_OK};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

const PENDING_RESULTS: HRESULT = 0x8AC8_1001_u32 as i32;
const APU_BASE: u32 = 0x0001_0000;

static START_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

struct ApuBlock {
    size: usize,
    apu: u32,
    layout: Layout,
}

struct ApuHeap {
    pool_limit: usize,
    pool_used: usize,
    blocks: BTreeMap<usize, ApuBlock>,
    by_apu: BTreeMap<u32, usize>,
    next_apu: u32,
}

static APU_HEAP: LazyLock<Mutex<ApuHeap>> = LazyLock::new(|| {
    Mutex::new(ApuHeap {
        pool_limit: 512 * 1024 * 1024,
        pool_used: 0,
        blocks: BTreeMap::new(),
        by_apu: BTreeMap::new(),
        next_apu: APU_BASE,
    })
});

pub fn apu_heap_usage() -> (usize, usize, usize) {
    let heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    (heap.pool_used, 0, heap.blocks.len())
}

// ---- AcpHal / APU exports (9) ----

#[unsafe(no_mangle)]
pub extern "system" fn ApuCreateHeap(cached_size: u32, non_cached_size: u32) -> HRESULT {
    let mut heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    let combined = (cached_size as usize)
        .saturating_add(non_cached_size as usize)
        .max(512 * 1024 * 1024);
    heap.pool_limit = combined;
    shim_common::boot_trace(
        "audio_pc",
        "ApuCreateHeap",
        &format!("cached={cached_size:#x} non_cached={non_cached_size:#x} pool_limit={combined:#x}"),
    );
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn ApuAlloc(
    virtual_address: *mut *mut c_void,
    apu_address: *mut u32,
    size_in_bytes: u32,
    alignment_in_bytes: u32,
) -> HRESULT {
    if virtual_address.is_null() {
        return E_POINTER;
    }
    let align = (alignment_in_bytes as usize).max(16).next_power_of_two();
    let size = (size_in_bytes as usize).max(1);
    let Ok(layout) = Layout::from_size_align(size, align) else {
        return E_INVALIDARG;
    };

    let mut heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    if heap.pool_used.saturating_add(size) > heap.pool_limit {
        return E_OUTOFMEMORY;
    }

    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return E_OUTOFMEMORY;
    }

    let apu = (heap.next_apu.wrapping_add(align as u32 - 1)) & !(align as u32 - 1);
    heap.next_apu = apu.saturating_add(size_in_bytes.max(16));
    heap.pool_used = heap.pool_used.saturating_add(size);
    heap.blocks.insert(
        ptr as usize,
        ApuBlock {
            size,
            apu,
            layout,
        },
    );
    heap.by_apu.insert(apu, ptr as usize);
    unsafe {
        *virtual_address = ptr.cast();
        if !apu_address.is_null() {
            *apu_address = apu;
        }
    }
    static ALLOC_LOGS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = ALLOC_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        shim_common::boot_trace(
            "audio_pc",
            "ApuAlloc",
            &format!("#{n} size={size_in_bytes:#x} align={align:#x} va={ptr:?} apu={apu:#x}"),
        );
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn ApuFree(virtual_address: *mut c_void) -> HRESULT {
    if virtual_address.is_null() {
        return S_OK;
    }
    let mut heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(blk) = heap.blocks.remove(&(virtual_address as usize)) {
        heap.by_apu.remove(&blk.apu);
        heap.pool_used = heap.pool_used.saturating_sub(blk.size);
        unsafe { std::alloc::dealloc(virtual_address.cast(), blk.layout) };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn ApuIsVirtualAddressValid(
    virtual_address: *const c_void,
    physical_alignment: u32,
) -> i32 {
    let addr = virtual_address as usize;
    if physical_alignment > 0
        && physical_alignment.is_power_of_two()
        && !addr.is_multiple_of(physical_alignment as usize)
    {
        return 0;
    }
    let heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    heap.blocks
        .range(..=addr)
        .next_back()
        .is_some_and(|(&base, blk)| addr < base + blk.size) as i32
}

#[unsafe(no_mangle)]
pub extern "system" fn ApuMapVirtualAddress(virtual_address: *const c_void) -> u32 {
    let addr = virtual_address as usize;
    let heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((&base, blk)) = heap.blocks.range(..=addr).next_back() {
        if addr < base + blk.size {
            return blk.apu + (addr - base) as u32;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn ApuMapApuAddress(apu_address: u32) -> *mut c_void {
    let heap = APU_HEAP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((&apu_base, &host_base)) = heap.by_apu.range(..=apu_address).next_back() {
        if let Some(blk) = heap.blocks.get(&host_base) {
            let off = (apu_address - apu_base) as usize;
            if off < blk.size {
                return (host_base + off) as *mut c_void;
            }
        }
    }
    std::ptr::null_mut()
}

/// Xbox GDK `APU_SHAPE_CONTEXTS` (`acphal.h`) layout passed to
/// `AcpHalAllocateShapeContexts` / `AcpHalReleaseShapeContexts`.
#[repr(C)]
pub struct ShapeContexts {
    pub num_src_contexts: u32,
    pub num_eq_contexts: u32,
    pub num_filt_contexts: u32,
    pub num_dma_contexts: u32,
    pub num_xma_contexts: u32,
    pub num_pcm_contexts: u32,
    pub src_context_array: *mut c_void,
    pub eq_context_array: *mut c_void,
    pub filt_context_array: *mut c_void,
    pub dma_context_array: *mut c_void,
    pub xma_context_array: *mut c_void,
    pub pcm_context_array: *mut c_void,
}

const SHAPE_CONTEXT_BYTES: [usize; 6] = [256, 256, 256, 256, 64, 64];

static SHAPE_CONTEXT_ALLOCS: LazyLock<Mutex<BTreeMap<usize, Layout>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

const S_FALSE: HRESULT = 1;

#[repr(C)]
pub struct AcpHalObject {
    pub vtable: *const [*const c_void; 16],
    pub id: u64,
}

pub type AcpHalInstance = AcpHalObject;

#[repr(transparent)]
struct AcpHalVtable([*const c_void; 16]);
unsafe impl Sync for AcpHalVtable {}

extern "system" fn acp_hal_connect(
    this: *mut AcpHalObject,
    cmd_len: u32,
    msg_len: u32,
) -> HRESULT {
    let id = unsafe { this.as_ref() }.map_or(0, |o| o.id);
    shim_common::boot_trace(
        "audio_pc",
        "IAcpHal::Connect",
        &format!("id={id} cmd_len={cmd_len:#x} msg_len={msg_len:#x}"),
    );
    S_OK
}

extern "system" fn acp_hal_disconnect(this: *mut AcpHalObject) -> HRESULT {
    let id = unsafe { this.as_ref() }.map_or(0, |o| o.id);
    shim_common::boot_trace("audio_pc", "IAcpHal::Disconnect", &format!("id={id}"));
    S_OK
}

extern "system" fn acp_hal_submit_command(
    this: *mut AcpHalObject,
    cmd_type: u32,
    cmd_id: u32,
    flags: u32,
    data: *const c_void,
) -> HRESULT {
    static SUBMIT_LOGS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = SUBMIT_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        let id = unsafe { this.as_ref() }.map_or(0, |o| o.id);
        shim_common::boot_trace(
            "audio_pc",
            "IAcpHal::SubmitCommand",
            &format!("#{n} id={id} type={cmd_type:#x} cmd_id={cmd_id:#x} flags={flags:#x} data={data:?}"),
        );
    }
    S_OK
}

extern "system" fn acp_hal_pop_message(
    this: *mut AcpHalObject,
    msg: *mut c_void,
) -> HRESULT {
    static POP_LOGS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = POP_LOGS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 16 {
        let id = unsafe { this.as_ref() }.map_or(0, |o| o.id);
        shim_common::boot_trace(
            "audio_pc",
            "IAcpHal::PopMessage",
            &format!("#{n} id={id} msg={msg:?} -> S_FALSE"),
        );
    }
    S_FALSE
}

extern "system" fn acp_hal_slot<const SLOT: usize>(this: *mut AcpHalObject) -> HRESULT {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO_U32: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static SLOT_LOGS: [std::sync::atomic::AtomicU32; 16] = [ZERO_U32; 16];
    let n = SLOT_LOGS[SLOT.min(15)].fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 {
        let id = unsafe { this.as_ref() }.map_or(0, |o| o.id);
        shim_common::boot_trace(
            "audio_pc",
            "IAcpHal::slot",
            &format!("#{n} id={id} slot={SLOT}"),
        );
    }
    S_OK
}

static ACP_HAL_VTABLE: AcpHalVtable = AcpHalVtable([
    acp_hal_connect as *const c_void,
    acp_hal_disconnect as *const c_void,
    acp_hal_submit_command as *const c_void,
    acp_hal_pop_message as *const c_void,
    acp_hal_slot::<4> as *const c_void,
    acp_hal_slot::<5> as *const c_void,
    acp_hal_slot::<6> as *const c_void,
    acp_hal_slot::<7> as *const c_void,
    acp_hal_slot::<8> as *const c_void,
    acp_hal_slot::<9> as *const c_void,
    acp_hal_slot::<10> as *const c_void,
    acp_hal_slot::<11> as *const c_void,
    acp_hal_slot::<12> as *const c_void,
    acp_hal_slot::<13> as *const c_void,
    acp_hal_slot::<14> as *const c_void,
    acp_hal_slot::<15> as *const c_void,
]);

static NEXT_ACPHAL_ID: AtomicU64 = AtomicU64::new(1);

#[unsafe(no_mangle)]
pub extern "system" fn AcpHalCreate(out: *mut *mut AcpHalObject) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let id = NEXT_ACPHAL_ID.fetch_add(1, Ordering::Relaxed);
    let inst = Box::new(AcpHalObject {
        vtable: &raw const ACP_HAL_VTABLE.0,
        id,
    });
    unsafe { *out = Box::into_raw(inst) };
    shim_common::boot_trace("audio_pc", "AcpHalCreate", &format!("id={id}"));
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn AcpHalAllocateShapeContexts(context_data: *mut ShapeContexts) -> HRESULT {
    let Some(sc) = (unsafe { context_data.as_mut() }) else {
        return E_INVALIDARG;
    };
    let counts = [
        sc.num_src_contexts,
        sc.num_eq_contexts,
        sc.num_filt_contexts,
        sc.num_dma_contexts,
        sc.num_xma_contexts,
        sc.num_pcm_contexts,
    ];
    let mut ptrs = [std::ptr::null_mut::<c_void>(); 6];
    let mut allocs = Vec::new();
    for i in 0..6 {
        let count = counts[i] as usize;
        if count == 0 {
            continue;
        }
        let Some(bytes) = count.checked_mul(SHAPE_CONTEXT_BYTES[i]) else {
            for (p, l) in allocs {
                unsafe { std::alloc::dealloc(p, l) };
            }
            return E_INVALIDARG;
        };
        let Ok(layout) = Layout::from_size_align(bytes, 64) else {
            for (p, l) in allocs {
                unsafe { std::alloc::dealloc(p, l) };
            }
            return E_INVALIDARG;
        };
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            for (p, l) in allocs {
                unsafe { std::alloc::dealloc(p, l) };
            }
            return E_OUTOFMEMORY;
        }
        ptrs[i] = ptr.cast();
        allocs.push((ptr, layout));
    }
    {
        let mut tracked = SHAPE_CONTEXT_ALLOCS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (ptr, layout) in allocs {
            tracked.insert(ptr as usize, layout);
        }
    }
    sc.src_context_array = ptrs[0];
    sc.eq_context_array = ptrs[1];
    sc.filt_context_array = ptrs[2];
    sc.dma_context_array = ptrs[3];
    sc.xma_context_array = ptrs[4];
    sc.pcm_context_array = ptrs[5];
    shim_common::boot_trace(
        "audio_pc",
        "AcpHalAllocateShapeContexts",
        &format!(
            "counts={counts:?} ptrs=[{:?},{:?},{:?},{:?},{:?},{:?}]",
            ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4], ptrs[5]
        ),
    );
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn AcpHalReleaseShapeContexts(context_data: *mut ShapeContexts) -> HRESULT {
    let Some(sc) = (unsafe { context_data.as_mut() }) else {
        return E_INVALIDARG;
    };
    let fields = [
        &mut sc.src_context_array,
        &mut sc.eq_context_array,
        &mut sc.filt_context_array,
        &mut sc.dma_context_array,
        &mut sc.xma_context_array,
        &mut sc.pcm_context_array,
    ];
    let mut tracked = SHAPE_CONTEXT_ALLOCS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for field in fields {
        let addr = (*field) as usize;
        if addr != 0 {
            if let Some(layout) = tracked.remove(&addr) {
                unsafe { std::alloc::dealloc(addr as *mut u8, layout) };
            }
            *field = std::ptr::null_mut();
        }
    }
    S_OK
}

// ---- XApu exports (5) ----

#[repr(C)]
pub struct XApuConnectInput {
    pub process: u32,
    pub streams: u32,
    pub commands_per_stream: u32,
    pub memory: u32,
    pub frames_per_output: u32,
    pub options: u32,
}

#[repr(C)]
pub struct XApuConnectOutput {
    pub memory: *mut c_void,
    pub result_event: HANDLE,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct XApuCommandId {
    pub kind: u32,
    pub stream: u32,
    pub sequence: u32,
    pub options: u32,
    pub context: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct XApuResult {
    pub id: XApuCommandId,
    pub state: u32,
    pub state_data: u64,
    pub usec: u64,
    pub error: HRESULT,
    pub frames: u32,
    pub output_length: u32,
    pub output: *mut u8,
    pub pitch: f32,
    pub input_length: u32,
    pub input: *const u8,
}

unsafe impl Send for XApuResult {}

struct XApuRingState {
    capacity: usize,
    head: usize,
    tail: usize,
    queue: VecDeque<XApuResult>,
}

pub struct XApuConnection {
    memory: *mut u8,
    mem_size: usize,
    layout: Layout,
    frames_per_output: u32,
    event: HANDLE,
    ring: Mutex<XApuRingState>,
}

unsafe impl Send for XApuConnection {}

#[unsafe(no_mangle)]
pub extern "system" fn XApuConnect(
    input: *const XApuConnectInput,
    output: *mut XApuConnectOutput,
    handle: *mut *mut XApuConnection,
) -> HRESULT {
    if input.is_null() || output.is_null() || handle.is_null() {
        return E_INVALIDARG;
    }
    let inp = unsafe { &*input };
    let mem_size = (inp.memory as usize).max(4096);
    let Ok(layout) = Layout::from_size_align(mem_size, 16) else {
        return E_INVALIDARG;
    };
    let memory = unsafe { std::alloc::alloc_zeroed(layout) };
    if memory.is_null() {
        return E_OUTOFMEMORY;
    }
    let ring_capacity = (inp.streams.max(1) as usize)
        .saturating_mul(inp.commands_per_stream.max(16) as usize)
        .clamp(64, 4096);
    let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    let conn = Box::new(XApuConnection {
        memory,
        mem_size,
        layout,
        frames_per_output: inp.frames_per_output.max(256),
        event,
        ring: Mutex::new(XApuRingState {
            capacity: ring_capacity,
            head: 0,
            tail: 0,
            queue: VecDeque::with_capacity(ring_capacity),
        }),
    });
    unsafe {
        (*output).memory = memory.cast();
        (*output).result_event = event;
        *handle = Box::into_raw(conn);
    }
    shim_common::boot_trace(
        "audio_pc",
        "XApuConnect",
        &format!("streams={} mem={mem_size:#x}", inp.streams),
    );
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XApuDisconnect(conn: *mut XApuConnection) -> HRESULT {
    if conn.is_null() {
        return E_INVALIDARG;
    }
    let c = unsafe { Box::from_raw(conn) };
    if !c.event.is_null() {
        unsafe { CloseHandle(c.event) };
    }
    unsafe { std::alloc::dealloc(c.memory, c.layout) };
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XApuEnqueueCommand(
    conn: *mut XApuConnection,
    cmd: *const XApuCommandId,
) -> HRESULT {
    if conn.is_null() || cmd.is_null() {
        return E_INVALIDARG;
    }
    let c = unsafe { &*conn };
    let id = unsafe { *cmd };
    let mut ring = c.ring.lock().unwrap_or_else(|e| e.into_inner());
    if ring.queue.len() >= ring.capacity {
        ring.queue.pop_front();
        ring.tail = (ring.tail + 1) % ring.capacity;
    }
    let slot_off = (ring.head * 64) % c.mem_size;
    let output_ptr = unsafe { c.memory.add(slot_off) };
    ring.head = (ring.head + 1) % ring.capacity;

    let res = XApuResult {
        id,
        state: 1,
        state_data: 0,
        usec: START_TIME.elapsed().as_micros() as u64,
        error: S_OK,
        frames: c.frames_per_output,
        output_length: 0,
        output: output_ptr,
        pitch: 1.0,
        input_length: 0,
        input: std::ptr::null(),
    };
    ring.queue.push_back(res);
    if !c.event.is_null() {
        unsafe { SetEvent(c.event) };
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XApuGetResultCount(conn: *mut XApuConnection, count: *mut u32) -> HRESULT {
    if conn.is_null() || count.is_null() {
        return E_INVALIDARG;
    }
    let c = unsafe { &*conn };
    let n = c.ring.lock().unwrap_or_else(|e| e.into_inner()).queue.len() as u32;
    unsafe { *count = n };
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XApuDequeueResult(
    conn: *mut XApuConnection,
    out: *mut XApuResult,
) -> HRESULT {
    if conn.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    let c = unsafe { &*conn };
    let mut ring = c.ring.lock().unwrap_or_else(|e| e.into_inner());
    let Some(res) = ring.queue.pop_front() else {
        return PENDING_RESULTS;
    };
    ring.tail = (ring.tail + 1) % ring.capacity;
    unsafe { out.write(res) };
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xapu_ring_and_acphal_heap_work() {
        assert_eq!(std::mem::offset_of!(ShapeContexts, num_xma_contexts), 0x10);
        assert_eq!(std::mem::offset_of!(ShapeContexts, xma_context_array), 0x38);
        assert_eq!(std::mem::offset_of!(ShapeContexts, pcm_context_array), 0x40);

        assert_eq!(ApuCreateHeap(0x0ff0_0000, 0x22_6e00), S_OK);
        let mut apu_va = std::ptr::null_mut();
        let mut apu_addr = 0u32;
        assert_eq!(ApuAlloc(&mut apu_va, &mut apu_addr, 4096, 64), S_OK);
        assert!(!apu_va.is_null() && apu_addr != 0);
        assert_eq!(ApuMapVirtualAddress(apu_va), apu_addr);
        assert_eq!(ApuMapApuAddress(apu_addr), apu_va);
        assert_eq!(ApuFree(apu_va), S_OK);

        assert_eq!(std::mem::offset_of!(AcpHalObject, vtable), 0);
        let mut hal = std::ptr::null_mut();
        assert_eq!(AcpHalCreate(&mut hal), S_OK);
        assert!(!hal.is_null() && unsafe { (&*hal).id } > 0);
        unsafe {
            let vtbl = *(&*hal).vtable;
            type ConnectFn = unsafe extern "system" fn(*mut AcpHalObject, u32, u32) -> HRESULT;
            type DisconnectFn = unsafe extern "system" fn(*mut AcpHalObject) -> HRESULT;
            type SubmitFn =
                unsafe extern "system" fn(*mut AcpHalObject, u32, u32, u32, *const c_void) -> HRESULT;
            type PopFn = unsafe extern "system" fn(*mut AcpHalObject, *mut c_void) -> HRESULT;
            let connect: ConnectFn = std::mem::transmute(vtbl[0]);
            let disconnect: DisconnectFn = std::mem::transmute(vtbl[1]);
            let submit: SubmitFn = std::mem::transmute(vtbl[2]);
            let pop: PopFn = std::mem::transmute(vtbl[3]);
            assert_eq!(connect(hal, 0x1000, 0x1000), S_OK);
            assert_eq!(submit(hal, 1, 2, 0, std::ptr::null()), S_OK);
            assert_eq!(pop(hal, std::ptr::null_mut()), S_FALSE);
            assert_eq!(disconnect(hal), S_OK);
        }
        drop(unsafe { Box::from_raw(hal) });

        let mut sc = ShapeContexts {
            num_src_contexts: 2,
            num_eq_contexts: 0,
            num_filt_contexts: 1,
            num_dma_contexts: 0,
            num_xma_contexts: 0x15e,
            num_pcm_contexts: 4,
            src_context_array: std::ptr::null_mut(),
            eq_context_array: std::ptr::null_mut(),
            filt_context_array: std::ptr::null_mut(),
            dma_context_array: std::ptr::null_mut(),
            xma_context_array: std::ptr::null_mut(),
            pcm_context_array: std::ptr::null_mut(),
        };
        assert_eq!(AcpHalAllocateShapeContexts(&raw mut sc), S_OK);
        assert!(!sc.src_context_array.is_null());
        assert!(sc.eq_context_array.is_null());
        assert!(!sc.filt_context_array.is_null());
        assert!(sc.dma_context_array.is_null());
        assert!(!sc.xma_context_array.is_null());
        assert!(!sc.pcm_context_array.is_null());
        assert_eq!((sc.xma_context_array as usize) % 64, 0);
        unsafe { std::ptr::write_bytes(sc.xma_context_array.cast::<u8>(), 0xAB, 0x15e * 64) };
        assert_eq!(AcpHalReleaseShapeContexts(&raw mut sc), S_OK);
        assert!(sc.src_context_array.is_null());
        assert!(sc.xma_context_array.is_null());
        assert!(sc.pcm_context_array.is_null());

        let inp = XApuConnectInput {
            process: 1,
            streams: 4,
            commands_per_stream: 16,
            memory: 16384,
            frames_per_output: 512,
            options: 0,
        };
        let mut out = XApuConnectOutput {
            memory: std::ptr::null_mut(),
            result_event: std::ptr::null_mut(),
        };
        let mut conn = std::ptr::null_mut();
        assert_eq!(XApuConnect(&inp, &mut out, &mut conn), S_OK);

        let cmd = XApuCommandId {
            kind: 1,
            stream: 0,
            sequence: 7,
            options: 0,
            context: 0xDEAD_BEEF,
        };
        assert_eq!(XApuEnqueueCommand(conn, &cmd), S_OK);
        let mut cnt = 0u32;
        assert_eq!(XApuGetResultCount(conn, &mut cnt), S_OK);
        assert_eq!(cnt, 1);

        let mut res: XApuResult = unsafe { std::mem::zeroed() };
        assert_eq!(XApuDequeueResult(conn, &mut res), S_OK);
        let seq = res.id.sequence;
        let frames = res.frames;
        assert_eq!(seq, 7);
        assert_eq!(frames, 512);
        assert_eq!(XApuDisconnect(conn), S_OK);
    }
}
