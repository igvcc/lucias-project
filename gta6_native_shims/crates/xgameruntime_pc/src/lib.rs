#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, VecDeque};
use std::ffi::{CStr, c_char, c_void};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use shim_common::{
    E_FAIL, E_INVALIDARG, E_NOTIMPL, E_POINTER, Guid, HRESULT, S_OK, boot_trace, boot_trace_hr,
};

const NOT_SUPPORTED: HRESULT = 0x8007_0032_u32 as i32; // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)
const E_PENDING: HRESULT = 0x8000_000A_u32 as i32;
const E_ABORT: HRESULT = 0x8000_4004_u32 as i32;
const E_NOT_SUFFICIENT_BUFFER: HRESULT = 0x8007_007A_u32 as i32;
const ERROR_NETWORK_UNREACHABLE: HRESULT = 0x8007_04CF_u32 as i32;
const XSTORE_NETWORK_ERROR: HRESULT = 0x8924_5301_u32 as i32;
const BLOB_NOT_FOUND: HRESULT = 0x8083_0008_u32 as i32;

const LOCAL_QUOTA_BYTES: u64 = 256 * 1024 * 1024;
const TITLE_ID: u32 = 0x5454_086A; // GTA VI Scarlett title ID placeholder

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static INIT_VERSION: AtomicU64 = AtomicU64::new(0);
static INIT_BUILD: AtomicU64 = AtomicU64::new(0);
static INIT_FLAGS: AtomicU64 = AtomicU64::new(0);
static ERROR_REPORT_COUNT: AtomicU32 = AtomicU32::new(0);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Returns `%LOCALAPPDATA%\LUCIAS_PROJECT\` (or `LUCIAS_PROJECT_DATA_DIR` / legacy `GTA6_PC_DATA_DIR` when overridden for tests).
pub fn data_root() -> PathBuf {
    for key in ["LUCIAS_PROJECT_DATA_DIR", "GTA6_PC_DATA_DIR"] {
        if let Ok(custom) = std::env::var(key) {
            if !custom.trim().is_empty() {
                return PathBuf::from(custom);
            }
        }
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        if !local.trim().is_empty() {
            return PathBuf::from(local).join("LUCIAS_PROJECT");
        }
    }
    std::env::temp_dir().join("LUCIAS_PROJECT")
}

fn ensure_data_dirs() -> PathBuf {
    let root = data_root();
    let _ = fs::create_dir_all(root.join("storage"));
    let _ = fs::create_dir_all(root.join("saves"));
    root
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn error_report_count() -> u32 {
    ERROR_REPORT_COUNT.load(Ordering::Relaxed)
}

#[repr(C)]
pub struct RuntimeObject {
    vtable: *const *const c_void,
    area: &'static str,
}

unsafe impl Sync for RuntimeObject {}

pub struct Vtable<const N: usize>(pub [*const c_void; N]);
unsafe impl<const N: usize> Sync for Vtable<N> {}

type This = *const RuntimeObject;

extern "system" fn obj_add_ref(_: This) -> u32 {
    1
}

extern "system" fn obj_release(_: This) -> u32 {
    1
}

extern "system" fn obj_missing<const SLOT: usize>(this: This) -> HRESULT {
    let area = unsafe { &*this }.area;
    boot_trace(
        "xgameruntime",
        "UNIMPL_SLOT",
        &format!("area={area} slot={SLOT} (+{:#x})", SLOT * 8),
    );
    E_NOTIMPL
}

const fn fill_missing<const N: usize>() -> [*const c_void; N] {
    let mut t = [std::ptr::null(); N];
    macro_rules! assign {
        ($($i:expr),*) => {
            $(
                if $i < N {
                    t[$i] = obj_missing::<$i> as *const c_void;
                }
            )*
        };
    }
    assign!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79
    );
    t[1] = obj_add_ref as *const c_void;
    t[2] = obj_release as *const c_void;
    t
}

fn put<T>(out: *mut T, val: T) -> HRESULT {
    if out.is_null() {
        return E_INVALIDARG;
    }
    unsafe { out.write(val) };
    S_OK
}

fn put_string(text: &str, size: usize, buf: *mut u8, used: *mut usize) -> HRESULT {
    let needed = text.len() + 1;
    if buf.is_null() || size < needed {
        return E_NOT_SUFFICIENT_BUFFER;
    }
    unsafe {
        buf.copy_from_nonoverlapping(text.as_ptr(), text.len());
        buf.add(text.len()).write(0);
    }
    if !used.is_null() {
        unsafe { used.write(needed) };
    }
    S_OK
}

fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
    }
}

// ============================================================================
// 1. XThreading / XAsync / XTaskQueue (`073b7dcb-1fcf-4030-94be-e3c9eb623428`)
// ============================================================================

const PROVIDER_XTHREADING: Guid = Guid::new(
    0x073b_7dcb,
    0x1fcf,
    0x4030,
    [0x94, 0xbe, 0xe3, 0xc9, 0xeb, 0x62, 0x34, 0x28],
);

#[repr(C)]
pub struct XAsyncBlock {
    pub queue: *const c_void,
    pub context: *mut c_void,
    pub callback: Option<extern "system" fn(*mut XAsyncBlock)>,
    pub internal: [u64; 4],
}

#[repr(C)]
pub struct XAsyncProviderData {
    pub block: *mut XAsyncBlock,
    pub buffer_size: usize,
    pub buffer: *mut c_void,
    pub context: *mut c_void,
}

type TaskCallback = extern "system" fn(*mut c_void, bool);
type WorkFn = extern "system" fn(*mut XAsyncBlock) -> HRESULT;
type ProviderFn = extern "system" fn(u32, *const XAsyncProviderData) -> HRESULT;

const MODE_MANUAL: u32 = 0;
const MODE_THREADPOOL: u32 = 1;
const MODE_SERIALIZED: u32 = 2;
const MODE_IMMEDIATE: u32 = 3;
const PORT_WORK: u32 = 0;
const PORT_COMPLETION: u32 = 1;

const OP_BEGIN: u32 = 0;
const OP_DO_WORK: u32 = 1;
const OP_GET_RESULT: u32 = 2;
const OP_CANCEL: u32 = 3;
const OP_CLEANUP: u32 = 4;

#[derive(Clone, Copy)]
struct QueuedTask {
    context: usize,
    callback: usize,
}

impl QueuedTask {
    fn run(self, canceled: bool) {
        let cb: TaskCallback = unsafe { std::mem::transmute(self.callback) };
        cb(self.context as *mut c_void, canceled);
    }
}

struct TaskPort {
    mode: u32,
    tasks: Mutex<VecDeque<QueuedTask>>,
    ready: Condvar,
}

impl TaskPort {
    fn new(mode: u32) -> Arc<Self> {
        let port = Arc::new(Self {
            mode,
            tasks: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
        });
        if mode == MODE_SERIALIZED {
            let worker = port.clone();
            std::thread::spawn(move || {
                loop {
                    let task = {
                        let mut g = worker.tasks.lock().unwrap_or_else(|e| e.into_inner());
                        while g.is_empty() {
                            if Arc::strong_count(&worker) == 1 {
                                return;
                            }
                            let (ng, _) = worker
                                .ready
                                .wait_timeout(g, std::time::Duration::from_millis(250))
                                .unwrap_or_else(|e| e.into_inner());
                            g = ng;
                        }
                        g.pop_front()
                    };
                    if let Some(t) = task {
                        t.run(false);
                    }
                }
            });
        }
        port
    }

    fn submit(&self, task: QueuedTask) {
        match self.mode {
            MODE_IMMEDIATE => task.run(false),
            MODE_MANUAL | MODE_SERIALIZED => {
                let mut g = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
                g.push_back(task);
                self.ready.notify_one();
            }
            _ => {
                let _ = MODE_THREADPOOL;
                std::thread::spawn(move || task.run(false));
            }
        }
    }

    fn dispatch(&self, timeout_ms: u32) -> bool {
        let mut g = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_empty() && timeout_ms > 0 {
            let dur = std::time::Duration::from_millis(u64::from(timeout_ms.min(500)));
            let (guard, _) = self.ready.wait_timeout(g, dur).unwrap_or_else(|e| e.into_inner());
            g = guard;
        }
        if let Some(t) = g.pop_front() {
            drop(g);
            t.run(false);
            true
        } else {
            false
        }
    }
}

pub struct TaskQueue {
    work: Arc<TaskPort>,
    completion: Arc<TaskPort>,
}

static PROCESS_QUEUE: LazyLock<Mutex<Arc<TaskQueue>>> = LazyLock::new(|| {
    Mutex::new(Arc::new(TaskQueue {
        work: TaskPort::new(MODE_THREADPOOL),
        completion: TaskPort::new(MODE_THREADPOOL),
    }))
});

struct AsyncState {
    status: HRESULT,
    result_size: usize,
    provider: Option<ProviderFn>,
    context: usize,
    identity: usize,
    payload: Option<Vec<u8>>,
    signal: Arc<(Mutex<bool>, Condvar)>,
}

static ASYNC_CALLS: LazyLock<Mutex<BTreeMap<usize, AsyncState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn queue_arc(q: *const c_void) -> Arc<TaskQueue> {
    if q.is_null() {
        PROCESS_QUEUE.lock().unwrap_or_else(|e| e.into_inner()).clone()
    } else {
        unsafe {
            Arc::increment_strong_count(q.cast::<TaskQueue>());
            Arc::from_raw(q.cast::<TaskQueue>())
        }
    }
}

fn finish_async_with(block: *mut XAsyncBlock, hr: HRESULT, payload: Vec<u8>) -> HRESULT {
    if block.is_null() {
        return E_INVALIDARG;
    }
    let size = payload.len();
    let signal = Arc::new((Mutex::new(true), Condvar::new()));
    let (cb, queue_ptr) = {
        let mut calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        calls.insert(
            block as usize,
            AsyncState {
                status: hr,
                result_size: size,
                provider: None,
                context: 0,
                identity: 0,
                payload: Some(payload),
                signal,
            },
        );
        unsafe {
            (*block).internal[0] = 1;
            (*block).internal[1] = hr as u64;
            ((*block).callback, (*block).queue)
        }
    };
    if cb.is_some() {
        extern "system" fn run_comp(ctx: *mut c_void, _canceled: bool) {
            let blk = ctx.cast::<XAsyncBlock>();
            if let Some(b) = unsafe { blk.as_ref() } {
                if let Some(cb) = b.callback {
                    cb(blk);
                }
            }
        }
        let q = queue_arc(queue_ptr);
        q.completion.submit(QueuedTask {
            context: block as usize,
            callback: run_comp as *const () as usize,
        });
    }
    S_OK
}

extern "system" fn xasync_get_status(_: This, block: *mut XAsyncBlock, wait: u8) -> HRESULT {
    let Some(b) = (unsafe { block.as_ref() }) else {
        return E_INVALIDARG;
    };
    let sig = {
        let calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(st) = calls.get(&(block as usize)) {
            if st.status != E_PENDING || wait == 0 {
                return st.status;
            }
            Some(st.signal.clone())
        } else if b.internal[0] != 0 {
            return b.internal[1] as i32;
        } else {
            None
        }
    };
    if wait != 0 {
        if let Some(sig) = sig {
            let mut g = sig.0.lock().unwrap_or_else(|e| e.into_inner());
            while !*g {
                g = sig.1.wait(g).unwrap_or_else(|e| e.into_inner());
            }
        }
        let calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(st) = calls.get(&(block as usize)) {
            return st.status;
        }
        if b.internal[0] != 0 {
            return b.internal[1] as i32;
        }
    }
    E_PENDING
}

extern "system" fn xasync_get_result_size(_: This, block: *mut XAsyncBlock, out: *mut usize) -> HRESULT {
    if block.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    let calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(st) = calls.get(&(block as usize)) else {
        return E_INVALIDARG;
    };
    if st.status == E_PENDING {
        return E_PENDING;
    }
    unsafe { out.write(st.result_size) };
    S_OK
}

extern "system" fn xasync_cancel(_: This, block: *mut XAsyncBlock) {
    if block.is_null() {
        return;
    }
    let provider_ctx = {
        let mut calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(st) = calls.get_mut(&(block as usize)) else {
            return;
        };
        if st.status == E_PENDING {
            st.status = E_ABORT;
        }
        st.provider.map(|p| (p, st.context))
    };
    if let Some((provider, ctx)) = provider_ctx {
        let data = XAsyncProviderData {
            block,
            buffer_size: 0,
            buffer: std::ptr::null_mut(),
            context: ctx as *mut c_void,
        };
        provider(OP_CANCEL, &data);
    }
}

extern "system" fn xasync_run(_: This, block: *mut XAsyncBlock, work: Option<WorkFn>) -> HRESULT {
    let Some(work_fn) = work else {
        return E_INVALIDARG;
    };
    if block.is_null() {
        return E_INVALIDARG;
    }
    extern "system" fn run_provider(op: u32, data: *const XAsyncProviderData) -> HRESULT {
        let d = unsafe { &*data };
        match op {
            OP_BEGIN => xasync_schedule(&XTHREADING_OBJECT, d.block, 0),
            OP_DO_WORK => {
                let w: WorkFn = unsafe { std::mem::transmute(d.context) };
                w(d.block)
            }
            _ => S_OK,
        }
    }
    boot_trace("xgameruntime", "XAsyncRun", &format!("block={block:?}"));
    xasync_begin(
        &XTHREADING_OBJECT,
        block,
        work_fn as *mut c_void,
        xasync_run as *const c_void,
        std::ptr::null(),
        Some(run_provider),
    )
}

extern "system" fn xasync_begin(
    _: This,
    block: *mut XAsyncBlock,
    context: *mut c_void,
    identity: *const c_void,
    _name: *const u8,
    provider: Option<ProviderFn>,
) -> HRESULT {
    if block.is_null() {
        return E_INVALIDARG;
    }
    let Some(prov) = provider else {
        return E_INVALIDARG;
    };
    let sig = Arc::new((Mutex::new(false), Condvar::new()));
    {
        let mut calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        calls.insert(
            block as usize,
            AsyncState {
                status: E_PENDING,
                result_size: 0,
                provider: Some(prov),
                context: context as usize,
                identity: identity as usize,
                payload: None,
                signal: sig,
            },
        );
        unsafe {
            (*block).internal[0] = 1;
            (*block).internal[1] = E_PENDING as u64;
        }
    }
    let data = XAsyncProviderData {
        block,
        buffer_size: 0,
        buffer: std::ptr::null_mut(),
        context,
    };
    let hr = prov(OP_BEGIN, &data);
    if hr < 0 {
        xasync_complete(&XTHREADING_OBJECT, block, hr, 0);
    }
    S_OK
}

extern "system" fn do_work_trampoline(ctx: *mut c_void, canceled: bool) {
    let block = ctx.cast::<XAsyncBlock>();
    if block.is_null() || canceled {
        return;
    }
    let (prov, pctx) = {
        let calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(st) = calls.get(&(block as usize)) else {
            return;
        };
        (st.provider, st.context)
    };
    if let Some(p) = prov {
        let data = XAsyncProviderData {
            block,
            buffer_size: 0,
            buffer: std::ptr::null_mut(),
            context: pctx as *mut c_void,
        };
        let hr = p(OP_DO_WORK, &data);
        if hr != E_PENDING {
            xasync_complete(&XTHREADING_OBJECT, block, hr, 0);
        }
    }
}

extern "system" fn xasync_schedule(_: This, block: *mut XAsyncBlock, _delay: u32) -> HRESULT {
    if block.is_null() {
        return E_INVALIDARG;
    }
    let q = queue_arc(unsafe { (*block).queue });
    q.work.submit(QueuedTask {
        context: block as usize,
        callback: do_work_trampoline as *const () as usize,
    });
    S_OK
}

extern "system" fn xasync_complete(_: This, block: *mut XAsyncBlock, hr: HRESULT, result_size: usize) {
    if block.is_null() {
        return;
    }
    let sig_to_wake: Option<Arc<(Mutex<bool>, Condvar)>> = {
        let mut calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(st) = calls.get_mut(&(block as usize)) {
            st.status = hr;
            st.result_size = result_size;
            Some(st.signal.clone())
        } else {
            let sig = Arc::new((Mutex::new(true), Condvar::new()));
            calls.insert(
                block as usize,
                AsyncState {
                    status: hr,
                    result_size,
                    provider: None,
                    context: 0,
                    identity: 0,
                    payload: None,
                    signal: sig,
                },
            );
            None
        }
    };
    if let Some(sig) = sig_to_wake {
        let mut g = sig.0.lock().unwrap_or_else(|e| e.into_inner());
        *g = true;
        sig.1.notify_all();
    }
    let (cb, queue_ptr) = unsafe {
        (*block).internal[0] = 1;
        (*block).internal[1] = hr as u64;
        ((*block).callback, (*block).queue)
    };
    if cb.is_some() {
        extern "system" fn run_comp(ctx: *mut c_void, _canceled: bool) {
            let blk = ctx.cast::<XAsyncBlock>();
            if let Some(b) = unsafe { blk.as_ref() } {
                if let Some(cb) = b.callback {
                    cb(blk);
                }
            }
        }
        let q = queue_arc(queue_ptr);
        q.completion.submit(QueuedTask {
            context: block as usize,
            callback: run_comp as *const () as usize,
        });
    }
}

extern "system" fn xasync_get_result(
    _: This,
    block: *mut XAsyncBlock,
    identity: *const c_void,
    buffer_size: usize,
    buffer: *mut c_void,
    buffer_used: *mut usize,
) -> HRESULT {
    if block.is_null() {
        return E_INVALIDARG;
    }
    let removed = {
        let mut calls = ASYNC_CALLS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(st) = calls.get(&(block as usize)) else {
            return E_INVALIDARG;
        };
        if st.status == E_PENDING {
            return E_PENDING;
        }
        if !identity.is_null() && st.identity != 0 && st.identity != identity as usize {
            return E_INVALIDARG;
        }
        calls.remove(&(block as usize)).unwrap()
    };

    if !buffer_used.is_null() {
        unsafe { buffer_used.write(removed.result_size) };
    }
    if let Some(payload) = removed.payload {
        if !payload.is_empty() {
            if buffer.is_null() || buffer_size < payload.len() {
                return E_NOT_SUFFICIENT_BUFFER;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), buffer.cast::<u8>(), payload.len());
            }
        }
        return removed.status;
    }

    let mut hr = removed.status;
    if let Some(prov) = removed.provider {
        if removed.result_size > 0 {
            if buffer.is_null() || buffer_size < removed.result_size {
                return E_NOT_SUFFICIENT_BUFFER;
            }
            let data = XAsyncProviderData {
                block,
                buffer_size,
                buffer,
                context: removed.context as *mut c_void,
            };
            hr = prov(OP_GET_RESULT, &data);
        }
        let cleanup_data = XAsyncProviderData {
            block,
            buffer_size: 0,
            buffer: std::ptr::null_mut(),
            context: removed.context as *mut c_void,
        };
        prov(OP_CLEANUP, &cleanup_data);
    }
    hr
}

extern "system" fn xtaskqueue_create(
    _: This,
    work_mode: u32,
    comp_mode: u32,
    out: *mut *mut TaskQueue,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    boot_trace(
        "xgameruntime",
        "XTaskQueueCreate",
        &format!("work={work_mode} comp={comp_mode}"),
    );
    let q = Arc::new(TaskQueue {
        work: TaskPort::new(work_mode),
        completion: TaskPort::new(comp_mode),
    });
    unsafe { out.write(Arc::into_raw(q).cast_mut()) };
    S_OK
}

extern "system" fn xtaskqueue_create_composite(
    _: This,
    work_port: *const c_void,
    comp_port: *const c_void,
    out: *mut *mut TaskQueue,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let base = PROCESS_QUEUE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let w = if work_port.is_null() {
        base.work.clone()
    } else {
        unsafe { &*work_port.cast::<Arc<TaskPort>>() }.clone()
    };
    let c = if comp_port.is_null() {
        base.completion.clone()
    } else {
        unsafe { &*comp_port.cast::<Arc<TaskPort>>() }.clone()
    };
    let q = Arc::new(TaskQueue { work: w, completion: c });
    unsafe { out.write(Arc::into_raw(q).cast_mut()) };
    S_OK
}

extern "system" fn xtaskqueue_get_port(
    _: This,
    queue: *const TaskQueue,
    port: u32,
    out: *mut *const c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let q = queue_arc(queue.cast());
    let cloned = match port {
        PORT_WORK => q.work.clone(),
        PORT_COMPLETION => q.completion.clone(),
        _ => return E_INVALIDARG,
    };
    let boxed = Box::new(cloned);
    unsafe { out.write(Box::into_raw(boxed).cast()) };
    S_OK
}

extern "system" fn xtaskqueue_duplicate(
    _: This,
    queue: *mut TaskQueue,
    out: *mut *mut TaskQueue,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if !queue.is_null() {
        unsafe { Arc::increment_strong_count(queue) };
    }
    unsafe { out.write(queue) };
    S_OK
}

extern "system" fn xtaskqueue_dispatch(
    _: This,
    queue: *const TaskQueue,
    port: u32,
    timeout_ms: u32,
) -> bool {
    let q = queue_arc(queue.cast());
    match port {
        PORT_WORK => q.work.dispatch(timeout_ms),
        PORT_COMPLETION => q.completion.dispatch(timeout_ms),
        _ => false,
    }
}

extern "system" fn xtaskqueue_close(_: This, queue: *mut TaskQueue) {
    if !queue.is_null() {
        unsafe { Arc::decrement_strong_count(queue) };
    }
}

extern "system" fn xtaskqueue_submit(
    _: This,
    queue: *const TaskQueue,
    port: u32,
    context: *mut c_void,
    callback: Option<TaskCallback>,
) -> HRESULT {
    let Some(cb) = callback else {
        return E_INVALIDARG;
    };
    let q = queue_arc(queue.cast());
    let task = QueuedTask {
        context: context as usize,
        callback: cb as *const () as usize,
    };
    match port {
        PORT_WORK => q.work.submit(task),
        PORT_COMPLETION => q.completion.submit(task),
        _ => return E_INVALIDARG,
    }
    S_OK
}

extern "system" fn xtaskqueue_submit_delayed(
    this: This,
    queue: *const TaskQueue,
    port: u32,
    _delay_ms: u32,
    context: *mut c_void,
    callback: Option<TaskCallback>,
) -> HRESULT {
    xtaskqueue_submit(this, queue, port, context, callback)
}

extern "system" fn xtaskqueue_register_waiter(
    _: This,
    _q: *const TaskQueue,
    port: u32,
    wait_handle: *mut c_void,
    _ctx: *mut c_void,
    _cb: *const c_void,
    token_out: *mut u64,
) -> HRESULT {
    boot_trace(
        "xgameruntime",
        "XTaskQueueRegisterWaiter",
        &format!("port={port} handle={wait_handle:?}"),
    );
    put(token_out, NEXT_TOKEN.fetch_add(1, Ordering::Relaxed))
}

extern "system" fn xtaskqueue_unregister_waiter(_: This, _q: *const TaskQueue, _token: u64) {}

extern "system" fn xtaskqueue_terminate(
    _: This,
    _q: *const TaskQueue,
    _wait: u8,
    ctx: *mut c_void,
    cb: Option<extern "system" fn(*mut c_void)>,
) -> HRESULT {
    if let Some(f) = cb {
        f(ctx);
    }
    S_OK
}

extern "system" fn xtaskqueue_register_monitor(
    _: This,
    _q: *const TaskQueue,
    _ctx: *mut c_void,
    _cb: *const c_void,
    token: *mut u64,
) -> HRESULT {
    put(token, NEXT_TOKEN.fetch_add(1, Ordering::Relaxed))
}
extern "system" fn xtaskqueue_unregister_monitor(_: This, _q: *const TaskQueue, _token: u64) {}
extern "system" fn xtaskqueue_get_process_queue(_: This, out: *mut *const TaskQueue) -> bool {
    if out.is_null() {
        return false;
    }
    let q = PROCESS_QUEUE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    unsafe { out.write(Arc::into_raw(q)) };
    true
}
extern "system" fn xtaskqueue_set_process_queue(_: This, q: *const TaskQueue) {
    let next = queue_arc(q.cast());
    *PROCESS_QUEUE.lock().unwrap_or_else(|e| e.into_inner()) = next;
}
extern "system" fn xthread_assert_not_time_sensitive(_: This) -> HRESULT {
    S_OK
}

static XTHREADING_VTABLE: Vtable<30> = {
    let mut t = fill_missing::<30>();
    t[3] = xasync_get_status as *const c_void;
    t[4] = xasync_get_result_size as *const c_void;
    t[5] = xasync_cancel as *const c_void;
    t[6] = xasync_run as *const c_void;
    t[7] = xasync_begin as *const c_void;
    t[9] = xasync_schedule as *const c_void;
    t[10] = xasync_complete as *const c_void;
    t[11] = xasync_get_result as *const c_void;
    t[12] = xtaskqueue_create as *const c_void;
    t[13] = xtaskqueue_create_composite as *const c_void;
    t[14] = xtaskqueue_get_port as *const c_void;
    t[15] = xtaskqueue_duplicate as *const c_void;
    t[16] = xtaskqueue_dispatch as *const c_void;
    t[17] = xtaskqueue_close as *const c_void;
    t[18] = xtaskqueue_submit as *const c_void;
    t[19] = xtaskqueue_submit_delayed as *const c_void;
    t[20] = xtaskqueue_register_waiter as *const c_void;
    t[21] = xtaskqueue_unregister_waiter as *const c_void;
    t[22] = xtaskqueue_terminate as *const c_void;
    t[23] = xtaskqueue_register_monitor as *const c_void;
    t[24] = xtaskqueue_unregister_monitor as *const c_void;
    t[25] = xtaskqueue_get_process_queue as *const c_void;
    t[26] = xtaskqueue_set_process_queue as *const c_void;
    t[29] = xthread_assert_not_time_sensitive as *const c_void; // 0xe8
    Vtable(t)
};

static XTHREADING_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XTHREADING_VTABLE.0.as_ptr(),
    area: "XThreading",
};

// ============================================================================
// 2,3,4. XGame / XGameRuntimeFeature / XGameEvent
// ============================================================================

const PROVIDER_XGAME: Guid = Guid::new(0x973a_344e, 0x24bf, 0x4d0f, [0x84, 0x57, 0x56, 0xc5, 0x34, 0x89, 0x2b, 0x29]);
const IID_XGAME: Guid = Guid::new(0x2549_f142, 0x6419, 0x4a06, [0x97, 0xb5, 0x93, 0x1a, 0xab, 0x7c, 0x2f, 0x34]);
const PROVIDER_XFEATURE: Guid = Guid::new(0x8836_fe87, 0xedb9, 0x4fe3, [0x8d, 0xad, 0x05, 0xf0, 0xd2, 0xcd, 0x5b, 0x40]);
const PROVIDER_XEVENT: Guid = Guid::new(0xbbfb_dcc7, 0xbfe7, 0x409b, [0xa5, 0xca, 0xed, 0xf0, 0x54, 0x96, 0x0b, 0x4d]);

extern "system" fn xgame_title_id(_: This, out: *mut u32) -> HRESULT {
    put(out, TITLE_ID)
}
extern "system" fn xgame_launch_new(_: This, _exe: *const c_char, _args: *const c_char, _user: *const c_void) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn xgame_feature_avail(_: This, _feature: u32) -> bool {
    true
}
extern "system" fn xgame_event_write(_: This, _user: *const c_void, _name: *const c_char, _fmt: *const c_char) -> HRESULT {
    S_OK
}

static XGAME_VTABLE: Vtable<12> = {
    let mut t = fill_missing::<12>();
    t[3] = xgame_title_id as *const c_void;
    t[4] = xgame_launch_new as *const c_void;
    Vtable(t)
};
static XFEATURE_VTABLE: Vtable<6> = {
    let mut t = fill_missing::<6>();
    t[3] = xgame_feature_avail as *const c_void;
    Vtable(t)
};
static XEVENT_VTABLE: Vtable<6> = {
    let mut t = fill_missing::<6>();
    t[3] = xgame_event_write as *const c_void;
    Vtable(t)
};

static XGAME_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XGAME_VTABLE.0.as_ptr(),
    area: "XGame",
};
static XFEATURE_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XFEATURE_VTABLE.0.as_ptr(),
    area: "XGameRuntimeFeature",
};
static XEVENT_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XEVENT_VTABLE.0.as_ptr(),
    area: "XGameEvent",
};

// ============================================================================
// 5,6. XSystem & XSystemAnalytics (`0x90`-byte struct returning `RDX` in `RAX`)
// ============================================================================

const PROVIDER_XSYSTEM: Guid = Guid::new(0xe349_bd1a, 0xfc20, 0x4e40, [0xb9, 0x9c, 0x41, 0x78, 0xcc, 0x6b, 0x40, 0x9f]);
const IID_XSYSTEM: Guid = Guid::new(0x6fd7_1f09, 0x7513, 0x49f0, [0x89, 0xbc, 0xbf, 0xaf, 0x5d, 0xf6, 0xf8, 0x52]);
const IID_XSYSTEM_2026: Guid = Guid::new(0x1861_cf2e, 0xe18b, 0x4834, [0xa9, 0xf5, 0xb4, 0xa4, 0xe6, 0xef, 0xb4, 0xcf]);
const PROVIDER_ANALYTICS: Guid = Guid::new(0xb884_675d, 0xb738, 0x4a9c, [0x81, 0x5d, 0x9a, 0x9a, 0x1e, 0x0c, 0x6c, 0x9b]);

extern "system" fn xsys_console_id(_: This, sz: usize, buf: *mut u8, used: *mut usize) -> HRESULT {
    put_string("00000000000000000000000000000000000001", sz, buf, used)
}
extern "system" fn xsys_sandbox_id(_: This, sz: usize, buf: *mut u8, used: *mut usize) -> HRESULT {
    put_string("RETAIL", sz, buf, used)
}
extern "system" fn xsys_device_id(_: This, sz: usize, buf: *mut u8, used: *mut usize) -> HRESULT {
    put_string("R1RBNl9QQ19ERVZJQ0VfSURfMDAwMDAwMDE=", sz, buf, used)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

#[repr(C)]
pub struct XSystemAnalyticsInfo {
    pub os_version: XVersion,
    pub hosting_os_version: XVersion,
    pub family: [u8; 64],
    pub form: [u8; 64],
}
const _: () = assert!(size_of::<XSystemAnalyticsInfo>() == 0x90);

fn fixed_cstr_64(s: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    let n = s.len().min(63);
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
    out
}

extern "system" fn xsys_analytics_info(_: This, out: *mut XSystemAnalyticsInfo) -> *mut XSystemAnalyticsInfo {
    if !out.is_null() {
        let ver = XVersion {
            major: 10,
            minor: 0,
            build: 26100,
            revision: 7901,
        };
        unsafe {
            out.write(XSystemAnalyticsInfo {
                os_version: ver,
                hosting_os_version: ver,
                family: fixed_cstr_64("Xbox"),
                form: fixed_cstr_64("Xbox Series X"),
            });
        }
    }
    out
}

static XSYSTEM_VTABLE: Vtable<8> = {
    let mut t = fill_missing::<8>();
    t[3] = xsys_console_id as *const c_void;
    t[4] = xsys_sandbox_id as *const c_void;
    t[5] = xsys_device_id as *const c_void;
    Vtable(t)
};
static XANALYTICS_VTABLE: Vtable<4> = {
    let mut t = fill_missing::<4>();
    t[3] = xsys_analytics_info as *const c_void;
    Vtable(t)
};

static XSYSTEM_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XSYSTEM_VTABLE.0.as_ptr(),
    area: "XSystem",
};
static XANALYTICS_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XANALYTICS_VTABLE.0.as_ptr(),
    area: "XSystemAnalytics",
};

// ============================================================================
// 7. XUser + XUserGamertag + XUserDevice (`Vtable<35>`)
// ============================================================================

const PROVIDER_XUSER: Guid = Guid::new(0x01ac_d177, 0x91f9, 0x4763, [0xa3, 0x8e, 0xcc, 0xbb, 0x55, 0xce, 0x32, 0xe0]);
const IID_XUSER: Guid = Guid::new(0xeb9b_f948, 0x18dc, 0x4d82, [0xbb, 0xcc, 0x40, 0xe0, 0xa8, 0x09, 0xc4, 0xc0]);
const IID_XUSER_GAMERTAG: Guid = Guid::new(0xcef4_fac0, 0x7676, 0x4a94, [0xa1, 0x19, 0x4c, 0x43, 0xf9, 0xeb, 0x5b, 0x74]);
const PROVIDER_XUSER_DEV: Guid = Guid::new(0x7d82_4997, 0x10dc, 0x45ab, [0x86, 0xb7, 0x27, 0x37, 0x76, 0x7c, 0x0b, 0xf1]);
const IID_XUSER_DEV: Guid = Guid::new(0x0cc6_a956, 0xe7e1, 0x4fdf, [0x93, 0x41, 0x9d, 0x5d, 0xa6, 0x49, 0xeb, 0xc8]);

const FAILED_TO_GET_TOKEN: HRESULT = 0x8924_5111_u32 as i32;
static OFFLINE_USER_HANDLE: u8 = 1;

extern "system" fn xuser_duplicate(_: This, _: *const c_void, out: *mut *const c_void) -> HRESULT {
    put(out, (&raw const OFFLINE_USER_HANDLE).cast())
}
extern "system" fn xuser_close(_: This, _: *const c_void) {}
extern "system" fn xuser_compare(_: This, u1: *const c_void, u2: *const c_void, out: *mut i32) -> HRESULT {
    let cmp = if u1 == u2 {
        0
    } else if (u1 as usize) < (u2 as usize) {
        -1
    } else {
        1
    };
    put(out, cmp)
}
extern "system" fn xuser_get_max_users(_: This, out: *mut u32) -> HRESULT {
    put(out, 4)
}
extern "system" fn xuser_add_async(_: This, options: u32, block: *mut XAsyncBlock) -> HRESULT {
    boot_trace(
        "xgameruntime",
        "XUser::AddAsync",
        &format!("options={options:#x} block={block:?}"),
    );
    finish_async_with(block, S_OK, (&raw const OFFLINE_USER_HANDLE as usize).to_le_bytes().to_vec())
}
extern "system" fn xuser_add_by_id_with_ui_async(
    this: This,
    _user_id: u64,
    options: u32,
    block: *mut XAsyncBlock,
) -> HRESULT {
    xuser_add_async(this, options, block)
}
extern "system" fn xuser_add_result(_: This, block: *mut XAsyncBlock, out: *mut *const c_void) -> HRESULT {
    boot_trace(
        "xgameruntime",
        "XUser::AddResult",
        &format!("block={block:?} user={:?}", (&raw const OFFLINE_USER_HANDLE)),
    );
    put(out, (&raw const OFFLINE_USER_HANDLE).cast())
}
extern "system" fn xuser_get_id(_: This, _: *const c_void, out: *mut u64) -> HRESULT {
    put(out, 0x0009_0000_0000_0001)
}
extern "system" fn xuser_find_by_id(_: This, _xuid: u64, out: *mut *const c_void) -> HRESULT {
    put(out, (&raw const OFFLINE_USER_HANDLE).cast())
}
extern "system" fn xuser_get_local_id(_: This, _: *const c_void, out: *mut u64) -> HRESULT {
    put(out, 1)
}
extern "system" fn xuser_find_by_local_id(_: This, _local_id: u64, out: *mut *const c_void) -> HRESULT {
    put(out, (&raw const OFFLINE_USER_HANDLE).cast())
}
extern "system" fn xuser_get_is_guest(_: This, _: *const c_void, out: *mut bool) -> HRESULT {
    put(out, false)
}
extern "system" fn xuser_get_state(_: This, _: *const c_void, out: *mut u32) -> HRESULT {
    put(out, 0) // SignedIn
}
extern "system" fn xuser_get_gamertag(
    _: This,
    _: *const c_void,
    component: u32,
    sz: usize,
    buf: *mut u8,
    used: *mut usize,
) -> HRESULT {
    let text = if component == 2 { "" } else { "Player" };
    put_string(text, sz, buf, used)
}
extern "system" fn xuser_get_age_group(_: This, _: *const c_void, out: *mut u32) -> HRESULT {
    put(out, 3) // Adult
}
extern "system" fn xuser_check_privilege(
    _: This,
    _: *const c_void,
    _opts: u32,
    _priv_id: u32,
    has: *mut bool,
    reason: *mut u32,
) -> HRESULT {
    if !reason.is_null() {
        unsafe { reason.write(0) };
    }
    put(has, true)
}
extern "system" fn xuser_resolve_priv_async(
    _: This,
    _: *const c_void,
    _opts: u32,
    _priv_id: u32,
    block: *mut XAsyncBlock,
) -> HRESULT {
    finish_async_with(block, S_OK, Vec::new())
}
extern "system" fn xuser_resolve_priv_result(_: This, block: *mut XAsyncBlock) -> HRESULT {
    xasync_get_status(&XTHREADING_OBJECT, block, 0)
}
extern "system" fn xuser_token_async(
    _: This,
    _: *const c_void,
    _opts: u32,
    _method: *const c_char,
    _url: *const c_char,
    _hc: usize,
    _h: *const c_void,
    _bsz: usize,
    _b: *const c_void,
    block: *mut XAsyncBlock,
) -> HRESULT {
    boot_trace("xgameruntime", "XUser::GetTokenAndSignatureAsync", &format!("opts={_opts:#x} block={block:?}"));
    finish_async_with(block, FAILED_TO_GET_TOKEN, Vec::new())
}
extern "system" fn xuser_token_size(_: This, block: *mut XAsyncBlock, out: *mut usize) -> HRESULT {
    xasync_get_result_size(&XTHREADING_OBJECT, block, out)
}
extern "system" fn xuser_token_result(
    _: This,
    block: *mut XAsyncBlock,
    _sz: usize,
    _buf: *mut c_void,
    _out_ptr: *mut *mut c_void,
    _used: *mut usize,
) -> HRESULT {
    xasync_get_status(&XTHREADING_OBJECT, block, 0)
}
extern "system" fn xuser_reg_change(
    _: This,
    _q: *const c_void,
    _ctx: *mut c_void,
    _cb: *const c_void,
    tok: *mut u64,
) -> HRESULT {
    boot_trace("xgameruntime", "XUser::RegisterForChangeEvent", &format!("cb={_cb:?} ctx={_ctx:?}"));
    put(tok, NEXT_TOKEN.fetch_add(1, Ordering::Relaxed))
}
extern "system" fn xuser_unreg_change(_: This, _tok: u64, _wait: bool) -> bool {
    true
}
extern "system" fn xuser_gamertag_slot(
    _: This,
    _: *const c_void,
    component: u32,
    sz: usize,
    buf: *mut u8,
    used: *mut usize,
) -> HRESULT {
    let text = if component == 2 { "" } else { "Player" };
    put_string(text, sz, buf, used)
}
extern "system" fn xuser_dev_find(_: This, _id: *const c_void, out: *mut *const c_void) -> HRESULT {
    put(out, (&raw const OFFLINE_USER_HANDLE).cast())
}

static XUSER_VTABLE: Vtable<40> = {
    let mut t = fill_missing::<40>();
    t[3] = xuser_duplicate as *const c_void;
    t[4] = xuser_close as *const c_void;
    t[5] = xuser_compare as *const c_void;
    t[6] = xuser_get_max_users as *const c_void;
    t[7] = xuser_add_async as *const c_void;
    t[8] = xuser_add_result as *const c_void;
    t[9] = xuser_get_local_id as *const c_void;
    t[10] = xuser_find_by_local_id as *const c_void;
    t[11] = xuser_get_id as *const c_void;
    t[12] = xuser_find_by_id as *const c_void;
    t[13] = xuser_get_is_guest as *const c_void;
    t[14] = xuser_get_state as *const c_void;
    t[15] = xuser_get_gamertag as *const c_void;
    t[19] = xuser_get_age_group as *const c_void;
    t[20] = xuser_check_privilege as *const c_void;
    t[21] = xuser_resolve_priv_async as *const c_void;
    t[22] = xuser_resolve_priv_result as *const c_void;
    t[23] = xuser_token_async as *const c_void;
    t[24] = xuser_token_size as *const c_void;
    t[25] = xuser_token_result as *const c_void;
    t[33] = xuser_reg_change as *const c_void;
    t[34] = xuser_unreg_change as *const c_void;
    t[37] = xuser_add_by_id_with_ui_async as *const c_void;
    t[38] = xuser_add_result as *const c_void;
    Vtable(t)
};
static XUSER_GAMERTAG_VTABLE: Vtable<6> = {
    let mut t = fill_missing::<6>();
    t[3] = xuser_gamertag_slot as *const c_void;
    Vtable(t)
};
static XUSER_DEV_VTABLE: Vtable<6> = {
    let mut t = fill_missing::<6>();
    t[3] = xuser_dev_find as *const c_void;
    Vtable(t)
};

static XUSER_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XUSER_VTABLE.0.as_ptr(),
    area: "XUser",
};
static XUSER_GAMERTAG_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XUSER_GAMERTAG_VTABLE.0.as_ptr(),
    area: "XUserGamertag",
};
static XUSER_DEV_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XUSER_DEV_VTABLE.0.as_ptr(),
    area: "XUserDevice",
};

// ============================================================================
// 8. Persistent Local Storage (`f4faf4d4-2d04-4fce-b3e0-474a713a3e84`)
// ============================================================================

const PROVIDER_STORAGE: Guid = Guid::new(0xf4fa_f4d4, 0x2d04, 0x4fce, [0xb3, 0xe0, 0x47, 0x4a, 0x71, 0x3a, 0x3e, 0x84]);
const IID_STORAGE: Guid = Guid::new(0xd294_11df, 0x0794, 0x4553, [0x8b, 0x27, 0x95, 0xfc, 0x02, 0xd0, 0xf7, 0x5d]);
const IID_STORAGE_2026: Guid = Guid::new(0x41a4_e10c, 0x5a7e, 0x41d9, [0x8c, 0x37, 0x37, 0xbd, 0xe6, 0x2a, 0x07, 0xd6]);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XPersistentLocalStorageSpaceInfo {
    pub available_free_bytes: u64,
    pub total_free_bytes: u64,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

fn dir_used_bytes(dir: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|entry| match entry.metadata() {
            Ok(m) if m.is_dir() => dir_used_bytes(&entry.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

fn storage_dir_string() -> String {
    let dir = ensure_data_dirs().join("storage");
    let _ = fs::create_dir_all(&dir);
    let mut s = dir.to_string_lossy().into_owned();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

extern "system" fn storage_path_size(_: This, out: *mut usize) -> HRESULT {
    let s = storage_dir_string();
    put(out, s.len() + 1)
}
extern "system" fn storage_path(_: This, size: usize, buf: *mut u8, used: *mut usize) -> HRESULT {
    let s = storage_dir_string();
    if size <= s.len() {
        return E_FAIL;
    }
    put_string(&s, size, buf, used)
}
extern "system" fn storage_space_info(_: This, out: *mut XPersistentLocalStorageSpaceInfo) -> HRESULT {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let dir = ensure_data_dirs().join("storage");
    let used = dir_used_bytes(&dir);
    let free = LOCAL_QUOTA_BYTES.saturating_sub(used);
    unsafe {
        out.write(XPersistentLocalStorageSpaceInfo {
            available_free_bytes: free,
            total_free_bytes: free,
            used_bytes: used,
            total_bytes: LOCAL_QUOTA_BYTES,
        });
    }
    S_OK
}
extern "system" fn storage_prompt_space(_: This, bytes: u64, block: *mut XAsyncBlock) -> HRESULT {
    let dir = ensure_data_dirs().join("storage");
    let free = LOCAL_QUOTA_BYTES.saturating_sub(dir_used_bytes(&dir));
    let hr = if bytes <= free { S_OK } else { E_ABORT };
    finish_async_with(block, hr, Vec::new())
}
extern "system" fn storage_prompt_result(_: This, block: *mut XAsyncBlock) -> HRESULT {
    xasync_get_status(&XTHREADING_OBJECT, block, 0)
}

static STORAGE_VTABLE: Vtable<10> = {
    let mut t = fill_missing::<10>();
    t[3] = storage_path_size as *const c_void;
    t[4] = storage_path as *const c_void;
    t[5] = storage_space_info as *const c_void;
    t[6] = storage_prompt_space as *const c_void;
    t[7] = storage_prompt_result as *const c_void;
    Vtable(t)
};

static STORAGE_OBJECT: RuntimeObject = RuntimeObject {
    vtable: STORAGE_VTABLE.0.as_ptr(),
    area: "PersistentLocalStorage",
};

// ============================================================================
// 9. XGameSave (`704c3f58-...`, `Vtable<30>`)
// ============================================================================

const PROVIDER_GAMESAVE: Guid = Guid::new(0x704c_3f58, 0xe629, 0x4cc2, [0xb1, 0x97, 0x30, 0x51, 0x1b, 0x99, 0x6f, 0xe2]);
const IID_GAMESAVE_2026: Guid = Guid::new(0x1bff_f3af, 0xf14a, 0x40a3, [0x8e, 0x35, 0x9a, 0xda, 0x90, 0x65, 0x93, 0xf9]);

pub struct GameSaveProvider {
    root: PathBuf,
}
pub struct GameSaveContainer {
    dir: PathBuf,
}
pub struct GameSaveUpdate {
    container_dir: PathBuf,
    writes: Vec<(String, Vec<u8>)>,
    deletes: Vec<String>,
}

fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

extern "system" fn gamesave_init_provider(
    _: This,
    _user: *const c_void,
    scid: *const c_char,
    _sync_on_demand: bool,
    out: *mut *mut GameSaveProvider,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let scid_str = if scid.is_null() {
        "default".to_string()
    } else {
        sanitize_name(&cstr_to_string(scid))
    };
    let root = ensure_data_dirs().join("saves").join(scid_str);
    let _ = fs::create_dir_all(&root);
    let prov = Box::new(GameSaveProvider { root });
    unsafe { out.write(Box::into_raw(prov)) };
    S_OK
}
extern "system" fn gamesave_init_provider_async(
    this: This,
    user: *const c_void,
    scid: *const c_char,
    sync_on_demand: bool,
    block: *mut XAsyncBlock,
) -> HRESULT {
    let mut prov = std::ptr::null_mut();
    let hr = gamesave_init_provider(this, user, scid, sync_on_demand, &mut prov);
    finish_async_with(block, hr, (prov as usize).to_le_bytes().to_vec())
}
extern "system" fn gamesave_init_provider_result(
    _: This,
    block: *mut XAsyncBlock,
    out: *mut *mut GameSaveProvider,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let mut addr = 0usize;
    let hr = xasync_get_result(
        &XTHREADING_OBJECT,
        block,
        std::ptr::null(),
        size_of::<usize>(),
        (&raw mut addr).cast(),
        std::ptr::null_mut(),
    );
    if hr >= 0 {
        unsafe { out.write(addr as *mut GameSaveProvider) };
    }
    hr
}
extern "system" fn gamesave_close_provider(_: This, prov: *mut GameSaveProvider) {
    if !prov.is_null() {
        drop(unsafe { Box::from_raw(prov) });
    }
}
extern "system" fn gamesave_get_quota(_: This, prov: *mut GameSaveProvider, remaining: *mut i64) -> HRESULT {
    let used = unsafe { prov.as_ref() }.map_or(0, |p| dir_used_bytes(&p.root));
    put(remaining, LOCAL_QUOTA_BYTES.saturating_sub(used) as i64)
}
extern "system" fn gamesave_get_quota_async(
    _: This,
    prov: *mut GameSaveProvider,
    block: *mut XAsyncBlock,
) -> HRESULT {
    let used = unsafe { prov.as_ref() }.map_or(0, |p| dir_used_bytes(&p.root));
    let rem = LOCAL_QUOTA_BYTES.saturating_sub(used) as i64;
    finish_async_with(block, S_OK, rem.to_le_bytes().to_vec())
}
extern "system" fn gamesave_get_quota_result(
    _: This,
    block: *mut XAsyncBlock,
    remaining: *mut i64,
) -> HRESULT {
    if remaining.is_null() {
        return E_POINTER;
    }
    xasync_get_result(
        &XTHREADING_OBJECT,
        block,
        std::ptr::null(),
        size_of::<i64>(),
        remaining.cast(),
        std::ptr::null_mut(),
    )
}
extern "system" fn gamesave_enum_containers(
    _: This,
    _prov: *mut GameSaveProvider,
    _prefix: *const c_char,
    _ctx: *mut c_void,
    _cb: *const c_void,
) -> HRESULT {
    S_OK
}
extern "system" fn gamesave_create_container(
    _: This,
    prov: *mut GameSaveProvider,
    name: *const c_char,
    out: *mut *mut GameSaveContainer,
) -> HRESULT {
    if out.is_null() || prov.is_null() {
        return E_INVALIDARG;
    }
    let cname = sanitize_name(&cstr_to_string(name));
    let dir = unsafe { &*prov }.root.join(if cname.is_empty() { "default" } else { &cname });
    let _ = fs::create_dir_all(&dir);
    let cont = Box::new(GameSaveContainer { dir });
    unsafe { out.write(Box::into_raw(cont)) };
    S_OK
}
extern "system" fn gamesave_close_container(_: This, cont: *mut GameSaveContainer) {
    if !cont.is_null() {
        drop(unsafe { Box::from_raw(cont) });
    }
}
extern "system" fn gamesave_enum_blobs(
    _: This,
    _cont: *mut GameSaveContainer,
    _ctx: *mut c_void,
    _cb: *const c_void,
) -> HRESULT {
    S_OK
}
extern "system" fn gamesave_read_blob_async(
    _: This,
    cont: *mut GameSaveContainer,
    blob_names: *const *const c_char,
    num_blobs: u32,
    block: *mut XAsyncBlock,
) -> HRESULT {
    let Some(c) = (unsafe { cont.as_ref() }) else {
        return E_INVALIDARG;
    };
    if num_blobs == 0 || blob_names.is_null() {
        return finish_async_with(block, BLOB_NOT_FOUND, Vec::new());
    }
    let name = sanitize_name(&cstr_to_string(unsafe { *blob_names }));
    match fs::read(c.dir.join(name)) {
        Ok(bytes) => finish_async_with(block, S_OK, bytes),
        Err(_) => finish_async_with(block, BLOB_NOT_FOUND, Vec::new()),
    }
}
extern "system" fn gamesave_create_update(
    _: This,
    cont: *mut GameSaveContainer,
    _display_name: *const c_char,
    out: *mut *mut GameSaveUpdate,
) -> HRESULT {
    if out.is_null() || cont.is_null() {
        return E_INVALIDARG;
    }
    let upd = Box::new(GameSaveUpdate {
        container_dir: unsafe { &*cont }.dir.clone(),
        writes: Vec::new(),
        deletes: Vec::new(),
    });
    unsafe { out.write(Box::into_raw(upd)) };
    S_OK
}
extern "system" fn gamesave_close_update(_: This, upd: *mut GameSaveUpdate) {
    if !upd.is_null() {
        drop(unsafe { Box::from_raw(upd) });
    }
}
extern "system" fn gamesave_write_blob(
    _: This,
    upd: *mut GameSaveUpdate,
    name: *const c_char,
    data: *const u8,
    size: usize,
) -> HRESULT {
    let Some(u) = (unsafe { upd.as_mut() }) else {
        return E_INVALIDARG;
    };
    let bname = sanitize_name(&cstr_to_string(name));
    let bytes = if data.is_null() || size == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, size) }.to_vec()
    };
    u.writes.push((bname, bytes));
    S_OK
}
extern "system" fn gamesave_delete_blob(
    _: This,
    upd: *mut GameSaveUpdate,
    name: *const c_char,
) -> HRESULT {
    let Some(u) = (unsafe { upd.as_mut() }) else {
        return E_INVALIDARG;
    };
    u.deletes.push(sanitize_name(&cstr_to_string(name)));
    S_OK
}
extern "system" fn gamesave_submit_update(_: This, upd: *mut GameSaveUpdate) -> HRESULT {
    let Some(u) = (unsafe { upd.as_mut() }) else {
        return E_INVALIDARG;
    };
    let _ = fs::create_dir_all(&u.container_dir);
    for (name, bytes) in u.writes.drain(..) {
        let _ = fs::write(u.container_dir.join(name), bytes);
    }
    for name in u.deletes.drain(..) {
        let _ = fs::remove_file(u.container_dir.join(name));
    }
    S_OK
}
extern "system" fn gamesave_submit_update_async(
    this: This,
    upd: *mut GameSaveUpdate,
    block: *mut XAsyncBlock,
) -> HRESULT {
    let hr = gamesave_submit_update(this, upd);
    finish_async_with(block, hr, Vec::new())
}
extern "system" fn gamesave_status_result(_: This, block: *mut XAsyncBlock) -> HRESULT {
    xasync_get_status(&XTHREADING_OBJECT, block, 0)
}

static GAMESAVE_VTABLE: Vtable<30> = {
    let mut t = fill_missing::<30>();
    t[3] = gamesave_init_provider as *const c_void;
    t[4] = gamesave_init_provider_async as *const c_void;
    t[5] = gamesave_init_provider_result as *const c_void;
    t[6] = gamesave_close_provider as *const c_void;
    t[7] = gamesave_get_quota as *const c_void;
    t[8] = gamesave_get_quota_async as *const c_void;
    t[9] = gamesave_get_quota_result as *const c_void;
    t[13] = gamesave_enum_containers as *const c_void;
    t[14] = gamesave_enum_containers as *const c_void;
    t[16] = gamesave_create_container as *const c_void;
    t[17] = gamesave_close_container as *const c_void;
    t[19] = gamesave_enum_blobs as *const c_void;
    t[20] = gamesave_read_blob_async as *const c_void;
    t[23] = gamesave_create_update as *const c_void;
    t[24] = gamesave_close_update as *const c_void;
    t[25] = gamesave_write_blob as *const c_void;
    t[26] = gamesave_delete_blob as *const c_void;
    t[27] = gamesave_submit_update as *const c_void;
    t[28] = gamesave_submit_update_async as *const c_void;
    t[29] = gamesave_status_result as *const c_void;
    Vtable(t)
};

static GAMESAVE_OBJECT: RuntimeObject = RuntimeObject {
    vtable: GAMESAVE_VTABLE.0.as_ptr(),
    area: "XGameSave",
};

// ============================================================================
// 10. XNetworking (`37e56907-...` / `bf2346b2-...`, `Vtable<18>`)
// ============================================================================

const PROVIDER_XNET: Guid = Guid::new(0x37e5_6907, 0x2f10, 0x41e8, [0xb7, 0x2f, 0x36, 0xed, 0xb1, 0x85, 0x33, 0x1a]);
const IID_XNET_2026: Guid = Guid::new(0xbf23_46b2, 0x39af, 0x4658, [0xb5, 0xea, 0x44, 0x71, 0x3c, 0x7e, 0x83, 0xb3]);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XNetworkingConnectivityHint {
    pub connectivity_level: u32,
    pub data_limit_cost: u32,
    pub iana_interface_type: u32,
    pub network_initialized: bool,
    pub approaching_data_limit: bool,
    pub over_data_limit: bool,
    pub roaming: bool,
}

const _: () = assert!(size_of::<XNetworkingConnectivityHint>() == 16);

extern "system" fn xnet_udp_port(_: This, out: *mut u16) -> HRESULT {
    boot_trace("xgameruntime", "XNet::GetPreferredUdpPort", "3074");
    put(out, 3074)
}
extern "system" fn xnet_udp_port_async(_: This, block: *mut XAsyncBlock) -> HRESULT {
    boot_trace("xgameruntime", "XNet::GetPreferredUdpPortAsync", "");
    finish_async_with(block, S_OK, 3074u16.to_le_bytes().to_vec())
}
extern "system" fn xnet_udp_port_result(_: This, _blk: *mut XAsyncBlock, out: *mut u16) -> HRESULT {
    put(out, 3074)
}
extern "system" fn xnet_sec_async(_: This, _url: *const c_void, block: *mut XAsyncBlock) -> HRESULT {
    boot_trace("xgameruntime", "XNet::SecurityInfoAsync", "offline");
    finish_async_with(block, ERROR_NETWORK_UNREACHABLE, Vec::new())
}
extern "system" fn xnet_sec_size(_: This, block: *mut XAsyncBlock, out: *mut usize) -> HRESULT {
    xasync_get_result_size(&XTHREADING_OBJECT, block, out)
}
extern "system" fn xnet_sec_result(
    _: This,
    block: *mut XAsyncBlock,
    _sz: usize,
    _used: *mut usize,
    _out: *mut c_void,
) -> HRESULT {
    xasync_get_status(&XTHREADING_OBJECT, block, 0)
}
extern "system" fn xnet_connectivity_hint(_: This, out: *mut XNetworkingConnectivityHint) -> HRESULT {
    if out.is_null() {
        return E_INVALIDARG;
    }
    boot_trace("xgameruntime", "XNet::GetConnectivityHint", "initialized=true level=1");
    unsafe {
        out.write(XNetworkingConnectivityHint {
            connectivity_level: 1, // LocalAccess / offline
            data_limit_cost: 0,
            iana_interface_type: 0,
            network_initialized: true,
            approaching_data_limit: false,
            over_data_limit: false,
            roaming: false,
        });
    }
    S_OK
}
extern "system" fn xnet_reg_hint(_: This, _q: *const c_void, _ctx: *mut c_void, _cb: *const c_void, tok: *mut u64) -> HRESULT {
    boot_trace("xgameruntime", "XNet::RegisterConnectivityHintChanged", "");
    put(tok, NEXT_TOKEN.fetch_add(1, Ordering::Relaxed))
}
extern "system" fn xnet_unreg_hint(_: This, _tok: u64, _wait: bool) -> bool {
    true
}

static XNET_VTABLE: Vtable<18> = {
    let mut t = fill_missing::<18>();
    t[3] = xnet_udp_port as *const c_void;
    t[4] = xnet_udp_port_async as *const c_void;
    t[5] = xnet_udp_port_result as *const c_void;
    t[8] = xnet_sec_async as *const c_void;
    t[9] = xnet_sec_async as *const c_void;
    t[10] = xnet_sec_size as *const c_void;
    t[11] = xnet_sec_result as *const c_void;
    t[15] = xnet_connectivity_hint as *const c_void; // 0x78
    t[16] = xnet_reg_hint as *const c_void;          // 0x80
    t[17] = xnet_unreg_hint as *const c_void;        // 0x88
    Vtable(t)
};
static XNET_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XNET_VTABLE.0.as_ptr(),
    area: "XNetworking",
};

// ============================================================================
// 11. XPackage (`af406016-...` / `0b9d556e-...`, `Vtable<40>`)
// ============================================================================

const PROVIDER_XPKG: Guid = Guid::new(0xaf40_6016, 0xe850, 0x4aa8, [0xa8, 0x8d, 0x2f, 0x3d, 0xcb, 0x9d, 0xac, 0x7e]);
const IID_XPKG_2026: Guid = Guid::new(0x0b9d_556e, 0xab70, 0x43f4, [0xba, 0xa0, 0x99, 0x99, 0xac, 0x4c, 0xb0, 0x40]);

static PKG_MONITOR: u8 = 0;

extern "system" fn xpkg_current_id(_: This, size: usize, buf: *mut u8) -> HRESULT {
    let id = format!("{TITLE_ID:08X}");
    put_string(&id, size, buf, std::ptr::null_mut())
}
extern "system" fn xpkg_is_packaged(_: This) -> bool {
    true
}
extern "system" fn xpkg_create_monitor(
    _: This,
    _id: *const c_char,
    _sc: u32,
    _sel: *const c_void,
    _int: u32,
    _q: *const c_void,
    out: *mut *const u8,
) -> HRESULT {
    put(out, &raw const PKG_MONITOR)
}
extern "system" fn xpkg_close_monitor(_: This, _m: *const u8) {}
#[repr(C)]
pub struct XPackageInstallationProgress {
    pub total_bytes: u64,
    pub installed_bytes: u64,
    pub launch_bytes: u64,
    pub launchable: bool,
    pub completed: bool,
}

extern "system" fn xpkg_progress(_: This, _m: *const u8, out: *mut XPackageInstallationProgress) {
    if !out.is_null() {
        let bytes = 120u64 * 1024 * 1024 * 1024;
        unsafe {
            out.write(XPackageInstallationProgress {
                total_bytes: bytes,
                installed_bytes: bytes,
                launch_bytes: bytes,
                launchable: true,
                completed: true,
            });
        }
    }
}
extern "system" fn xpkg_register_progress(
    _: This,
    _m: *const u8,
    _ctx: *mut c_void,
    _cb: *const c_void,
    tok: *mut u64,
) -> HRESULT {
    put(tok, NEXT_TOKEN.fetch_add(1, Ordering::Relaxed))
}
extern "system" fn xpkg_unregister_progress(_: This, _m: *const u8, _tok: u64, _wait: bool) -> bool {
    true
}
extern "system" fn xpkg_find_avail(
    _: This,
    _id: *const c_char,
    _sc: u32,
    _sel: *const c_void,
    out: *mut u32,
) -> HRESULT {
    put(out, 0)
}
extern "system" fn xpkg_ok(_: This) -> HRESULT {
    S_OK
}
extern "system" fn xpkg_enumerate(_: This, _kind: u32, _scope: u32, _ctx: *mut c_void, _cb: *const c_void) -> HRESULT {
    S_OK
}

static XPKG_VTABLE: Vtable<40> = {
    let mut t = fill_missing::<40>();
    t[3] = xpkg_current_id as *const c_void;          // 0x18
    t[4] = xpkg_is_packaged as *const c_void;         // 0x20
    t[5] = xpkg_create_monitor as *const c_void;      // 0x28
    t[6] = xpkg_close_monitor as *const c_void;       // 0x30
    t[7] = xpkg_progress as *const c_void;            // 0x38
    t[9] = xpkg_register_progress as *const c_void;   // 0x48
    t[10] = xpkg_unregister_progress as *const c_void;// 0x50
    t[12] = xpkg_find_avail as *const c_void;         // 0x60
    t[14] = xpkg_ok as *const c_void;                 // 0x70
    t[39] = xpkg_enumerate as *const c_void;          // 0x138
    Vtable(t)
};
static XPKG_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XPKG_VTABLE.0.as_ptr(),
    area: "XPackage",
};

// ============================================================================
// 12. XStore (`0dd112ac-...` / `b09d803c-...` & `2d42fea5-...`, `Vtable<77>`)
// ============================================================================

const PROVIDER_XSTORE: Guid = Guid::new(0x0dd1_12ac, 0x7c24, 0x448c, [0xb9, 0x2b, 0x39, 0x60, 0xfb, 0x5b, 0xd3, 0x0c]);
const IID_XSTORE_2026: Guid = Guid::new(0xb09d_803c, 0x2414, 0x4a05, [0x82, 0xc6, 0x66, 0xdf, 0xdc, 0x9e, 0x9a, 0x44]);
const IID_XSTORE_DURABLES: Guid = Guid::new(0x2d42_fea5, 0xe71d, 0x4b76, [0x97, 0xcd, 0xc5, 0x0a, 0xfb, 0xb3, 0xae, 0x5d]);

static STORE_CTX: u8 = 0;
static STORE_LIC: u8 = 0;

#[repr(C)]
pub struct XStoreGameLicense {
    pub sku_store_id: [u8; 18],
    pub is_active: bool,
    pub is_trial_owned_by_this_user: bool,
    pub is_disc_license: bool,
    pub is_trial: bool,
    pub trial_time_remaining_in_seconds: u32,
    pub trial_unique_id: [u8; 64],
    pub expiration_date: i64,
}

extern "system" fn xstore_create_ctx(_: This, _user: *const c_void, out: *mut *const u8) -> HRESULT {
    put(out, &raw const STORE_CTX)
}
extern "system" fn xstore_close(_: This, _h: *const c_void) {}
extern "system" fn xstore_is_license_valid(_: This, _lic: *const c_void) -> bool {
    true
}
extern "system" fn xstore_acquire_pkg_lic_async(_: This, _ctx: *const c_void, _id: *const c_char, block: *mut XAsyncBlock) -> HRESULT {
    finish_async_with(block, S_OK, (&raw const STORE_LIC as usize).to_le_bytes().to_vec())
}
extern "system" fn xstore_acquire_pkg_lic_result(_: This, _blk: *mut XAsyncBlock, out: *mut *const u8) -> HRESULT {
    put(out, &raw const STORE_LIC)
}
extern "system" fn xstore_acquire_durables_lic_async(
    _: This,
    _ctx: *const c_void,
    store_id: *const c_char,
    block: *mut XAsyncBlock,
) -> HRESULT {
    let id_str = if store_id.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(store_id) }.to_string_lossy().into_owned()
    };
    boot_trace(
        "xgameruntime",
        "XStore::AcquireLicenseForDurablesAsync",
        &format!("store_id={id_str} block={block:?}"),
    );
    finish_async_with(block, S_OK, (&raw const STORE_LIC as usize).to_le_bytes().to_vec())
}
extern "system" fn xstore_query_game_lic_async(_: This, _ctx: *const c_void, block: *mut XAsyncBlock) -> HRESULT {
    finish_async_with(block, S_OK, Vec::new())
}
extern "system" fn xstore_query_game_lic_result(_: This, _blk: *mut XAsyncBlock, out: *mut XStoreGameLicense) -> HRESULT {
    if out.is_null() {
        return E_INVALIDARG;
    }
    unsafe { out.write_bytes(0, 1) };
    unsafe { (*out).is_active = true };
    S_OK
}
extern "system" fn xstore_offline_async(_: This, _ctx: *const c_void, block: *mut XAsyncBlock) -> HRESULT {
    finish_async_with(block, XSTORE_NETWORK_ERROR, Vec::new())
}
extern "system" fn xstore_reg_pkg_lic_lost(
    _: This,
    _license: *const c_void,
    _q: *const c_void,
    _ctx: *mut c_void,
    _cb: *const c_void,
    out_token: *mut u64,
) -> HRESULT {
    let tok = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    boot_trace(
        "xgameruntime",
        "XStore::RegisterPackageLicenseLost",
        &format!("token={tok}"),
    );
    put(out_token, tok)
}
extern "system" fn xstore_unreg_pkg_lic_lost(
    _: This,
    _license: *const c_void,
    _token: u64,
    _wait: bool,
) -> bool {
    true
}

static XSTORE_VTABLE: Vtable<77> = {
    let mut t = fill_missing::<77>();
    t[3] = xstore_create_ctx as *const c_void;             // 0x18
    t[4] = xstore_close as *const c_void;                  // 0x20
    t[20] = xstore_acquire_pkg_lic_async as *const c_void; // 0xa0
    t[21] = xstore_acquire_pkg_lic_result as *const c_void;// 0xa8
    t[22] = xstore_is_license_valid as *const c_void;      // 0xb0
    t[28] = xstore_query_game_lic_async as *const c_void;  // 0xe0
    t[29] = xstore_query_game_lic_result as *const c_void; // 0xe8
    t[68] = xstore_reg_pkg_lic_lost as *const c_void;      // 0x220
    t[69] = xstore_unreg_pkg_lic_lost as *const c_void;    // 0x228
    t[71] = xstore_acquire_durables_lic_async as *const c_void; // 0x238
    t[72] = xstore_acquire_pkg_lic_result as *const c_void;     // 0x240
    t[75] = xstore_offline_async as *const c_void;         // 0x258
    Vtable(t)
};
static XSTORE_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XSTORE_VTABLE.0.as_ptr(),
    area: "XStore",
};

// ============================================================================
// 13,14,15,16,17. XGameUi / XDisplayHdr / XShell / XCapture / XSpeech
// ============================================================================

const PROVIDER_XGAMEUI: Guid = Guid::new(0xdfcd_4649, 0x4ff8, 0x4043, [0xba, 0x07, 0x35, 0xd6, 0x07, 0xdf, 0x98, 0xb0]);
const IID_XGAMEUI_2026: Guid = Guid::new(0xeaf6_69df, 0x5542, 0x4590, [0x99, 0xa3, 0x8d, 0xc0, 0x61, 0xf8, 0x37, 0xcc]);
const PROVIDER_HDR: Guid = Guid::new(0x03f0_fe74, 0xfdd9, 0x4e5c, [0xb6, 0x30, 0xf9, 0x33, 0x9c, 0x47, 0xac, 0xc5]);
const IID_HDR: Guid = Guid::new(0x35f0_7670, 0x706e, 0x4bfb, [0x94, 0x76, 0x09, 0x07, 0x98, 0xc5, 0xeb, 0xf3]);
const PROVIDER_SHELL: Guid = Guid::new(0x1b33_9674, 0x328d, 0x4283, [0xa2, 0x00, 0x31, 0x71, 0xf1, 0x8d, 0x36, 0x39]);
const PROVIDER_CAPTURE: Guid = Guid::new(0xa4f1_aee2, 0x4bf1, 0x4485, [0xb0, 0x08, 0xa7, 0xc2, 0x6d, 0x52, 0xac, 0x27]);
const IID_CAPTURE_2026: Guid = Guid::new(0x22e6_72d7, 0xb4e3, 0x406c, [0xbd, 0x50, 0x8f, 0x0d, 0x25, 0x23, 0x6f, 0x9e]);
const PROVIDER_SPEECH: Guid = Guid::new(0x3e24_1977, 0x6237, 0x41e9, [0x85, 0x59, 0x10, 0x2c, 0x2d, 0x99, 0x83, 0xf1]);
const IID_SPEECH: Guid = Guid::new(0xd722_b373, 0x8c4d, 0x4692, [0x9e, 0x51, 0xd6, 0xad, 0x9b, 0x37, 0xaa, 0x7d]);

extern "system" fn xgameui_profile_async(_: This, block: *mut XAsyncBlock, _user: *const c_void, _xuid: u64) -> HRESULT {
    finish_async_with(block, S_OK, Vec::new())
}
extern "system" fn xgameui_cancel_async(_: This, block: *mut XAsyncBlock) -> HRESULT {
    finish_async_with(block, E_ABORT, Vec::new())
}
extern "system" fn xgameui_status(_: This, block: *mut XAsyncBlock) -> HRESULT {
    xasync_get_status(&XTHREADING_OBJECT, block, 0)
}
static XGAMEUI_VTABLE: Vtable<20> = {
    let mut t = fill_missing::<20>();
    t[7] = xgameui_profile_async as *const c_void; // 0x38
    t[8] = xgameui_status as *const c_void;        // 0x40
    t[17] = xgameui_cancel_async as *const c_void; // 0x88
    t[19] = xgameui_status as *const c_void;       // 0x98
    Vtable(t)
};
static XGAMEUI_OBJECT: RuntimeObject = RuntimeObject {
    vtable: XGAMEUI_VTABLE.0.as_ptr(),
    area: "XGameUi",
};

extern "system" fn hdr_try_enable(_: This, _pref: u32, _info: *mut c_void) -> u32 {
    2 // Disabled (SDR)
}
static HDR_VTABLE: Vtable<6> = {
    let mut t = fill_missing::<6>();
    t[4] = hdr_try_enable as *const c_void; // 0x20
    Vtable(t)
};
static HDR_OBJECT: RuntimeObject = RuntimeObject {
    vtable: HDR_VTABLE.0.as_ptr(),
    area: "XDisplayHdr",
};

static DUMMY_DEFERRAL: u8 = 0;
extern "system" fn shell_launch_uri(_: This, _user: *const c_void, _uri: *const c_char) -> HRESULT {
    NOT_SUPPORTED
}
extern "system" fn shell_acquire_deferral(_: This, out: *mut *const u8) -> HRESULT {
    put(out, &raw const DUMMY_DEFERRAL)
}
extern "system" fn shell_close_deferral(_: This, _h: *const u8) {}
static SHELL_VTABLE: Vtable<6> = {
    let mut t = fill_missing::<6>();
    t[3] = shell_launch_uri as *const c_void;       // 0x18
    t[4] = shell_acquire_deferral as *const c_void; // 0x20
    t[5] = shell_close_deferral as *const c_void;   // 0x28
    Vtable(t)
};
static SHELL_OBJECT: RuntimeObject = RuntimeObject {
    vtable: SHELL_VTABLE.0.as_ptr(),
    area: "XShell",
};

extern "system" fn capture_not_supported(_: This) -> HRESULT {
    NOT_SUPPORTED
}
static CAPTURE_VTABLE: Vtable<8> = {
    let mut t = fill_missing::<8>();
    t[5] = capture_not_supported as *const c_void; // 0x28
    Vtable(t)
};
static CAPTURE_OBJECT: RuntimeObject = RuntimeObject {
    vtable: CAPTURE_VTABLE.0.as_ptr(),
    area: "XCapture",
};

const SILENCE_WAV: [u8; 44] =
    *b"RIFF\x24\0\0\0WAVEfmt \x10\0\0\0\x01\0\x01\0\x80\x3e\0\0\0\x7d\0\0\x02\0\x10\0data\0\0\0\0";
static SPEECH_SYNTH: u8 = 0;
static SPEECH_STREAM: u8 = 0;

extern "system" fn speech_enum(_: This, _ctx: *mut c_void, _cb: *const c_void) -> HRESULT {
    S_OK
}
extern "system" fn speech_create(_: This, out: *mut *const u8) -> HRESULT {
    put(out, &raw const SPEECH_SYNTH)
}
extern "system" fn speech_ok(_: This) -> HRESULT {
    S_OK
}
extern "system" fn speech_stream(_: This, _: *const u8, _w: *const c_char, out: *mut *const u8) -> HRESULT {
    put(out, &raw const SPEECH_STREAM)
}
extern "system" fn speech_stream_size(_: This, _: *const u8, out: *mut usize) -> HRESULT {
    put(out, SILENCE_WAV.len())
}
extern "system" fn speech_stream_data(
    _: This,
    _: *const u8,
    size: usize,
    buf: *mut u8,
    used: *mut usize,
) -> HRESULT {
    if buf.is_null() || size < SILENCE_WAV.len() {
        return E_NOT_SUFFICIENT_BUFFER;
    }
    unsafe { buf.copy_from_nonoverlapping(SILENCE_WAV.as_ptr(), SILENCE_WAV.len()) };
    if !used.is_null() {
        unsafe { used.write(SILENCE_WAV.len()) };
    }
    S_OK
}

static SPEECH_VTABLE: Vtable<22> = {
    let mut t = fill_missing::<22>();
    t[8] = speech_enum as *const c_void;
    t[9] = speech_create as *const c_void;
    t[10] = speech_ok as *const c_void;
    t[11] = speech_ok as *const c_void;
    t[12] = speech_ok as *const c_void;
    t[13] = speech_stream as *const c_void;
    t[14] = speech_ok as *const c_void;
    t[15] = speech_stream_size as *const c_void;
    t[16] = speech_stream_data as *const c_void;
    t[21] = speech_stream as *const c_void;
    Vtable(t)
};
static SPEECH_OBJECT: RuntimeObject = RuntimeObject {
    vtable: SPEECH_VTABLE.0.as_ptr(),
    area: "XSpeech",
};

// ============================================================================
// Exported 6 `xgameruntime.dll` ABI entry points
// ============================================================================

#[unsafe(no_mangle)]
pub extern "system" fn InitializeApiImpl(version: u64, build: u64) -> HRESULT {
    let _ = ensure_data_dirs();
    INIT_VERSION.store(version, Ordering::Relaxed);
    INIT_BUILD.store(build, Ordering::Relaxed);
    INITIALIZED.store(true, Ordering::Release);
    boot_trace_hr(
        "xgameruntime",
        "InitializeApiImpl",
        S_OK,
        &format!("ver={version} build={build}"),
    );
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn InitializeApiImplEx(version: u64, build: u64, flags: u64) -> HRESULT {
    INIT_FLAGS.store(flags, Ordering::Relaxed);
    boot_trace(
        "xgameruntime",
        "InitializeApiImplEx",
        &format!("ver={version} build={build} flags={flags:#x}"),
    );
    InitializeApiImpl(version, build)
}

#[unsafe(no_mangle)]
pub extern "system" fn InitializeApiImplEx2(
    version: u64,
    build: u64,
    flags: u64,
    _options: *const c_void,
) -> HRESULT {
    boot_trace(
        "xgameruntime",
        "InitializeApiImplEx2",
        &format!("ver={version} build={build} flags={flags:#x}"),
    );
    InitializeApiImplEx(version, build, flags)
}

#[unsafe(no_mangle)]
pub extern "system" fn UninitializeApiImpl() -> HRESULT {
    INITIALIZED.store(false, Ordering::Release);
    boot_trace_hr("xgameruntime", "UninitializeApiImpl", S_OK, "");
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn QueryApiImpl(
    provider: *const Guid,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let (Some(&prov), Some(&id)) = (unsafe { provider.as_ref() }, unsafe { iid.as_ref() }) else {
        unsafe { *out = std::ptr::null_mut() };
        return NOT_SUPPORTED;
    };

    let matched: Option<&'static RuntimeObject> = match (prov, id) {
        (p, i) if p == PROVIDER_XTHREADING && i == PROVIDER_XTHREADING => Some(&XTHREADING_OBJECT),
        (p, i) if p == PROVIDER_XGAME && i == IID_XGAME => Some(&XGAME_OBJECT),
        (p, i) if p == PROVIDER_XFEATURE && i == PROVIDER_XFEATURE => Some(&XFEATURE_OBJECT),
        (p, i) if p == PROVIDER_XEVENT && i == PROVIDER_XEVENT => Some(&XEVENT_OBJECT),
        (p, i) if p == PROVIDER_XSYSTEM && (i == IID_XSYSTEM || i == IID_XSYSTEM_2026) => {
            Some(&XSYSTEM_OBJECT)
        }
        (p, i) if p == PROVIDER_ANALYTICS && i == PROVIDER_ANALYTICS => Some(&XANALYTICS_OBJECT),
        (p, i) if p == PROVIDER_XUSER && (i == IID_XUSER || i == PROVIDER_XUSER) => {
            Some(&XUSER_OBJECT)
        }
        (p, i) if p == PROVIDER_XUSER && i == IID_XUSER_GAMERTAG => Some(&XUSER_GAMERTAG_OBJECT),
        (p, i) if p == PROVIDER_XUSER_DEV && i == IID_XUSER_DEV => Some(&XUSER_DEV_OBJECT),
        (p, i) if p == PROVIDER_STORAGE && (i == IID_STORAGE || i == IID_STORAGE_2026) => {
            Some(&STORAGE_OBJECT)
        }
        (p, i) if p == PROVIDER_GAMESAVE && (i == PROVIDER_GAMESAVE || i == IID_GAMESAVE_2026) => {
            Some(&GAMESAVE_OBJECT)
        }
        (p, i) if p == PROVIDER_XNET && (i == PROVIDER_XNET || i == IID_XNET_2026) => {
            Some(&XNET_OBJECT)
        }
        (p, i) if p == PROVIDER_XPKG && i == IID_XPKG_2026 => Some(&XPKG_OBJECT),
        (p, i)
            if p == PROVIDER_XSTORE
                && (i == IID_XSTORE_2026 || i == IID_XSTORE_DURABLES) =>
        {
            Some(&XSTORE_OBJECT)
        }
        (p, i) if p == PROVIDER_XGAMEUI && i == IID_XGAMEUI_2026 => Some(&XGAMEUI_OBJECT),
        (p, i) if p == PROVIDER_HDR && i == IID_HDR => Some(&HDR_OBJECT),
        (p, i) if p == PROVIDER_SHELL && i == PROVIDER_SHELL => Some(&SHELL_OBJECT),
        (p, i) if p == PROVIDER_CAPTURE && i == IID_CAPTURE_2026 => Some(&CAPTURE_OBJECT),
        (p, i) if p == PROVIDER_SPEECH && i == IID_SPEECH => Some(&SPEECH_OBJECT),
        _ => None,
    };

    if let Some(obj) = matched {
        boot_trace_hr(
            "xgameruntime",
            "QueryApiImpl",
            S_OK,
            &format!("area={} prov={} iid={}", obj.area, prov.format_guid(), id.format_guid()),
        );
        unsafe { *out = (obj as *const RuntimeObject).cast_mut().cast() };
        S_OK
    } else {
        boot_trace_hr(
            "xgameruntime",
            "QueryApiImpl",
            NOT_SUPPORTED,
            &format!("UNSUPPORTED prov={} iid={}", prov.format_guid(), id.format_guid()),
        );
        unsafe { *out = std::ptr::null_mut() };
        NOT_SUPPORTED
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn XErrorReport(hr: HRESULT, message: *const c_char) -> HRESULT {
    ERROR_REPORT_COUNT.fetch_add(1, Ordering::Relaxed);
    let msg = cstr_to_string(message);
    boot_trace(
        "xgameruntime",
        "XErrorReport",
        &format!("hr={:#010x} msg={msg}", hr as u32),
    );
    let root = ensure_data_dirs();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("xerror_report.log"))
    {
        let _ = writeln!(f, "[{ts}] hr={:#010x} msg={msg}", hr as u32);
    }
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_query_all_18_pairs_and_localappdata_storage_work() {
        let tmp = std::env::temp_dir().join(format!("xgr_test_{}", std::process::id()));
        unsafe { std::env::set_var("LUCIAS_PROJECT_DATA_DIR", &tmp) };

        assert_eq!(InitializeApiImplEx2(26100, 7901, 0, std::ptr::null()), S_OK);
        assert!(is_initialized());

        let pairs = [
            (PROVIDER_XTHREADING, PROVIDER_XTHREADING),
            (PROVIDER_XGAME, IID_XGAME),
            (PROVIDER_XFEATURE, PROVIDER_XFEATURE),
            (PROVIDER_XEVENT, PROVIDER_XEVENT),
            (PROVIDER_XSYSTEM, IID_XSYSTEM_2026),
            (PROVIDER_ANALYTICS, PROVIDER_ANALYTICS),
            (PROVIDER_XUSER, PROVIDER_XUSER),
            (PROVIDER_XUSER, IID_XUSER_GAMERTAG),
            (PROVIDER_XUSER_DEV, IID_XUSER_DEV),
            (PROVIDER_STORAGE, IID_STORAGE_2026),
            (PROVIDER_GAMESAVE, IID_GAMESAVE_2026),
            (PROVIDER_XNET, IID_XNET_2026),
            (PROVIDER_XPKG, IID_XPKG_2026),
            (PROVIDER_XSTORE, IID_XSTORE_2026),
            (PROVIDER_XSTORE, IID_XSTORE_DURABLES),
            (PROVIDER_XGAMEUI, IID_XGAMEUI_2026),
            (PROVIDER_HDR, IID_HDR),
            (PROVIDER_SHELL, PROVIDER_SHELL),
            (PROVIDER_CAPTURE, IID_CAPTURE_2026),
            (PROVIDER_SPEECH, IID_SPEECH),
        ];
        for (p, i) in pairs {
            let mut obj = std::ptr::null_mut();
            assert_eq!(QueryApiImpl(&p, &i, &mut obj), S_OK, "failed {}", p.format_guid());
            assert!(!obj.is_null());
        }

        // Verify XSystemAnalytics returns RDX in RAX with 0x90-byte info.
        let mut analytics_obj: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            QueryApiImpl(&PROVIDER_ANALYTICS, &PROVIDER_ANALYTICS, &mut analytics_obj),
            S_OK
        );
        let a_vtbl = unsafe { *analytics_obj.cast::<*const *const c_void>() };
        type AnalyticsFn = unsafe extern "system" fn(*const c_void, *mut XSystemAnalyticsInfo) -> *mut XSystemAnalyticsInfo;
        let get_info: AnalyticsFn = unsafe { std::mem::transmute(*a_vtbl.add(3)) };
        let mut info = unsafe { std::mem::zeroed::<XSystemAnalyticsInfo>() };
        let ret = unsafe { get_info(analytics_obj, &mut info) };
        assert_eq!(ret, &raw mut info);
        assert_eq!(info.os_version.build, 26100);

        // Verify XNetworkingConnectivityHint places network_initialized at +0x0C (16B total)
        assert_eq!(size_of::<XNetworkingConnectivityHint>(), 16);
        assert_eq!(
            std::mem::offset_of!(XNetworkingConnectivityHint, network_initialized),
            0x0C
        );
        let mut net_obj: *mut c_void = std::ptr::null_mut();
        assert_eq!(QueryApiImpl(&PROVIDER_XNET, &IID_XNET_2026, &mut net_obj), S_OK);
        let n_vtbl = unsafe { *net_obj.cast::<*const *const c_void>() };
        type HintFn = unsafe extern "system" fn(*const c_void, *mut XNetworkingConnectivityHint) -> HRESULT;
        let get_hint: HintFn = unsafe { std::mem::transmute(*n_vtbl.add(15)) };
        let mut hint = unsafe { std::mem::zeroed::<XNetworkingConnectivityHint>() };
        assert_eq!(unsafe { get_hint(net_obj, &mut hint) }, S_OK);
        assert!(hint.network_initialized && hint.connectivity_level == 1);

        // Verify XAsyncRun + XAsyncGetStatus(wait=true) + process queue refcounting
        let mut pq: *const TaskQueue = std::ptr::null();
        assert!(xtaskqueue_get_process_queue(&XTHREADING_OBJECT, &mut pq));
        assert!(!pq.is_null());
        xtaskqueue_close(&XTHREADING_OBJECT, pq.cast_mut());
        extern "system" fn sample_work(_b: *mut XAsyncBlock) -> HRESULT {
            S_OK
        }
        let mut blk = XAsyncBlock {
            queue: std::ptr::null(),
            context: std::ptr::null_mut(),
            callback: None,
            internal: [0; 4],
        };
        assert_eq!(xasync_run(&XTHREADING_OBJECT, &mut blk, Some(sample_work)), S_OK);
        assert_eq!(xasync_get_status(&XTHREADING_OBJECT, &mut blk, 1), S_OK);

        assert_eq!(XErrorReport(E_FAIL, c"test runtime error".as_ptr()), S_OK);
        assert!(tmp.join("xerror_report.log").exists());
        assert_eq!(UninitializeApiImpl(), S_OK);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn xuser_vtable_slots_5_through_14_match_gdk_table() {
        let mut xuser_obj: *mut c_void = std::ptr::null_mut();
        assert_eq!(QueryApiImpl(&PROVIDER_XUSER, &IID_XUSER, &mut xuser_obj), S_OK);
        let vtbl = unsafe { *xuser_obj.cast::<*const *const c_void>() };

        type CompareFn = unsafe extern "system" fn(*const c_void, *const c_void, *const c_void, *mut i32) -> HRESULT;
        type MaxUsersFn = unsafe extern "system" fn(*const c_void, *mut u32) -> HRESULT;
        type AddAsyncFn = unsafe extern "system" fn(*const c_void, u32, *mut XAsyncBlock) -> HRESULT;
        type AddResultFn = unsafe extern "system" fn(*const c_void, *mut XAsyncBlock, *mut *const c_void) -> HRESULT;
        type GetU64Fn = unsafe extern "system" fn(*const c_void, *const c_void, *mut u64) -> HRESULT;
        type FindByU64Fn = unsafe extern "system" fn(*const c_void, u64, *mut *const c_void) -> HRESULT;
        type GetBoolFn = unsafe extern "system" fn(*const c_void, *const c_void, *mut bool) -> HRESULT;
        type GetU32Fn = unsafe extern "system" fn(*const c_void, *const c_void, *mut u32) -> HRESULT;

        unsafe {
            let mut blk = XAsyncBlock {
                queue: std::ptr::null(),
                context: std::ptr::null_mut(),
                callback: None,
                internal: [0; 4],
            };
            let add_async: AddAsyncFn = std::mem::transmute(*vtbl.add(7));
            assert_eq!(add_async(xuser_obj, 0, &mut blk), S_OK);
            let mut user_handle: *const c_void = std::ptr::null();
            let add_res: AddResultFn = std::mem::transmute(*vtbl.add(8));
            assert_eq!(add_res(xuser_obj, &mut blk, &mut user_handle), S_OK);
            assert!(!user_handle.is_null());

            let compare: CompareFn = std::mem::transmute(*vtbl.add(5));
            let mut cmp = -99i32;
            assert_eq!(compare(xuser_obj, user_handle, user_handle, &mut cmp), S_OK);
            assert_eq!(cmp, 0);

            let max_users: MaxUsersFn = std::mem::transmute(*vtbl.add(6));
            let mut max_u = 0u32;
            assert_eq!(max_users(xuser_obj, &mut max_u), S_OK);
            assert_eq!(max_u, 4);

            let get_local: GetU64Fn = std::mem::transmute(*vtbl.add(9));
            let mut local_id = 0u64;
            assert_eq!(get_local(xuser_obj, user_handle, &mut local_id), S_OK);
            assert_eq!(local_id, 1);

            let find_local: FindByU64Fn = std::mem::transmute(*vtbl.add(10));
            let mut by_local: *const c_void = std::ptr::null();
            assert_eq!(find_local(xuser_obj, local_id, &mut by_local), S_OK);
            assert_eq!(by_local, user_handle);

            let get_id: GetU64Fn = std::mem::transmute(*vtbl.add(11));
            let mut xuid = 0u64;
            assert_eq!(get_id(xuser_obj, user_handle, &mut xuid), S_OK);
            assert_eq!(xuid, 0x0009_0000_0000_0001);

            let find_id: FindByU64Fn = std::mem::transmute(*vtbl.add(12));
            let mut by_id: *const c_void = std::ptr::null();
            assert_eq!(find_id(xuser_obj, xuid, &mut by_id), S_OK);
            assert_eq!(by_id, user_handle);

            let get_guest: GetBoolFn = std::mem::transmute(*vtbl.add(13));
            let mut guest = true;
            assert_eq!(get_guest(xuser_obj, user_handle, &mut guest), S_OK);
            assert!(!guest);

            let get_state: GetU32Fn = std::mem::transmute(*vtbl.add(14));
            let mut state = 99u32;
            assert_eq!(get_state(xuser_obj, user_handle, &mut state), S_OK);
            assert_eq!(state, 0);
        }
    }

    #[test]
    fn xstore_slots_71_and_72_acquire_durables_license() {
        let mut store_obj: *mut c_void = std::ptr::null_mut();
        assert_eq!(QueryApiImpl(&PROVIDER_XSTORE, &IID_XSTORE_DURABLES, &mut store_obj), S_OK);
        let vtbl = unsafe { *store_obj.cast::<*const *const c_void>() };
        type AcquireDurAsyncFn = unsafe extern "system" fn(*const c_void, *const c_void, *const c_char, *mut XAsyncBlock) -> HRESULT;
        type AcquireDurResFn = unsafe extern "system" fn(*const c_void, *mut XAsyncBlock, *mut *const u8) -> HRESULT;
        let mut blk = XAsyncBlock {
            queue: std::ptr::null(),
            context: std::ptr::null_mut(),
            callback: None,
            internal: [0; 4],
        };
        unsafe {
            let acq_async: AcquireDurAsyncFn = std::mem::transmute(*vtbl.add(71));
            assert_eq!(acq_async(store_obj, &raw const STORE_CTX as *const c_void, c"9NBLGGH5L9XT".as_ptr(), &mut blk), S_OK);
            let mut lic: *const u8 = std::ptr::null();
            let acq_res: AcquireDurResFn = std::mem::transmute(*vtbl.add(72));
            assert_eq!(acq_res(store_obj, &mut blk, &mut lic), S_OK);
            assert_eq!(lic, &raw const STORE_LIC);

            type RegLostFn = unsafe extern "system" fn(*const c_void, *const c_void, *const c_void, *mut c_void, *const c_void, *mut u64) -> HRESULT;
            type UnregLostFn = unsafe extern "system" fn(*const c_void, *const c_void, u64, bool) -> bool;
            let reg_lost: RegLostFn = std::mem::transmute(*vtbl.add(68));
            let unreg_lost: UnregLostFn = std::mem::transmute(*vtbl.add(69));
            let mut tok = 0u64;
            assert_eq!(
                reg_lost(store_obj, lic.cast(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), &mut tok),
                S_OK
            );
            assert_ne!(tok, 0);
            assert!(unreg_lost(store_obj, lic.cast(), tok, true));
        }
    }
}
