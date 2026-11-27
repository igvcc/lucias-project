#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use shim_common::{E_INVALIDARG, E_OUTOFMEMORY, E_POINTER, HRESULT, S_OK};

const CONVOLUTION: u32 = 1;
const STEREO_OPTIONS: u32 = 2 | 8;
const NOT_FOR_CONVOLUTION: u32 = 4;

struct DspJob {
    input_addr: usize,
    output_addr: usize,
    samples: usize,
    gains: [f32; 2],
    channels: u32,
    status_addr: usize,
    ticket: u32,
    inflight: Arc<AtomicU32>,
}

struct AsyncQueueInner {
    jobs: Mutex<VecDeque<DspJob>>,
    cv: Condvar,
    shutdown: AtomicBool,
}

pub struct Dsp {
    max_streams: u32,
    active: Mutex<u32>,
    queue: Arc<AsyncQueueInner>,
    worker: Option<JoinHandle<()>>,
}

#[repr(C, packed)]
pub struct StreamDesc {
    pub kind: u32,
    pub options: u32,
    pub frames: u32,
    pub channels: u32,
    pub ir_floats: u32,
    pub ir: *const f32,
}

#[repr(C)]
pub struct Status {
    pub submitted: u32,
    pub completed: u32,
    pub reserved: u32,
    pub result: HRESULT,
}

pub struct Stream {
    dsp: *mut Dsp,
    frames: u32,
    channels: u32,
    status: Box<Status>,
    inflight: Arc<AtomicU32>,
}

#[repr(C)]
pub struct Command {
    pub gains: [f32; 2],
    pub input: *const f32,
    pub output: *mut f32,
    pub reserved: u64,
}

/// Real zlib decompression helper (via `zlib-rs`) for compressed DSP/asset payloads.
pub fn inflate_zlib_payload(compressed: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; max_output.max(64)];
    let (res, rc) =
        zlib_rs::decompress_slice(&mut out, compressed, zlib_rs::InflateConfig::default());
    if rc == zlib_rs::ReturnCode::Ok {
        Ok(res.to_vec())
    } else {
        Err(format!("zlib-rs decompress failed: {rc:?}"))
    }
}

/// Real zlib compression helper (via `zlib-rs`).
pub fn deflate_zlib_payload(raw: &[u8]) -> Result<Vec<u8>, String> {
    let bound = zlib_rs::compress_bound(raw.len());
    let mut out = vec![0u8; bound];
    let (res, rc) = zlib_rs::compress_slice(&mut out, raw, zlib_rs::DeflateConfig::default());
    if rc == zlib_rs::ReturnCode::Ok {
        Ok(res.to_vec())
    } else {
        Err(format!("zlib-rs compress failed: {rc:?}"))
    }
}

fn process_dsp_job(job: &DspJob) {
    if job.output_addr != 0 && job.samples > 0 {
        let out_ptr = job.output_addr as *mut f32;
        if job.input_addr != 0 {
            let in_ptr = job.input_addr as *const f32;
            let ch = (job.channels as usize).max(1);
            for i in 0..job.samples {
                let g = job.gains[i % ch];
                unsafe {
                    let s = *in_ptr.add(i);
                    out_ptr.add(i).write(s * g);
                }
            }
        } else {
            unsafe { std::ptr::write_bytes(out_ptr, 0, job.samples) };
        }
    }
    if job.status_addr != 0 {
        let status = unsafe { &mut *(job.status_addr as *mut Status) };
        unsafe {
            std::ptr::write_volatile(&mut status.result, S_OK);
            std::ptr::write_volatile(&mut status.completed, job.ticket);
        }
    }
    job.inflight.fetch_sub(1, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "system" fn XDspConnectWithMaximumStreamLimit(
    base: *mut c_void,
    base_length: u32,
    ir_seconds: u32,
    max_streams: u32,
    max_channels: u32,
    out: *mut *mut Dsp,
) -> HRESULT {
    if base.is_null()
        || !(0x1_0000..=0x1F40_0000).contains(&base_length)
        || ir_seconds > 0x80
        || max_streams > 0x100
        || max_channels > 2
    {
        return E_INVALIDARG;
    }
    if out.is_null() {
        return E_POINTER;
    }

    let queue = Arc::new(AsyncQueueInner {
        jobs: Mutex::new(VecDeque::new()),
        cv: Condvar::new(),
        shutdown: AtomicBool::new(false),
    });
    let q_worker = Arc::clone(&queue);
    let worker = std::thread::Builder::new()
        .name("chad_pc_dsp_queue".into())
        .spawn(move || loop {
            let job = {
                let mut g = q_worker.jobs.lock().unwrap_or_else(|e| e.into_inner());
                while g.is_empty() && !q_worker.shutdown.load(Ordering::Acquire) {
                    g = q_worker.cv.wait(g).unwrap_or_else(|e| e.into_inner());
                }
                if q_worker.shutdown.load(Ordering::Acquire) && g.is_empty() {
                    return;
                }
                g.pop_front()
            };
            if let Some(j) = job {
                process_dsp_job(&j);
            }
        })
        .ok();

    let dsp = Box::new(Dsp {
        max_streams,
        active: Mutex::new(0),
        queue,
        worker,
    });
    shim_common::boot_trace(
        "chad_pc",
        "XDspConnectWithMaximumStreamLimit",
        &format!("base_len={base_length:#x} max_streams={max_streams}"),
    );
    unsafe { out.write(Box::into_raw(dsp)) };
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XDspDisconnect(dsp: *mut Dsp) -> HRESULT {
    if dsp.is_null() {
        return E_INVALIDARG;
    }
    let mut d = unsafe { Box::from_raw(dsp) };
    d.queue.shutdown.store(true, Ordering::Release);
    d.queue.cv.notify_all();
    if let Some(handle) = d.worker.take() {
        let _ = handle.join();
    }
    S_OK
}

fn valid_desc(desc: &StreamDesc) -> bool {
    let (kind, options, frames, channels) = (desc.kind, desc.options, desc.frames, desc.channels);
    let shape = if kind == CONVOLUTION {
        (1..=2).contains(&channels)
            && matches!(frames, 0x200 | 0x400)
            && (options & NOT_FOR_CONVOLUTION) == 0
    } else {
        channels == 1 && matches!(frames, 0x200 | 0x400 | 0x800)
    };
    shape && ((options & STEREO_OPTIONS) == 0 || channels == 2)
}

#[unsafe(no_mangle)]
pub extern "system" fn XDspActivate(
    dsp: *mut Dsp,
    desc: *const StreamDesc,
    status: *mut *const Status,
    stream: *mut *mut Stream,
) -> HRESULT {
    if status.is_null() || stream.is_null() {
        return E_POINTER;
    }
    if dsp.is_null() || desc.is_null() {
        return E_INVALIDARG;
    }
    let desc_ref = unsafe { &*desc };
    if !valid_desc(desc_ref) {
        return E_INVALIDARG;
    }
    {
        let dsp_ref = unsafe { &*dsp };
        let mut active = dsp_ref.active.lock().unwrap_or_else(|e| e.into_inner());
        if *active >= dsp_ref.max_streams {
            return E_OUTOFMEMORY;
        }
        *active += 1;
    }
    let s = Box::new(Stream {
        dsp,
        frames: desc_ref.frames,
        channels: desc_ref.channels,
        status: Box::new(Status {
            submitted: 0,
            completed: 0,
            reserved: 0,
            result: S_OK,
        }),
        inflight: Arc::new(AtomicU32::new(0)),
    });
    unsafe {
        status.write(&*s.status);
        stream.write(Box::into_raw(s));
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XDspDeactivate(stream: *mut Stream) -> HRESULT {
    if stream.is_null() {
        return E_INVALIDARG;
    }
    let s = unsafe { Box::from_raw(stream) };
    // Drain any in-flight async DSP jobs referencing `s.status` before dropping `Box<Status>`.
    while s.inflight.load(Ordering::Acquire) > 0 {
        std::thread::yield_now();
    }
    let dsp_ref = unsafe { &*s.dsp };
    let mut active = dsp_ref.active.lock().unwrap_or_else(|e| e.into_inner());
    *active = active.saturating_sub(1);
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XDspSubmitCommand(
    stream: *mut Stream,
    command: *const Command,
    ticket: *mut u32,
) -> HRESULT {
    if stream.is_null() || command.is_null() {
        return E_INVALIDARG;
    }
    let (s, cmd) = unsafe { (&mut *stream, &*command) };
    let next = s.status.submitted.wrapping_add(1);
    unsafe {
        std::ptr::write_volatile(&mut s.status.submitted, next);
    }
    if !ticket.is_null() {
        unsafe { ticket.write(next) };
    }

    s.inflight.fetch_add(1, Ordering::AcqRel);
    let job = DspJob {
        input_addr: cmd.input as usize,
        output_addr: cmd.output as usize,
        samples: (s.frames * s.channels) as usize,
        gains: cmd.gains,
        channels: s.channels,
        status_addr: (&raw mut *s.status) as usize,
        ticket: next,
        inflight: Arc::clone(&s.inflight),
    };

    let dsp_ref = unsafe { &*s.dsp };
    if dsp_ref.worker.is_some() {
        let mut g = dsp_ref.queue.jobs.lock().unwrap_or_else(|e| e.into_inner());
        g.push_back(job);
        dsp_ref.queue.cv.notify_one();
    } else {
        process_dsp_job(&job);
    }
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_dsp_queue_and_zlib_roundtrip_work() {
        let compressed = deflate_zlib_payload(b"LUCIAS_PROJECT_CHAD_DSP_IMPULSE").unwrap();
        let inflated = inflate_zlib_payload(&compressed, 128).unwrap();
        assert_eq!(inflated, b"LUCIAS_PROJECT_CHAD_DSP_IMPULSE");

        let mut arena = vec![0u8; 0x2_0000];
        let mut dsp = std::ptr::null_mut();
        assert_eq!(
            XDspConnectWithMaximumStreamLimit(
                arena.as_mut_ptr().cast(),
                arena.len() as u32,
                2,
                8,
                2,
                &mut dsp
            ),
            S_OK
        );
        let desc = StreamDesc {
            kind: CONVOLUTION,
            options: 0,
            frames: 0x200,
            channels: 2,
            ir_floats: 0,
            ir: std::ptr::null(),
        };
        let mut status: *const Status = std::ptr::null();
        let mut stream = std::ptr::null_mut();
        assert_eq!(XDspActivate(dsp, &desc, &mut status, &mut stream), S_OK);

        let inp = vec![0.5f32; 0x400];
        let mut out = vec![0.0f32; 0x400];
        let cmd = Command {
            gains: [2.0, 0.5],
            input: inp.as_ptr(),
            output: out.as_mut_ptr(),
            reserved: 0,
        };
        let mut ticket = 0u32;
        assert_eq!(XDspSubmitCommand(stream, &cmd, &mut ticket), S_OK);
        assert_eq!(ticket, 1);

        // Wait briefly for worker thread to complete ticket 1.
        for _ in 0..200 {
            if unsafe { std::ptr::read_volatile(&(*status).completed) } >= 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(unsafe { std::ptr::read_volatile(&(*status).completed) }, 1);
        assert!((out[0] - 1.0).abs() < 1e-5);
        assert!((out[1] - 0.25).abs() < 1e-5);

        assert_eq!(XDspDeactivate(stream), S_OK);
        assert_eq!(XDspDisconnect(dsp), S_OK);
    }
}
