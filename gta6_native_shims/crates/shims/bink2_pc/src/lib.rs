#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::OnceLock;

use shim_common::translate_virtual_path_str;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

static REAL_BINK: OnceLock<usize> = OnceLock::new();

fn bink2w64() -> HMODULE {
    let addr = *REAL_BINK.get_or_init(|| {
        let name: Vec<u16> = "bink2w64.dll\0".encode_utf16().collect();
        let h = unsafe { LoadLibraryW(name.as_ptr()) };
        h as usize
    });
    addr as HMODULE
}

unsafe fn proc_or_none<F: Copy>(sym: &CStr) -> Option<F> {
    let h = bink2w64();
    if h.is_null() {
        return None;
    }
    let addr = unsafe { GetProcAddress(h, sym.as_ptr().cast()) }?;
    Some(unsafe { std::mem::transmute_copy(&addr) })
}

pub fn has_native_bink2w64() -> bool {
    !bink2w64().is_null()
}

#[repr(C)]
pub struct BinkHandle {
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub frame_num: u32,
    pub last_frame_num: u32,
    pub frame_rate: u32,
    pub frame_rate_div: u32,
    pub read_error: u32,
    pub open_flags: u32,
    pub paused: u32,
    pub will_loop: i32,
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkOpenWithOptions(
    name: *const c_char,
    open_options: *const c_void,
    flags: u32,
) -> *mut BinkHandle {
    let translated = if name.is_null() {
        None
    } else {
        let raw = unsafe { CStr::from_ptr(name) }.to_string_lossy();
        translate_virtual_path_str(&raw).and_then(|s| CString::new(s).ok())
    };
    let effective_name = translated.as_ref().map_or(name, |c| c.as_ptr());
    let name_log = if effective_name.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(effective_name) }.to_string_lossy().into_owned()
    };
    shim_common::boot_trace("bink2_pc", "BinkOpenWithOptions", &format!("file={name_log} flags={flags:#x}"));

    type FnTy = extern "C" fn(*const c_char, *const c_void, u32) -> *mut BinkHandle;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkOpenWithOptions") } {
        return f(effective_name, open_options, flags);
    }

    let bink = Box::new(BinkHandle {
        width: 1920,
        height: 1080,
        frames: 1,
        frame_num: 1,
        last_frame_num: 1,
        frame_rate: 60,
        frame_rate_div: 1,
        read_error: 0,
        open_flags: flags,
        paused: 0,
        will_loop: 0,
    });
    Box::into_raw(bink)
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkClose(bink: *mut BinkHandle) {
    type FnTy = extern "C" fn(*mut BinkHandle);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkClose") } {
        f(bink);
        return;
    }
    if !bink.is_null() {
        drop(unsafe { Box::from_raw(bink) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkDoFrame(bink: *mut BinkHandle) -> i32 {
    type FnTy = extern "C" fn(*mut BinkHandle) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkDoFrame") } {
        return f(bink);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkDoFrameAsyncMulti(
    bink: *mut BinkHandle,
    threads: *const u32,
    thread_count: i32,
) -> i32 {
    type FnTy = extern "C" fn(*mut BinkHandle, *const u32, i32) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkDoFrameAsyncMulti") } {
        return f(bink, threads, thread_count);
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkDoFrameAsyncWait(bink: *mut BinkHandle, us: i32) -> i32 {
    type FnTy = extern "C" fn(*mut BinkHandle, i32) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkDoFrameAsyncWait") } {
        return f(bink, us);
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkFreeGlobals() {
    type FnTy = extern "C" fn();
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkFreeGlobals") } {
        f();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkGetFrameBuffersInfo(bink: *mut BinkHandle, fb_set: *mut u8) {
    type FnTy = extern "C" fn(*mut BinkHandle, *mut u8);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkGetFrameBuffersInfo") } {
        f(bink, fb_set);
        return;
    }
    if !fb_set.is_null() {
        unsafe { std::ptr::write_bytes(fb_set, 0, 256) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkGetKeyFrame(bink: *mut BinkHandle, frame: u32, flags: i32) -> u32 {
    type FnTy = extern "C" fn(*mut BinkHandle, u32, i32) -> u32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkGetKeyFrame") } {
        return f(bink, frame, flags);
    }
    frame.max(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkGetPlatformInfo(bink_param: i32, info: *mut c_void) -> *const c_void {
    type FnTy = extern "C" fn(i32, *mut c_void) -> *const c_void;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkGetPlatformInfo") } {
        return f(bink_param, info);
    }
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkGoto(bink: *mut BinkHandle, frame: u32, flags: i32) {
    type FnTy = extern "C" fn(*mut BinkHandle, u32, i32);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkGoto") } {
        f(bink, frame, flags);
        return;
    }
    if let Some(b) = unsafe { bink.as_mut() } {
        b.frame_num = frame.max(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkNextFrame(bink: *mut BinkHandle) {
    type FnTy = extern "C" fn(*mut BinkHandle);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkNextFrame") } {
        f(bink);
        return;
    }
    if let Some(b) = unsafe { bink.as_mut() } {
        b.frame_num = (b.frame_num % b.frames.max(1)) + 1;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkPause(bink: *mut BinkHandle, pause: i32) -> i32 {
    type FnTy = extern "C" fn(*mut BinkHandle, i32) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkPause") } {
        return f(bink, pause);
    }
    if let Some(b) = unsafe { bink.as_mut() } {
        b.paused = (pause != 0) as u32;
        return b.paused as i32;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkRegisterFrameBuffers(bink: *mut BinkHandle, fb_set: *mut c_void) {
    type FnTy = extern "C" fn(*mut BinkHandle, *mut c_void);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkRegisterFrameBuffers") } {
        f(bink, fb_set);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkRequestStopAsyncThreadsMulti(threads: *const u32, count: i32) -> i32 {
    type FnTy = extern "C" fn(*const u32, i32) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkRequestStopAsyncThreadsMulti") } {
        return f(threads, count);
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkSetMemory(alloc: *const c_void, free: *const c_void) {
    type FnTy = extern "C" fn(*const c_void, *const c_void);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkSetMemory") } {
        f(alloc, free);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkSetOSFileCallbacks(callbacks: *const c_void) {
    type FnTy = extern "C" fn(*const c_void);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkSetOSFileCallbacks") } {
        f(callbacks);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkSetSoundSystem(open: *const c_void, param: usize) -> i32 {
    type FnTy = extern "C" fn(*const c_void, usize) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkSetSoundSystem") } {
        return f(open, param);
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkSetVolume(bink: *mut BinkHandle, track_id: u32, volume: i32) {
    type FnTy = extern "C" fn(*mut BinkHandle, u32, i32);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkSetVolume") } {
        f(bink, track_id, volume);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkSetWillLoop(bink: *mut BinkHandle, onoff: i32) {
    type FnTy = extern "C" fn(*mut BinkHandle, i32);
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkSetWillLoop") } {
        f(bink, onoff);
        return;
    }
    if let Some(b) = unsafe { bink.as_mut() } {
        b.will_loop = onoff;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkShouldSkip(bink: *mut BinkHandle) -> i32 {
    type FnTy = extern "C" fn(*mut BinkHandle) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkShouldSkip") } {
        return f(bink);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkStartAsyncThread(thread_num: i32, param: *const c_void) -> i32 {
    type FnTy = extern "C" fn(i32, *const c_void) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkStartAsyncThread") } {
        return f(thread_num, param);
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkWait(bink: *mut BinkHandle) -> i32 {
    type FnTy = extern "C" fn(*mut BinkHandle) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkWait") } {
        return f(bink);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn BinkWaitStopAsyncThreadsMulti(threads: *const u32, count: i32) -> i32 {
    type FnTy = extern "C" fn(*const u32, i32) -> i32;
    if let Some(f) = unsafe { proc_or_none::<FnTy>(c"BinkWaitStopAsyncThreadsMulti") } {
        return f(threads, count);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_lifecycle_works_without_bink2w64() {
        let h = BinkOpenWithOptions(c"G:\\movies\\intro.bk2".as_ptr(), std::ptr::null(), 0);
        assert!(!h.is_null());
        BinkPause(h, 1);
        assert_eq!(unsafe { (*h).paused }, 1);
        BinkSetWillLoop(h, 1);
        assert_eq!(unsafe { (*h).will_loop }, 1);
        BinkClose(h);
    }
}
