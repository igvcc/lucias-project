#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use shim_common::{E_NOINTERFACE, E_NOTIMPL, E_POINTER, Guid, HRESULT, S_OK, VtableHeader};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
use windows_sys::Win32::UI::Input::XboxController::{XINPUT_STATE, XInputGetState};

const READING_NOT_FOUND: HRESULT = 0x838A_0003_u32 as i32;
const DEVICE_NOT_FOUND: HRESULT = 0x838A_0002_u32 as i32;
const IID_IUNKNOWN: Guid = Guid::new(0x0000_0000, 0x0000, 0x0000, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
const IID_IGAMEINPUT: Guid = Guid::new(
    0x11BE_2A7E,
    0x4254,
    0x445A,
    [0x9C, 0x09, 0xFF, 0xC4, 0x0F, 0x00, 0x69, 0x18],
);

static START_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GamepadState {
    pub buttons: u32,
    pub left_trigger: f32,
    pub right_trigger: f32,
    pub left_x: f32,
    pub left_y: f32,
    pub right_x: f32,
    pub right_y: f32,
}

#[repr(C)]
pub struct GameInputObj {
    vtable: *const *const c_void,
    refs: AtomicU32,
}

#[repr(C)]
pub struct ReadingObj {
    vtable: *const *const c_void,
    refs: AtomicU32,
    seq: u64,
    timestamp: u64,
    pad: GamepadState,
}

static GAMEINPUT_VTABLE: VtableHeader<22> = VtableHeader([
    gi_qi as *const c_void,                  // 0x00 QueryInterface
    gi_add_ref as *const c_void,             // 0x08 AddRef
    gi_release as *const c_void,             // 0x10 Release
    gi_get_timestamp as *const c_void,       // 0x18 GetCurrentTimestamp
    gi_get_current_reading as *const c_void, // 0x20 GetCurrentReading
    gi_get_next_reading as *const c_void,    // 0x28 GetNextReading
    gi_get_prev_reading as *const c_void,    // 0x30 GetPreviousReading
    gi_stub_notimpl as *const c_void,        // 0x38 GetTemporalReading
    gi_stub_zero as *const c_void,           // 0x40 RegisterReadingCallback
    gi_register_cb as *const c_void,         // 0x48 RegisterDeviceCallback
    gi_stub_notimpl as *const c_void,        // 0x50 RegisterSystemButtonCallback
    gi_stub_notimpl as *const c_void,        // 0x58 RegisterKeyboardLayoutCallback
    gi_stub_zero as *const c_void,           // 0x60 StopCallback
    gi_unregister_cb as *const c_void,       // 0x68 UnregisterCallback
    gi_stub_zero as *const c_void,           // 0x70 CreateAggregateDevice
    gi_stub_zero as *const c_void,           // 0x78
    gi_find_device as *const c_void,         // 0x80 FindDeviceFromId
    gi_stub_notimpl as *const c_void,        // 0x88 FindDeviceFromObject
    gi_stub_zero as *const c_void,           // 0x90 FindDeviceFromPlatformHandle
    gi_stub_zero as *const c_void,           // 0x98 FindDeviceFromPlatformString
    gi_stub_zero as *const c_void,           // 0xa0 EnableOemDeviceSupport
    gi_stub_zero as *const c_void,           // 0xa8 SetFocusPolicy
]);

static READING_VTABLE: VtableHeader<25> = VtableHeader([
    gi_qi as *const c_void,           // 0x00
    reading_add_ref as *const c_void, // 0x08
    reading_release as *const c_void, // 0x10
    reading_kind as *const c_void,    // 0x18
    reading_seq as *const c_void,     // 0x20
    reading_ts as *const c_void,      // 0x28
    gi_stub_zero as *const c_void,    // 0x30
    gi_stub_zero as *const c_void,    // 0x38
    gi_stub_zero as *const c_void,    // 0x40
    gi_stub_zero as *const c_void,    // 0x48
    gi_stub_zero as *const c_void,    // 0x50
    gi_stub_zero as *const c_void,    // 0x58
    gi_stub_zero as *const c_void,    // 0x60
    gi_stub_zero as *const c_void,    // 0x68
    gi_stub_zero as *const c_void,    // 0x70
    gi_stub_zero as *const c_void,    // 0x78
    gi_stub_zero as *const c_void,    // 0x80
    gi_stub_zero as *const c_void,    // 0x88
    gi_stub_zero as *const c_void,    // 0x90
    gi_stub_zero as *const c_void,    // 0x98
    gi_stub_zero as *const c_void,    // 0xa0
    gi_stub_zero as *const c_void,    // 0xa8
    reading_gamepad as *const c_void, // 0xb0 GetGamepadState
    gi_stub_zero as *const c_void,    // 0xb8
    gi_stub_zero as *const c_void,    // 0xc0
]);

extern "system" fn gi_qi(this: *mut c_void, iid: *const Guid, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let id = unsafe { iid.as_ref() };
    if id == Some(&IID_IUNKNOWN) || id == Some(&IID_IGAMEINPUT) {
        unsafe { *out = this };
        gi_add_ref(this.cast());
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}

extern "system" fn gi_add_ref(this: *mut GameInputObj) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn gi_release(this: *mut GameInputObj) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

extern "system" fn gi_get_timestamp(_: *mut GameInputObj) -> u64 {
    START_TIME.elapsed().as_micros() as u64
}

fn map_xinput_buttons(w: u16) -> u32 {
    const MAP: [(u16, u32); 14] = [
        (0x0010, 0x0001), // START -> Menu
        (0x0020, 0x0002), // BACK -> View
        (0x1000, 0x0004), // A
        (0x2000, 0x0008), // B
        (0x4000, 0x0010), // X
        (0x8000, 0x0020), // Y
        (0x0001, 0x0040), // DPadUp
        (0x0002, 0x0080), // DPadDown
        (0x0004, 0x0100), // DPadLeft
        (0x0008, 0x0200), // DPadRight
        (0x0100, 0x0400), // LeftShoulder
        (0x0200, 0x0800), // RightShoulder
        (0x0040, 0x1000), // LeftThumbstick
        (0x0080, 0x2000), // RightThumbstick
    ];
    let mut out = 0u32;
    for (xi_bit, gi_bit) in MAP {
        if (w & xi_bit) != 0 {
            out |= gi_bit;
        }
    }
    out
}

fn key_down(vk: i32) -> bool {
    (unsafe { GetAsyncKeyState(vk) } as u16 & 0x8000) != 0
}

fn sample_gamepad() -> GamepadState {
    let mut xi = XINPUT_STATE::default();
    let mut pad = GamepadState::default();
    if unsafe { XInputGetState(0, &mut xi) } == 0 {
        pad.buttons = map_xinput_buttons(xi.Gamepad.wButtons);
        pad.left_trigger = xi.Gamepad.bLeftTrigger as f32 / 255.0;
        pad.right_trigger = xi.Gamepad.bRightTrigger as f32 / 255.0;
        pad.left_x = (xi.Gamepad.sThumbLX as f32 / 32767.0).max(-1.0);
        pad.left_y = (xi.Gamepad.sThumbLY as f32 / 32767.0).max(-1.0);
        pad.right_x = (xi.Gamepad.sThumbRX as f32 / 32767.0).max(-1.0);
        pad.right_y = (xi.Gamepad.sThumbRY as f32 / 32767.0).max(-1.0);
        return pad;
    }

    // Keyboard fallback when no XInput controller is attached.
    if key_down(0x1B) {
        pad.buttons |= 0x0001; // Esc -> Menu
    }
    if key_down(0x0D) {
        pad.buttons |= 0x0004; // Enter -> A
    }
    if key_down(0x08) {
        pad.buttons |= 0x0008; // Backspace -> B
    }
    if key_down(b'D' as i32) {
        pad.left_x += 1.0;
    }
    if key_down(b'A' as i32) {
        pad.left_x -= 1.0;
    }
    if key_down(b'W' as i32) {
        pad.left_y += 1.0;
    }
    if key_down(b'S' as i32) {
        pad.left_y -= 1.0;
    }
    pad
}

extern "system" fn gi_get_current_reading(
    _: *mut GameInputObj,
    _input_kind: u32,
    _device: *mut c_void,
    out: *mut *mut ReadingObj,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let r = Box::new(ReadingObj {
        vtable: READING_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
        seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
        timestamp: START_TIME.elapsed().as_micros() as u64,
        pad: sample_gamepad(),
    });
    unsafe { *out = Box::into_raw(r) };
    S_OK
}

extern "system" fn gi_get_next_reading(
    _: *mut GameInputObj,
    _: *mut ReadingObj,
    _: u32,
    _: *mut c_void,
    out: *mut *mut ReadingObj,
) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    READING_NOT_FOUND
}

extern "system" fn gi_get_prev_reading(
    _: *mut GameInputObj,
    _: *mut ReadingObj,
    _: u32,
    _: *mut c_void,
    out: *mut *mut ReadingObj,
) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    READING_NOT_FOUND
}

extern "system" fn gi_register_cb(
    _: *mut GameInputObj,
    _: *mut c_void,
    _: u32,
    _: u32,
    _: u32,
    _: *mut c_void,
    _: *mut c_void,
    token_out: *mut u64,
) -> HRESULT {
    if !token_out.is_null() {
        unsafe { *token_out = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed) };
    }
    S_OK
}

extern "system" fn gi_unregister_cb(_: *mut GameInputObj, _token: u64, _timeout: u64) -> bool {
    true
}

extern "system" fn gi_find_device(
    _: *mut GameInputObj,
    _: *const c_void,
    out: *mut *mut c_void,
) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    DEVICE_NOT_FOUND
}

extern "system" fn gi_stub_notimpl() -> HRESULT {
    E_NOTIMPL
}

extern "system" fn gi_stub_zero() -> usize {
    0
}

extern "system" fn reading_add_ref(this: *mut ReadingObj) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn reading_release(this: *mut ReadingObj) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

extern "system" fn reading_kind(_: *mut ReadingObj) -> u32 {
    0x4_0000 // Gamepad
}

extern "system" fn reading_seq(this: *mut ReadingObj) -> u64 {
    unsafe { &*this }.seq
}

extern "system" fn reading_ts(this: *mut ReadingObj) -> u64 {
    unsafe { &*this }.timestamp
}

extern "system" fn reading_gamepad(this: *mut ReadingObj, out: *mut GamepadState) -> bool {
    if this.is_null() || out.is_null() {
        return false;
    }
    unsafe { *out = (*this).pad };
    true
}

#[unsafe(no_mangle)]
pub extern "system" fn GameInputCreate(out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        shim_common::boot_trace_hr("gi_pc", "GameInputCreate", E_POINTER, "null out");
        return E_POINTER;
    }
    let obj = Box::new(GameInputObj {
        vtable: GAMEINPUT_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
    });
    unsafe { *out = Box::into_raw(obj).cast() };
    shim_common::boot_trace_hr("gi_pc", "GameInputCreate", S_OK, "IGameInput created");
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn com_vtable_qi_and_reading_work() {
        let mut gi: *mut c_void = std::ptr::null_mut();
        assert_eq!(GameInputCreate(&mut gi), S_OK);
        assert!(!gi.is_null());

        let vtbl = unsafe { *gi.cast::<*const *const c_void>() };
        type QiFn = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> HRESULT;
        type GetReadingFn = unsafe extern "system" fn(
            *mut c_void,
            u32,
            *mut c_void,
            *mut *mut c_void,
        ) -> HRESULT;
        type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;

        let qi: QiFn = unsafe { std::mem::transmute(*vtbl) };
        let get_reading: GetReadingFn = unsafe { std::mem::transmute(*vtbl.add(4)) };
        let release: RelFn = unsafe { std::mem::transmute(*vtbl.add(2)) };

        let mut gi2 = std::ptr::null_mut();
        assert_eq!(unsafe { qi(gi, &IID_IGAMEINPUT, &mut gi2) }, S_OK);
        assert_eq!(gi2, gi);
        assert_eq!(unsafe { release(gi2) }, 1);

        let mut reading = std::ptr::null_mut();
        assert_eq!(
            unsafe { get_reading(gi, 0x4_0000, std::ptr::null_mut(), &mut reading) },
            S_OK
        );
        assert!(!reading.is_null());

        let r_vtbl = unsafe { *reading.cast::<*const *const c_void>() };
        let r_release: RelFn = unsafe { std::mem::transmute(*r_vtbl.add(2)) };
        assert_eq!(unsafe { r_release(reading) }, 0);
        assert_eq!(unsafe { release(gi) }, 0);
    }
}
