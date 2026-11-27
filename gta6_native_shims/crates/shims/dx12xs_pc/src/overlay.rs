//! Translucent Win32 Layered Overlay HUD (`WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE`)
//! for `LUCIAS PROJECT`.
//!
//! Renders telemetry via a 32-bit premultiplied BGRA DIB + `UpdateLayeredWindow`, decoupled from
//! game root-signature / render-target state (< 0.1 ms per HUD refresh at ~10 Hz, toggle `F10`/`Insert`).

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use shim_common::telemetry::{self, HARDWARE_BANNER, PROJECT_NAME, TelemetrySnapshot};

pub const HUD_WIDTH: i32 = 480;
pub const HUD_HEIGHT: i32 = 286;

const WS_POPUP: u32 = 0x8000_0000;
const WS_EX_TOPMOST: u32 = 0x0000_0008;
const WS_EX_TRANSPARENT: u32 = 0x0000_0020;
const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
const WS_EX_LAYERED: u32 = 0x0008_0000;
const WS_EX_NOACTIVATE: u32 = 0x0800_0000;
const SW_HIDE: i32 = 0;
const SW_SHOWNOACTIVATE: i32 = 4;
const ULW_ALPHA: u32 = 2;
const AC_SRC_OVER: u8 = 0;
const AC_SRC_ALPHA: u8 = 1;
const TRANSPARENT_BK: i32 = 1;
const ANTIALIASED_QUALITY: u32 = 4;
const FW_BOLD: i32 = 700;
const FW_MEDIUM: i32 = 500;
const DIB_RGB_COLORS: u32 = 0;
const BI_RGB: u32 = 0;
const PM_REMOVE: u32 = 0x0001;
const VK_F10: i32 = 0x79;
const VK_INSERT: i32 = 0x2D;
const HWND_TOPMOST: isize = -1;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_SHOWWINDOW: u32 = 0x0040;
const DT_LEFT: u32 = 0x0000;
const DT_SINGLELINE: u32 = 0x0020;
const DT_END_ELLIPSIS: u32 = 0x8000;

/// Sentinel RGB cleared before GDI draws text; converted to translucent glass alpha afterwards.
const BG_SENTINEL_RGB: u32 = 0x0010_141E;
const GLASS_PREMUL_BGRA: u32 = 0xD2_0D_10_18;
const HEADER_PREMUL_BGRA: u32 = 0xEB_14_1C_2B;
const ACCENT_CYAN_BGRA: u32 = 0xFF_00_D4_FF;
const ACCENT_RED_BGRA: u32 = 0xFF_FF_33_55;
const BORDER_BGRA: u32 = 0xFF_28_38_50;

#[repr(C)]
#[derive(Default)]
struct Point {
    x: i32,
    y: i32,
}

#[repr(C)]
#[derive(Default)]
struct Size {
    cx: i32,
    cy: i32,
}

#[repr(C)]
#[derive(Default)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct BlendFunction {
    blend_op: u8,
    blend_flags: u8,
    source_constant_alpha: u8,
    alpha_format: u8,
}

#[repr(C)]
struct BitmapInfoHeader {
    bi_size: u32,
    bi_width: i32,
    bi_height: i32,
    bi_planes: u16,
    bi_bit_count: u16,
    bi_compression: u32,
    bi_size_image: u32,
    bi_x_pels_per_meter: i32,
    bi_y_pels_per_meter: i32,
    bi_clr_used: u32,
    bi_clr_important: u32,
}

#[repr(C)]
struct BitmapInfo {
    bmi_header: BitmapInfoHeader,
    bmi_colors: [u32; 1],
}

#[repr(C)]
struct WndClassExW {
    cb_size: u32,
    style: u32,
    lpfn_wnd_proc: Option<unsafe extern "system" fn(isize, u32, usize, isize) -> isize>,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: isize,
    h_icon: isize,
    h_cursor: isize,
    hbr_background: isize,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
    h_icon_sm: isize,
}

#[repr(C)]
#[derive(Default)]
struct Msg {
    hwnd: isize,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt: Point,
}

#[link(name = "user32")]
unsafe extern "system" {
    fn RegisterClassExW(lpwcx: *const WndClassExW) -> u16;
    fn CreateWindowExW(
        dw_ex_style: u32,
        lp_class_name: *const u16,
        lp_window_name: *const u16,
        dw_style: u32,
        x: i32,
        y: i32,
        n_width: i32,
        n_height: i32,
        h_wnd_parent: isize,
        h_menu: isize,
        h_instance: isize,
        lp_param: *const c_void,
    ) -> isize;
    fn DestroyWindow(hwnd: isize) -> i32;
    fn DefWindowProcW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> isize;
    fn PeekMessageW(lp_msg: *mut Msg, hwnd: isize, min: u32, max: u32, remove: u32) -> i32;
    fn TranslateMessage(lp_msg: *const Msg) -> i32;
    fn DispatchMessageW(lp_msg: *const Msg) -> isize;
    fn ShowWindow(hwnd: isize, n_cmd_show: i32) -> i32;
    fn IsWindow(hwnd: isize) -> i32;
    fn GetWindowRect(hwnd: isize, lp_rect: *mut Rect) -> i32;
    fn SetWindowPos(
        hwnd: isize,
        hwnd_insert_after: isize,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        u_flags: u32,
    ) -> i32;
    fn GetDC(hwnd: isize) -> isize;
    fn ReleaseDC(hwnd: isize, hdc: isize) -> i32;
    fn PostMessageW(hwnd: isize, msg: u32, w_param: usize, l_param: isize) -> i32;
    fn AdjustWindowRectEx(lp_rect: *mut Rect, dw_style: u32, b_menu: i32, dw_ex_style: u32) -> i32;
    fn GetSystemMetrics(n_index: i32) -> i32;
    fn UpdateLayeredWindow(
        hwnd: isize,
        hdc_dst: isize,
        ppt_dst: *const Point,
        psize: *const Size,
        hdc_src: isize,
        ppt_src: *const Point,
        cr_key: u32,
        pblend: *const BlendFunction,
        dw_flags: u32,
    ) -> i32;
    fn DrawTextW(
        hdc: isize,
        lpch_text: *const u16,
        cch_text: i32,
        lprc: *mut Rect,
        format: u32,
    ) -> i32;
    fn GetAsyncKeyState(v_key: i32) -> i16;
}

#[link(name = "gdi32")]
unsafe extern "system" {
    fn CreateCompatibleDC(hdc: isize) -> isize;
    fn DeleteDC(hdc: isize) -> i32;
    fn CreateDIBSection(
        hdc: isize,
        pbmi: *const BitmapInfo,
        usage: u32,
        ppv_bits: *mut *mut c_void,
        h_section: isize,
        offset: u32,
    ) -> isize;
    fn SelectObject(hdc: isize, h: isize) -> isize;
    fn DeleteObject(ho: isize) -> i32;
    fn CreateFontW(
        c_height: i32,
        c_width: i32,
        c_escapement: i32,
        c_orientation: i32,
        c_weight: i32,
        b_italic: u32,
        b_underline: u32,
        b_strike_out: u32,
        i_char_set: u32,
        i_out_precision: u32,
        i_clip_precision: u32,
        i_quality: u32,
        i_pitch_and_family: u32,
        psz_face_name: *const u16,
    ) -> isize;
    fn SetBkMode(hdc: isize, mode: i32) -> i32;
    fn SetTextColor(hdc: isize, color: u32) -> u32;
}

static HUD_STOP: AtomicBool = AtomicBool::new(false);
static HUD_THREAD_STARTED: AtomicBool = AtomicBool::new(false);
static HUD_THREAD_HANDLE: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> =
    std::sync::Mutex::new(None);
static HUD_HWND: AtomicU64 = AtomicU64::new(0);
static LAST_RENDER_QPC: AtomicU64 = AtomicU64::new(0);
static F10_DOWN: AtomicBool = AtomicBool::new(false);
static INS_DOWN: AtomicBool = AtomicBool::new(false);

fn utf16_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn hud_wnd_proc(
    hwnd: isize,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

pub struct HudSurface {
    mem_dc: isize,
    bmp: isize,
    old_bmp: isize,
    bits: *mut u32,
    font_title: isize,
    font_body: isize,
}

impl HudSurface {
    pub fn new() -> Option<Self> {
        unsafe {
            let screen_dc = GetDC(0);
            let mem_dc = CreateCompatibleDC(screen_dc);
            ReleaseDC(0, screen_dc);
            if mem_dc == 0 {
                return None;
            }
            let bmi = BitmapInfo {
                bmi_header: BitmapInfoHeader {
                    bi_size: size_of::<BitmapInfoHeader>() as u32,
                    bi_width: HUD_WIDTH,
                    bi_height: -HUD_HEIGHT, // top-down DIB
                    bi_planes: 1,
                    bi_bit_count: 32,
                    bi_compression: BI_RGB,
                    bi_size_image: 0,
                    bi_x_pels_per_meter: 0,
                    bi_y_pels_per_meter: 0,
                    bi_clr_used: 0,
                    bi_clr_important: 0,
                },
                bmi_colors: [0],
            };
            let mut bits: *mut c_void = std::ptr::null_mut();
            let bmp = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, &mut bits, 0, 0);
            if bmp == 0 || bits.is_null() {
                DeleteDC(mem_dc);
                return None;
            }
            let old_bmp = SelectObject(mem_dc, bmp);
            SetBkMode(mem_dc, TRANSPARENT_BK);
            let face = utf16_null("Consolas");
            let font_title = CreateFontW(
                16,
                0,
                0,
                0,
                FW_BOLD,
                0,
                0,
                0,
                1,
                0,
                0,
                ANTIALIASED_QUALITY,
                0,
                face.as_ptr(),
            );
            let font_body = CreateFontW(
                13,
                0,
                0,
                0,
                FW_MEDIUM,
                0,
                0,
                0,
                1,
                0,
                0,
                ANTIALIASED_QUALITY,
                0,
                face.as_ptr(),
            );
            Some(Self {
                mem_dc,
                bmp,
                old_bmp,
                bits: bits.cast::<u32>(),
                font_title,
                font_body,
            })
        }
    }

    pub fn render(&mut self, snap: &TelemetrySnapshot) -> &[u32] {
        let len = (HUD_WIDTH * HUD_HEIGHT) as usize;
        let pixels = unsafe { std::slice::from_raw_parts_mut(self.bits, len) };
        // Fill sentinel RGB so post-GDI pass detects text glyphs precisely.
        pixels.fill(BG_SENTINEL_RGB);

        let draw_line = |y: i32, x: i32, color_bgr: u32, font: isize, text: &str| unsafe {
            let old_f = SelectObject(self.mem_dc, font);
            SetTextColor(self.mem_dc, color_bgr);
            let wide: Vec<u16> = text.encode_utf16().collect();
            let mut rc = Rect {
                left: x,
                top: y,
                right: HUD_WIDTH - 12,
                bottom: y + 20,
            };
            DrawTextW(
                self.mem_dc,
                wide.as_ptr(),
                wide.len() as i32,
                &mut rc,
                DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            SelectObject(self.mem_dc, old_f);
        };

        // COLORREF is 0x00BBGGRR
        let title_col = if snap.shader_errors > 0 { 0x0055_44FF } else { 0x00FF_D400 };
        draw_line(10, 14, title_col, self.font_title, PROJECT_NAME);
        draw_line(12, 178, 0x00CC_B8A0, self.font_body, HARDWARE_BANNER);

        let fps = f64::from(snap.fps_x100) / 100.0;
        let frame_ms = f64::from(snap.frame_time_us) / 1000.0;
        let cpu_ms = f64::from(snap.cpu_time_us) / 1000.0;
        let gpu_ms = f64::from(snap.gpu_time_us) / 1000.0;
        draw_line(
            40,
            14,
            0x00E8_F8FF,
            self.font_body,
            &format!(
                "FPS: {fps:>5.1} | Frame: {frame_ms:>5.2}ms | CPU: {cpu_ms:>5.2}ms | GPU: {gpu_ms:>5.2}ms"
            ),
        );

        let vram_col = if snap.vram_used_mib >= snap.vram_budget_mib {
            0x0044_55FF
        } else {
            0x00A8_FFB0
        };
        let (rw, rh) = telemetry::configured_resolution();
        draw_line(
            62,
            14,
            vram_col,
            self.font_body,
            &format!(
                "VRAM: {:>4}/{:>4} MiB | RAM: {:>5}/{:>5} MiB | {rw}x{rh}",
                snap.vram_used_mib,
                snap.vram_budget_mib,
                snap.ram_commit_mib,
                snap.ram_budget_mib
            ),
        );

        let sh_col = if snap.shader_errors > 0 {
            0x0055_66FF
        } else {
            0x00F0_E6D2
        };
        draw_line(
            84,
            14,
            sh_col,
            self.font_body,
            &format!(
                "Shaders DXPK Hit/Miss: {}/{} | Compiled: {} | Err: {}",
                snap.dxpk_hits, snap.dxpk_misses, snap.shaders_compiled, snap.shader_errors
            ),
        );

        let err_detail = if snap.shader_errors > 0 {
            format!(
                "Last Shader Err: {:#018x} ({})",
                snap.last_failed_shader_hash,
                if snap.last_failed_stage.is_empty() {
                    "PSO"
                } else {
                    snap.last_failed_stage.as_str()
                }
            )
        } else {
            "Last Shader Err: none".to_string()
        };
        draw_line(
            106,
            14,
            if snap.shader_errors > 0 { 0x0066_77FF } else { 0x0088_99AA },
            self.font_body,
            &err_detail,
        );

        draw_line(
            134,
            14,
            0x00FF_D400,
            self.font_body,
            "Warnings / Events [F10 or Insert to toggle]:",
        );

        let visible_warns: Vec<&String> = snap.warnings.iter().rev().take(6).collect();
        if visible_warns.is_empty() {
            draw_line(156, 18, 0x0078_8899, self.font_body, "(no warnings recorded)");
        } else {
            for (idx, w) in visible_warns.iter().enumerate() {
                let y = 156 + (idx as i32) * 20;
                draw_line(y, 18, 0x0066_D0FF, self.font_body, w);
            }
        }

        // Convert GDI RGB pixels into premultiplied BGRA alpha glass card + crisp accent bar.
        let w = HUD_WIDTH as usize;
        let h = HUD_HEIGHT as usize;
        let bg_r = ((BG_SENTINEL_RGB >> 16) & 0xFF) as i32;
        let bg_g = ((BG_SENTINEL_RGB >> 8) & 0xFF) as i32;
        let bg_b = (BG_SENTINEL_RGB & 0xFF) as i32;
        let accent = if snap.shader_errors > 0 {
            ACCENT_RED_BGRA
        } else {
            ACCENT_CYAN_BGRA
        };

        for y in 0..h {
            let row = y * w;
            for x in 0..w {
                let p = &mut pixels[row + x];
                if x < 2 || y < 2 || x + 2 >= w || y + 2 >= h {
                    *p = if y < 34 { accent } else { BORDER_BGRA };
                    continue;
                }
                if y == 34 || y == 128 {
                    *p = if y == 34 { accent } else { BORDER_BGRA };
                    continue;
                }
                let rgb = *p & 0x00FF_FFFF;
                if rgb == BG_SENTINEL_RGB {
                    *p = if y < 34 { HEADER_PREMUL_BGRA } else { GLASS_PREMUL_BGRA };
                } else {
                    let r = ((rgb >> 16) & 0xFF) as i32;
                    let g = ((rgb >> 8) & 0xFF) as i32;
                    let b = (rgb & 0xFF) as i32;
                    let dr = (r - bg_r).abs();
                    let dg = (g - bg_g).abs();
                    let db = (b - bg_b).abs();
                    let lum_delta = dr.max(dg).max(db);
                    let a = (190 + (lum_delta * 65 / 255)).clamp(190, 255) as u32;
                    *p = (a << 24) | ((r as u32 * a / 255) << 16) | ((g as u32 * a / 255) << 8) | (b as u32 * a / 255);
                }
            }
        }
        pixels
    }
}

impl Drop for HudSurface {
    fn drop(&mut self) {
        unsafe {
            if self.font_title != 0 {
                DeleteObject(self.font_title);
            }
            if self.font_body != 0 {
                DeleteObject(self.font_body);
            }
            if self.mem_dc != 0 {
                if self.old_bmp != 0 {
                    SelectObject(self.mem_dc, self.old_bmp);
                }
                DeleteDC(self.mem_dc);
            }
            if self.bmp != 0 {
                DeleteObject(self.bmp);
            }
        }
    }
}

fn create_layered_hud_window() -> isize {
    unsafe {
        let class_name = utf16_null("LuciasProjectOverlayHudClass");
        let wnd_name = utf16_null("LUCIAS PROJECT Telemetry HUD");
        let wc = WndClassExW {
            cb_size: size_of::<WndClassExW>() as u32,
            style: 0,
            lpfn_wnd_proc: Some(hud_wnd_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: 0,
            h_icon: 0,
            h_cursor: 0,
            hbr_background: 0,
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: class_name.as_ptr(),
            h_icon_sm: 0,
        };
        RegisterClassExW(&wc);
        let ex_style = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW;
        CreateWindowExW(
            ex_style,
            class_name.as_ptr(),
            wnd_name.as_ptr(),
            WS_POPUP,
            24,
            24,
            HUD_WIDTH,
            HUD_HEIGHT,
            0,
            0,
            0,
            std::ptr::null(),
        )
    }
}

fn poll_hotkey_toggle() {
    unsafe {
        let f10_now = (GetAsyncKeyState(VK_F10) as u16 & 0x8000) != 0;
        let f10_prev = F10_DOWN.swap(f10_now, Ordering::Relaxed);
        let ins_now = (GetAsyncKeyState(VK_INSERT) as u16 & 0x8000) != 0;
        let ins_prev = INS_DOWN.swap(ins_now, Ordering::Relaxed);
        if (f10_now && !f10_prev) || (ins_now && !ins_prev) {
            telemetry::toggle_overlay_visible();
        }
    }
}

fn push_hud_to_window(hwnd: isize, surface: &mut HudSurface) {
    if hwnd == 0 || unsafe { IsWindow(hwnd) } == 0 {
        return;
    }
    let visible = telemetry::is_overlay_visible();
    if !visible {
        unsafe {
            ShowWindow(hwnd, SW_HIDE);
        }
        return;
    }

    let snap = telemetry::snapshot();
    surface.render(&snap);

    let mut dst_pt = Point { x: 24, y: 24 };
    let target = telemetry::target_hwnd() as isize;
    if target != 0 && unsafe { IsWindow(target) } != 0 {
        let mut rc = Rect::default();
        if unsafe { GetWindowRect(target, &mut rc) } != 0 && rc.right > rc.left + 64 {
            dst_pt.x = rc.left + 16;
            dst_pt.y = rc.top + 16;
        }
    }
    let sz = Size {
        cx: HUD_WIDTH,
        cy: HUD_HEIGHT,
    };
    let src_pt = Point { x: 0, y: 0 };
    let blend = BlendFunction {
        blend_op: AC_SRC_OVER,
        blend_flags: 0,
        source_constant_alpha: 255,
        alpha_format: AC_SRC_ALPHA,
    };
    unsafe {
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            dst_pt.x,
            dst_pt.y,
            0,
            0,
            SWP_NOACTIVATE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        UpdateLayeredWindow(
            hwnd,
            0,
            &dst_pt,
            &sz,
            surface.mem_dc,
            &src_pt,
            0,
            &blend,
            ULW_ALPHA,
        );
    }
}

pub(crate) fn drain_window_messages(hwnd: isize) -> bool {
    const WM_DESTROY: u32 = 0x0002;
    let mut msg = Msg::default();
    let mut destroyed = false;
    unsafe {
        while PeekMessageW(&mut msg, hwnd, 0, 0, PM_REMOVE) != 0 {
            if msg.message == WM_DESTROY {
                destroyed = true;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    destroyed
}

pub(crate) unsafe fn create_simple_window(
    class_name: *const u16,
    title: *const u16,
    wnd_proc: unsafe extern "system" fn(isize, u32, usize, isize) -> isize,
    client_w: i32,
    client_h: i32,
) -> isize {
    const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
    const WS_VISIBLE: u32 = 0x1000_0000;
    const CW_USEDEFAULT: i32 = i32::MIN;
    const SM_CXSCREEN: i32 = 0;
    const SM_CYSCREEN: i32 = 1;
    unsafe {
        let h_inst = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null()) as isize;
        let sx = GetSystemMetrics(SM_CXSCREEN).max(800);
        let sy = GetSystemMetrics(SM_CYSCREEN).max(600);
        let fitted_w = client_w.min(sx.saturating_sub(48).max(640));
        let fitted_h = client_h.min(sy.saturating_sub(64).max(360));
        let wc = WndClassExW {
            cb_size: size_of::<WndClassExW>() as u32,
            style: 0,
            lpfn_wnd_proc: Some(wnd_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: h_inst,
            h_icon: 0,
            h_cursor: 0,
            hbr_background: 0,
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: class_name,
            h_icon_sm: 0,
        };
        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            let gle = windows_sys::Win32::Foundation::GetLastError();
            if gle != 1410 {
                shim_common::boot_trace(
                    "dx12xs_pc",
                    "PresentContext::RegisterClassExW",
                    &format!("failed gle={gle}"),
                );
            }
        }
        let mut rc = Rect {
            left: 0,
            top: 0,
            right: fitted_w,
            bottom: fitted_h,
        };
        AdjustWindowRectEx(&mut rc, WS_OVERLAPPEDWINDOW, 0, 0);
        let h = CreateWindowExW(
            0,
            class_name,
            title,
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rc.right - rc.left,
            rc.bottom - rc.top,
            0,
            0,
            h_inst,
            std::ptr::null(),
        );
        if h != 0 {
            ShowWindow(h, SW_SHOWNOACTIVATE);
        }
        h
    }
}

pub(crate) unsafe fn destroy_simple_window(hwnd: isize) {
    if hwnd != 0 {
        unsafe { DestroyWindow(hwnd) };
    }
}

pub(crate) unsafe fn post_null_message(hwnd: isize) {
    if hwnd != 0 {
        unsafe { PostMessageW(hwnd, 0, 0, 0) };
    }
}

pub(crate) unsafe fn default_wnd_proc(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> isize {
    if msg == 0x0010 {
        unsafe { ShowWindow(hwnd, SW_HIDE) };
        return 0;
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn hud_thread_main() {
    let hwnd = create_layered_hud_window();
    HUD_HWND.store(hwnd as u64, Ordering::Release);
    let Some(mut surface) = HudSurface::new() else {
        if hwnd != 0 {
            unsafe { DestroyWindow(hwnd) };
        }
        HUD_HWND.store(0, Ordering::Release);
        return;
    };

    let mut msg = Msg::default();
    while !HUD_STOP.load(Ordering::Acquire) {
        unsafe {
            while PeekMessageW(&mut msg, hwnd, 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        poll_hotkey_toggle();
        push_hud_to_window(hwnd, &mut surface);
        telemetry::flush_telemetry_json_if_due(false);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if hwnd != 0 {
        unsafe { DestroyWindow(hwnd) };
    }
    HUD_HWND.store(0, Ordering::Release);
}

/// Ensures the background `LUCIAS PROJECT` Win32 layered overlay HUD thread is running.
pub fn ensure_started() {
    if std::env::var("LUCIAS_DISABLE_OVERLAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return;
    }
    if HUD_THREAD_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        HUD_STOP.store(false, Ordering::Release);
        if let Ok(handle) = std::thread::Builder::new()
            .name("lucias-hud".into())
            .spawn(hud_thread_main)
        {
            *HUD_THREAD_HANDLE.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        }
    }
}

/// Triggers an immediate non-blocking rate-limited HUD + JSON telemetry refresh (< 10 Hz).
pub fn notify_present_tick() {
    ensure_started();
    let now = telemetry::qpc_now();
    let freq = telemetry::qpc_freq();
    let last = LAST_RENDER_QPC.load(Ordering::Relaxed);
    if (now.saturating_sub(last)) * 10 >= freq {
        LAST_RENDER_QPC.store(now, Ordering::Relaxed);
        telemetry::flush_telemetry_json_if_due(false);
    }
}

/// Performs a single synchronous layered window create + render + destroy smoke verification (for tests).
pub fn smoke_layered_hud_once() -> Result<usize, String> {
    let hwnd = create_layered_hud_window();
    if hwnd == 0 {
        return Err("CreateWindowExW failed for LuciasProjectOverlayHudClass".into());
    }
    let Some(mut surface) = HudSurface::new() else {
        unsafe { DestroyWindow(hwnd) };
        return Err("HudSurface::new failed".into());
    };
    let snap = telemetry::snapshot();
    let pixels = surface.render(&snap);
    let non_zero_alpha = pixels.iter().filter(|&&p| (p >> 24) > 0).count();
    push_hud_to_window(hwnd, &mut surface);
    unsafe { DestroyWindow(hwnd) };
    Ok(non_zero_alpha)
}

pub fn shutdown() {
    HUD_STOP.store(true, Ordering::Release);
    if let Some(handle) = HUD_THREAD_HANDLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        let _ = handle.join();
    }
    HUD_THREAD_STARTED.store(false, Ordering::Release);
}

pub fn current_hud_hwnd() -> isize {
    HUD_HWND.load(Ordering::Relaxed) as isize
}
