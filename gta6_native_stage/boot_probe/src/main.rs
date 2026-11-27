#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, GetLastError, HANDLE, MAX_PATH,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_ALL_AMD64, ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
    RIP_EVENT, ReadProcessMemory, UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEvent,
    CREATE_PROCESS_DEBUG_EVENT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DEBUG_ONLY_THIS_PROCESS,
    OpenThread, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, SuspendThread,
    THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, WaitForSingleObject,
};

#[link(name = "kernel32")]
extern "system" {
    fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> i32;
}

const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
const MS_VC_THREAD_NAME_EXCEPTION: u32 = 0x406D_1388;

struct Config {
    exe: PathBuf,
    cwd: PathBuf,
    cli_args: String,
    timeout_ms: u64,
    mem_limit_mb: u64,
    log_dir: PathBuf,
    shim_log: PathBuf,
    d3d12_debug: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exe: PathBuf::from(r"E:\LUCIAS_PROJECT\LuciasProject.exe"),
            cwd: PathBuf::from(r"E:\LUCIAS_PROJECT"),
            cli_args: String::new(),
            timeout_ms: 20_000,
            mem_limit_mb: 10_752, // 10.5 GiB
            log_dir: PathBuf::from(r"E:\LUCIAS_PROJECT\logs"),
            shim_log: PathBuf::from(r"E:\LUCIAS_PROJECT\logs\shim_trace.log"),
            d3d12_debug: false,
        }
    }
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        let k = args[i].as_str();
        let next = |idx: &mut usize| -> Result<String, String> {
            *idx += 1;
            args.get(*idx)
                .cloned()
                .ok_or_else(|| format!("missing value for {k}"))
        };
        match k {
            "--exe" => cfg.exe = PathBuf::from(next(&mut i)?),
            "--cwd" => cfg.cwd = PathBuf::from(next(&mut i)?),
            "--args" => cfg.cli_args = next(&mut i)?,
            "--timeout-ms" => {
                cfg.timeout_ms = next(&mut i)?
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --timeout-ms: {e}"))?;
            }
            "--mem-limit-mb" => {
                cfg.mem_limit_mb = next(&mut i)?
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --mem-limit-mb: {e}"))?;
            }
            "--log-dir" => cfg.log_dir = PathBuf::from(next(&mut i)?),
            "--shim-log" => cfg.shim_log = PathBuf::from(next(&mut i)?),
            "--d3d12-debug" => cfg.d3d12_debug = true,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(cfg)
}

fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn path_from_handle(h: HANDLE) -> String {
    if h.is_null() {
        return String::new();
    }
    let mut buf = vec![0u16; MAX_PATH as usize * 4];
    let n = unsafe {
        GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED)
    };
    if n == 0 || (n as usize) >= buf.len() {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

#[derive(Clone, Debug)]
struct LoadedMod {
    size: u64,
    path: String,
}

impl LoadedMod {
    fn short_name(&self) -> &str {
        Path::new(&self.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&self.path)
    }
}

fn read_pe_image_size(process: HANDLE, base: u64) -> u64 {
    let mut hdr = [0u8; 0x400];
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            base as *const c_void,
            hdr.as_mut_ptr().cast(),
            hdr.len(),
            &mut read,
        )
    };
    if ok == 0 || read < 0x100 {
        return 0;
    }
    if hdr[0..2] != *b"MZ" {
        return 0;
    }
    let lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
    if lfanew + 0x58 > read || hdr[lfanew..lfanew + 4] != *b"PE\0\0" {
        return 0;
    }
    u32::from_le_bytes(hdr[lfanew + 24 + 56..lfanew + 24 + 60].try_into().unwrap()) as u64
}

fn format_addr(mods: &BTreeMap<u64, LoadedMod>, addr: u64) -> String {
    if let Some((&base, m)) = mods.range(..=addr).next_back() {
        let delta = addr - base;
        if m.size == 0 || delta < m.size {
            return format!("{}+0x{:X} (0x{:016X})", m.short_name(), delta, addr);
        }
    }
    format!("0x{:016X}", addr)
}

fn read_bytes(process: HANDLE, addr: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as *const c_void,
            buf.as_mut_ptr().cast(),
            len,
            &mut read,
        )
    };
    if ok == 0 {
        return Vec::new();
    }
    buf.truncate(read);
    buf
}

fn read_debug_string(process: HANDLE, ptr: u64, len: u16, is_unicode: bool) -> String {
    if ptr == 0 || len == 0 {
        return String::new();
    }
    let byte_len = if is_unicode {
        (len as usize) * 2
    } else {
        len as usize
    }
    .min(2048);
    let raw = read_bytes(process, ptr, byte_len);
    if is_unicode {
        let u16s: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&u16s).trim().to_string()
    } else {
        let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..nul]).trim().to_string()
    }
}

fn build_env_block(shim_log: &Path, game_root: &Path, d3d12_debug: bool) -> Vec<u16> {
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in std::env::vars() {
        vars.insert(k, v);
    }
    vars.insert("LUCIAS_RES".to_string(), "1920x1080".to_string());
    vars.insert("LUCIAS_PROFILE".to_string(), "1080p".to_string());
    vars.insert("LUCIAS_CONSOLE_MODE".to_string(), "seriess".to_string());
    if d3d12_debug {
        vars.insert("LUCIAS_D3D12_DEBUG".to_string(), "1".to_string());
    }
    vars.insert(
        "GTA6_SHIM_LOG".to_string(),
        shim_log.to_string_lossy().into_owned(),
    );
    vars.insert(
        "LUCIAS_SHIM_LOG".to_string(),
        shim_log.to_string_lossy().into_owned(),
    );
    vars.insert(
        "LUCIAS_TELEMETRY_LOG".to_string(),
        game_root
            .join("logs")
            .join("telemetry_latest.json")
            .to_string_lossy()
            .into_owned(),
    );
    vars.insert(
        "GTA6_VFS_G".to_string(),
        game_root.to_string_lossy().into_owned(),
    );
    vars.insert(
        "GTA6_VFS_T".to_string(),
        game_root.join("pc_cache").to_string_lossy().into_owned(),
    );

    let mut block = Vec::new();
    for (k, v) in vars {
        let line = format!("{k}={v}");
        block.extend(line.encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

struct JobGuard {
    job: HANDLE,
    process: HANDLE,
    thread: HANDLE,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.job.is_null() {
                TerminateJobObject(self.job, 0xDEAD_0020);
                CloseHandle(self.job);
            }
            if !self.thread.is_null() {
                CloseHandle(self.thread);
            }
            if !self.process.is_null() {
                CloseHandle(self.process);
            }
        }
    }
}

fn exc_name(code: u32) -> &'static str {
    match code {
        0xC000_0005 => "EXCEPTION_ACCESS_VIOLATION",
        0xC000_001D => "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xC000_0094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xC000_00FD => "EXCEPTION_STACK_OVERFLOW",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0138 => "STATUS_ORDINAL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        0xE06D_7363 => "CPP_EH_EXCEPTION",
        0x8000_0003 => "EXCEPTION_BREAKPOINT",
        _ => "OTHER_EXCEPTION",
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn capture_thread_snapshot(pid: u32, process: HANDLE, mods: &BTreeMap<u64, LoadedMod>) -> Vec<String> {
    let mut lines = Vec::new();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap.is_null() || snap == -1isize as HANDLE {
        return lines;
    }
    let mut te: THREADENTRY32 = unsafe { zeroed() };
    te.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut ok = unsafe { Thread32First(snap, &mut te) };
    while ok != 0 {
        if te.th32OwnerProcessID == pid && lines.len() < 32 {
            let h_thr = unsafe {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    0,
                    te.th32ThreadID,
                )
            };
            if !h_thr.is_null() {
                unsafe { SuspendThread(h_thr) };
                #[repr(C, align(16))]
                struct AlignedContext(CONTEXT);
                let mut ctx: AlignedContext = unsafe { zeroed() };
                ctx.0.ContextFlags = CONTEXT_ALL_AMD64;
                if unsafe { GetThreadContext(h_thr, &mut ctx.0) } != 0 {
                    let mut entry = format!(
                        "tid={} RIP={} RSP=0x{:016X}",
                        te.th32ThreadID,
                        format_addr(mods, ctx.0.Rip),
                        ctx.0.Rsp
                    );
                    let stack = read_bytes(process, ctx.0.Rsp, 96);
                    let mut callers = Vec::new();
                    for chunk in stack.as_chunks::<8>().0 {
                        let val = u64::from_le_bytes(*chunk);
                        if let Some((&base, m)) = mods.range(..=val).next_back() {
                            let delta = val - base;
                            if m.size == 0 || delta < m.size {
                                callers.push(format!("{}+0x{:X}", m.short_name(), delta));
                                if callers.len() >= 6 {
                                    break;
                                }
                            }
                        }
                    }
                    if !callers.is_empty() {
                        entry.push_str(&format!(" | stack=[{}]", callers.join(", ")));
                    }
                    lines.push(entry);
                }
                unsafe { ResumeThread(h_thr) };
                unsafe { CloseHandle(h_thr) };
            }
        }
        ok = unsafe { Thread32Next(snap, &mut te) };
    }
    unsafe { CloseHandle(snap) };
    lines
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_args().map_err(|e| format!("arg error: {e}"))?;
    fs::create_dir_all(&cfg.log_dir)?;
    if let Some(parent) = cfg.shim_log.parent() {
        fs::create_dir_all(parent)?;
    }

    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(format!("CreateJobObjectW failed: err={}", unsafe { GetLastError() }).into());
    }
    let mut guard = JobGuard {
        job,
        process: std::ptr::null_mut(),
        thread: std::ptr::null_mut(),
    };

    let mem_bytes = cfg.mem_limit_mb * 1024 * 1024;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.ProcessMemoryLimit = mem_bytes as usize;
    limits.JobMemoryLimit = mem_bytes as usize;
    let set_ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set_ok == 0 {
        return Err(
            format!("SetInformationJobObject failed: err={}", unsafe { GetLastError() }).into(),
        );
    }

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    let exe_w = to_wide_nul(&cfg.exe.to_string_lossy());
    let mut cmd_w = if cfg.cli_args.trim().is_empty() {
        Vec::new()
    } else {
        to_wide_nul(&format!("\"{}\" {}", cfg.exe.display(), cfg.cli_args.trim()))
    };
    let cmd_ptr = if cmd_w.is_empty() {
        std::ptr::null_mut()
    } else {
        cmd_w.as_mut_ptr()
    };
    let cwd_w = to_wide_nul(&cfg.cwd.to_string_lossy());
    let env_w = build_env_block(&cfg.shim_log, &cfg.cwd, cfg.d3d12_debug);

    let created = unsafe {
        CreateProcessW(
            exe_w.as_ptr(),
            cmd_ptr,
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT,
            env_w.as_ptr().cast(),
            cwd_w.as_ptr(),
            &si,
            &mut pi,
        )
    };
    if created == 0 {
        return Err(format!("CreateProcessW failed: err={}", unsafe { GetLastError() }).into());
    }
    guard.process = pi.hProcess;
    guard.thread = pi.hThread;

    if unsafe { AssignProcessToJobObject(job, pi.hProcess) } == 0 {
        return Err(format!(
            "AssignProcessToJobObject failed: err={}",
            unsafe { GetLastError() }
        )
        .into());
    }
    unsafe { ResumeThread(pi.hThread) };

    let start = Instant::now();
    let timeout = Duration::from_millis(cfg.timeout_ms);

    let mut mods: BTreeMap<u64, LoadedMod> = BTreeMap::new();
    let mut load_order: Vec<String> = Vec::new();
    let mut debug_strings: Vec<String> = Vec::new();
    let mut first_chance_events: Vec<String> = Vec::new();
    let mut fatal_summary: Option<String> = None;
    let mut timeout_threads: Vec<String> = Vec::new();
    let mut fatal_code: Option<u32> = None;
    let mut fatal_addr_str: Option<String> = None;
    let mut process_exit_code: Option<u32> = None;
    let mut status = "unknown";
    let mut saw_initial_bp = false;
    let mut peak_ws_mb = 0.0f64;
    let mut peak_commit_mb = 0.0f64;
    let mut last_mem_poll = Instant::now();

    loop {
        if last_mem_poll.elapsed() >= Duration::from_millis(250) {
            let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
            pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if unsafe {
                GetProcessMemoryInfo(pi.hProcess, &mut pmc, size_of::<PROCESS_MEMORY_COUNTERS>() as u32)
            } != 0
            {
                peak_ws_mb = peak_ws_mb.max(pmc.PeakWorkingSetSize as f64 / (1024.0 * 1024.0));
                peak_commit_mb = peak_commit_mb.max(pmc.PeakPagefileUsage as f64 / (1024.0 * 1024.0));
            }
            last_mem_poll = Instant::now();
        }

        if start.elapsed() >= timeout {
            status = "timeout_clean_kill";
            timeout_threads = capture_thread_snapshot(pi.dwProcessId, pi.hProcess, &mods);
            unsafe { TerminateJobObject(job, 0xDEAD_0020) };
            unsafe { WaitForSingleObject(pi.hProcess, 2000) };
            break;
        }

        let mut ev: DEBUG_EVENT = unsafe { zeroed() };
        if unsafe { WaitForDebugEvent(&mut ev, 100) } == 0 {
            if unsafe { WaitForSingleObject(pi.hProcess, 0) } == WAIT_OBJECT_0 {
                status = "exited_unexpectedly";
                break;
            }
            continue;
        }

        let mut continue_status = DBG_CONTINUE;
        let mut break_loop = false;

        match ev.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { ev.u.CreateProcessInfo };
                let base = info.lpBaseOfImage as u64;
                let size = read_pe_image_size(pi.hProcess, base);
                let mut path = path_from_handle(info.hFile);
                if path.is_empty() {
                    path = cfg.exe.to_string_lossy().into_owned();
                }
                mods.insert(
                    base,
                    LoadedMod {
                        size,
                        path: path.clone(),
                    },
                );
                load_order.push(format!("0x{base:016X} (size=0x{size:X}) {path}"));
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { ev.u.LoadDll };
                let base = info.lpBaseOfDll as u64;
                let size = read_pe_image_size(pi.hProcess, base);
                let path = path_from_handle(info.hFile);
                let display = if path.is_empty() {
                    format!("<dll@0x{base:016X}>")
                } else {
                    path
                };
                mods.insert(
                    base,
                    LoadedMod {
                        size,
                        path: display.clone(),
                    },
                );
                load_order.push(format!("0x{base:016X} (size=0x{size:X}) {display}"));
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { ev.u.UnloadDll };
                mods.remove(&(info.lpBaseOfDll as u64));
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let info = unsafe { ev.u.DebugString };
                let msg = read_debug_string(
                    pi.hProcess,
                    info.lpDebugStringData as u64,
                    info.nDebugStringLength,
                    info.fUnicode != 0,
                );
                if !msg.is_empty() && debug_strings.len() < 200 {
                    debug_strings.push(msg);
                }
            }
            EXCEPTION_DEBUG_EVENT => {
                let info = unsafe { ev.u.Exception };
                let rec = info.ExceptionRecord;
                let code = rec.ExceptionCode as u32;
                let addr = rec.ExceptionAddress as u64;
                let first_chance = info.dwFirstChance != 0;

                if code == EXCEPTION_BREAKPOINT && !saw_initial_bp {
                    saw_initial_bp = true;
                    continue_status = DBG_CONTINUE;
                } else if code == MS_VC_THREAD_NAME_EXCEPTION || code == EXCEPTION_SINGLE_STEP {
                    continue_status = DBG_CONTINUE;
                } else {
                    let addr_fmt = format_addr(&mods, addr);
                    if first_chance {
                        if first_chance_events.len() < 50 {
                            first_chance_events.push(format!(
                                "[{:.3}s] first-chance 0x{code:08X} ({}) at {addr_fmt} tid={}",
                                start.elapsed().as_secs_f64(),
                                exc_name(code),
                                ev.dwThreadId
                            ));
                        }
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    } else {
                        // Second-chance (unhandled) fatal exception!
                        #[repr(C, align(16))]
                        struct AlignedContext(CONTEXT);
                        let mut aligned_ctx: AlignedContext = unsafe { zeroed() };
                        aligned_ctx.0.ContextFlags = CONTEXT_ALL_AMD64;
                        let h_thr = unsafe {
                            OpenThread(
                                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                0,
                                ev.dwThreadId,
                            )
                        };
                        let mut ctx_ok = false;
                        if !h_thr.is_null() {
                            ctx_ok = unsafe { GetThreadContext(h_thr, &mut aligned_ctx.0) } != 0;
                            unsafe { CloseHandle(h_thr) };
                        }
                        let ctx = &aligned_ctx.0;

                        let mut detail = String::new();
                        detail.push_str(&format!(
                            "FATAL EXCEPTION: 0x{code:08X} ({})\nThreadId: {}\nElapsed: {:.3}s\nFaultingAddress: {addr_fmt}\n",
                            exc_name(code),
                            ev.dwThreadId,
                            start.elapsed().as_secs_f64(),
                        ));
                        if code == 0xC000_0005 && rec.NumberParameters >= 2 {
                            let op = match rec.ExceptionInformation[0] {
                                0 => "READ".to_string(),
                                1 => "WRITE".to_string(),
                                8 => "DEP_EXEC".to_string(),
                                x => format!("OP_{x}"),
                            };
                            detail.push_str(&format!(
                                "AccessViolation: {op} target=0x{:016X}\n",
                                rec.ExceptionInformation[1]
                            ));
                        }
                        if ctx_ok {
                            detail.push_str(&format!(
                                "RIP={} RSP=0x{:016X} RBP=0x{:016X}\n",
                                format_addr(&mods, ctx.Rip),
                                ctx.Rsp,
                                ctx.Rbp
                            ));
                            detail.push_str(&format!(
                                "RAX=0x{:016X} RBX=0x{:016X} RCX=0x{:016X} RDX=0x{:016X}\n",
                                ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx
                            ));
                            detail.push_str(&format!(
                                "RSI=0x{:016X} RDI=0x{:016X} R8 =0x{:016X} R9 =0x{:016X}\n",
                                ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9
                            ));
                            detail.push_str(&format!(
                                "R10=0x{:016X} R11=0x{:016X} R12=0x{:016X} R13=0x{:016X}\n",
                                ctx.R10, ctx.R11, ctx.R12, ctx.R13
                            ));
                            detail.push_str(&format!(
                                "R14=0x{:016X} R15=0x{:016X} EFLAGS=0x{:08X}\n",
                                ctx.R14, ctx.R15, ctx.EFlags
                            ));
                            let code_bytes = read_bytes(pi.hProcess, ctx.Rip, 32);
                            if !code_bytes.is_empty() {
                                let hex: Vec<String> =
                                    code_bytes.iter().map(|b| format!("{b:02X}")).collect();
                                detail.push_str(&format!("Bytes@RIP: {}\n", hex.join(" ")));
                            }
                            let stack_bytes = read_bytes(pi.hProcess, ctx.Rsp, 128);
                            if stack_bytes.len() >= 8 {
                                detail.push_str("Stack QWORDs:\n");
                                for (idx, chunk) in stack_bytes.as_chunks::<8>().0.iter().enumerate() {
                                    let val = u64::from_le_bytes(*chunk);
                                    detail.push_str(&format!(
                                        "  [RSP+0x{:02X}] = {}\n",
                                        idx * 8,
                                        format_addr(&mods, val)
                                    ));
                                }
                            }
                        }

                        fatal_code = Some(code);
                        fatal_addr_str = Some(addr_fmt);
                        fatal_summary = Some(detail);
                        status = "crashed_unhandled_exception";
                        break_loop = true;
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let info = unsafe { ev.u.ExitProcess };
                process_exit_code = Some(info.dwExitCode);
                status = "exited";
                break_loop = true;
            }
            RIP_EVENT => {
                status = "rip_event";
                break_loop = true;
            }
            _ => {}
        }

        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continue_status) };
        if break_loop {
            unsafe {
                TerminateJobObject(job, fatal_code.unwrap_or(0));
                WaitForSingleObject(pi.hProcess, 2000);
            }
            break;
        }
    }

    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    if unsafe {
        GetProcessMemoryInfo(pi.hProcess, &mut pmc, size_of::<PROCESS_MEMORY_COUNTERS>() as u32)
    } != 0
    {
        peak_ws_mb = peak_ws_mb.max(pmc.PeakWorkingSetSize as f64 / (1024.0 * 1024.0));
        peak_commit_mb = peak_commit_mb.max(pmc.PeakPagefileUsage as f64 / (1024.0 * 1024.0));
    }

    let elapsed_s = start.elapsed().as_secs_f64();
    let txt_path = cfg.log_dir.join("boot_probe_latest.txt");
    let json_path = cfg.log_dir.join("boot_probe_latest.json");

    {
        let mut f = File::create(&txt_path)?;
        writeln!(f, "=== LUCIAS PROJECT Native Boot Probe Report ===")?;
        writeln!(f, "Exe: {}", cfg.exe.display())?;
        writeln!(f, "Status: {status}")?;
        writeln!(f, "Elapsed: {elapsed_s:.3}s (cap={}ms)", cfg.timeout_ms)?;
        writeln!(
            f,
            "Memory Cap: {} MiB | PeakWorkingSet: {:.2} MiB | PeakCommit: {:.2} MiB",
            cfg.mem_limit_mb, peak_ws_mb, peak_commit_mb
        )?;
        if let Some(ec) = process_exit_code {
            writeln!(f, "ExitCode: 0x{ec:08X} ({ec})")?;
        }
        if let Some(ref fsumm) = fatal_summary {
            writeln!(f, "\n--- Crash Detail ---\n{fsumm}")?;
        }
        if !timeout_threads.is_empty() {
            writeln!(f, "\n--- Timeout Thread Snapshot ({}) ---", timeout_threads.len())?;
            for t in &timeout_threads {
                writeln!(f, "  {t}")?;
            }
        }
        writeln!(f, "\n--- First-Chance Exceptions ({}) ---", first_chance_events.len())?;
        for e in &first_chance_events {
            writeln!(f, "  {e}")?;
        }
        writeln!(f, "\n--- OutputDebugString ({}) ---", debug_strings.len())?;
        for d in &debug_strings {
            writeln!(f, "  {d}")?;
        }
        writeln!(f, "\n--- Loaded Modules ({}) ---", load_order.len())?;
        for m in &load_order {
            writeln!(f, "  {m}")?;
        }
    }

    {
        let mut jf = File::create(&json_path)?;
        let fatal_code_json = match fatal_code {
            Some(c) => format!("\"0x{c:08X}\""),
            None => "null".to_string(),
        };
        let fatal_addr_json = match &fatal_addr_str {
            Some(a) => format!("\"{}\"", json_escape(a)),
            None => "null".to_string(),
        };
        let exit_code_json = match process_exit_code {
            Some(c) => format!("{c}"),
            None => "null".to_string(),
        };
        writeln!(jf, "{{")?;
        writeln!(jf, "  \"status\": \"{status}\",")?;
        writeln!(jf, "  \"elapsed_seconds\": {elapsed_s:.3},")?;
        writeln!(jf, "  \"mem_limit_mb\": {},", cfg.mem_limit_mb)?;
        writeln!(jf, "  \"peak_working_set_mb\": {peak_ws_mb:.2},")?;
        writeln!(jf, "  \"peak_commit_mb\": {peak_commit_mb:.2},")?;
        writeln!(jf, "  \"exit_code\": {exit_code_json},")?;
        writeln!(jf, "  \"fatal_exception_code\": {fatal_code_json},")?;
        writeln!(jf, "  \"fatal_address\": {fatal_addr_json},")?;
        writeln!(jf, "  \"loaded_module_count\": {},", load_order.len())?;
        writeln!(jf, "  \"first_chance_count\": {},", first_chance_events.len())?;
        writeln!(jf, "  \"debug_string_count\": {},", debug_strings.len())?;
        writeln!(jf, "  \"report_txt\": \"{}\"", json_escape(&txt_path.to_string_lossy()))?;
        writeln!(jf, "}}")?;
    }

    println!(
        "LuciasBootProbe status={status} elapsed={elapsed_s:.2}s peak_ws={peak_ws_mb:.1}MB peak_commit={peak_commit_mb:.1}MB mods={} fatal_code={:?} fatal_addr={:?}",
        load_order.len(),
        fatal_code.map(|c| format!("0x{c:08X}")),
        fatal_addr_str
    );

    Ok(())
}
