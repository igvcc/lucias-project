#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::ffi::{CString, c_void};
use std::path::{Path, PathBuf};

use dx12xs_pc::dxpk::DxpkReader;
use pe_native_patcher::{
    ImportSymbolKind, PatchConfig, analyze_file, analyze_pe, default_console_dll_remap,
    patch_pe_bytes, subsystem, vfs_hook_dll_remap,
};
use windows_sys::Win32::Foundation::{CloseHandle, FreeLibrary, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

const REAL_EXE_PATH: &str = r"S:\gta\Gta6fordevelopersacces\game_scarlett_master.exe";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn find_built_dll_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
    if profile_dir.join("xmem_pc.dll").exists() && profile_dir.join("xgameruntime.dll").exists() {
        return profile_dir;
    }
    let root = workspace_root();
    for sub in ["target/debug", "target/release"] {
        let cand = root.join(sub);
        if cand.join("xmem_pc.dll").exists() && cand.join("xgameruntime.dll").exists() {
            return cand;
        }
    }
    panic!("cannot locate built shim DLLs; run `cargo build --workspace` first");
}

fn stage_shims_to_out(dll_dir: &Path) -> PathBuf {
    static STAGED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    STAGED
        .get_or_init(|| {
            let out_dir = workspace_root().join("out");
            std::fs::create_dir_all(&out_dir).unwrap();
            let dlls = [
                "xmem_pc.dll",
                "xcrd_pc.dll",
                "ffx_pc.dll",
                "dx12xs_pc.dll",
                "xg_pc.dll",
                "xbvh_pc.dll",
                "chad_pc.dll",
                "audio_pc.dll",
                "bink2_pc.dll",
                "hc_pc.dll",
                "gi_pc.dll",
                "GameInput.dll",
                "vfs_pc.dll",
                "xgameruntime.dll",
            ];
            for name in dlls {
                let src = dll_dir.join(name);
                assert!(src.exists(), "missing built shim DLL: {}", src.display());
                let dst = out_dir.join(name);
                std::fs::copy(&src, &dst).unwrap();
            }
            out_dir
        })
        .clone()
}

fn load_dll(dir: &Path, name: &str) -> HMODULE {
    let wide: Vec<u16> = dir
        .join(name)
        .to_string_lossy()
        .encode_utf16()
        .chain([0])
        .collect();
    let h = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert!(!h.is_null(), "LoadLibraryW failed for {name}");
    h
}

fn resolve_symbol(h: HMODULE, sym: &ImportSymbolKind) -> usize {
    let addr = match sym {
        ImportSymbolKind::Name { name, .. } => {
            let c = CString::new(name.as_str()).unwrap();
            unsafe { GetProcAddress(h, c.as_ptr().cast()) }
        }
        ImportSymbolKind::Ordinal(ord) => {
            let ord_ptr = std::ptr::without_provenance::<u8>(*ord as usize);
            unsafe { GetProcAddress(h, ord_ptr) }
        }
    };
    addr.map_or(0, |f| f as usize)
}

#[test]
fn real_exe_dry_run_patch_and_loadlibrary_getprocaddress_coverage() {
    let dll_dir = find_built_dll_dir();
    let out_dir = stage_shims_to_out(&dll_dir);

    let real_exe = Path::new(REAL_EXE_PATH);
    assert!(
        real_exe.exists(),
        "expected read-only Scarlett binary at {REAL_EXE_PATH}"
    );

    let bytes = std::fs::read(real_exe).unwrap();
    let before = analyze_pe(&bytes).unwrap();
    assert_eq!(before.imports.len(), 68);
    assert_eq!(before.total_import_count, 587);
    assert_eq!(before.total_delay_import_count, 0);

    // 1. Dry-run patch in-memory (standard 12 console DLLs)
    let (patched, report) = patch_pe_bytes(&bytes, &PatchConfig::default()).unwrap();
    assert!(report.integrity_verified);
    assert_eq!(report.remapped_dlls.len(), 12);
    assert_eq!(report.total_remapped_imports, 110);
    assert_eq!(report.added_section, None);

    let after = analyze_pe(&patched).unwrap();
    assert_eq!(after.total_import_count, 587);
    assert_eq!(after.tls_callbacks, before.tls_callbacks);

    // 2. Dry-run patch with VFS + Virtual Registry hook enabled as well
    let vfs_cfg = PatchConfig {
        hook_vfs: true,
        ..PatchConfig::default()
    };
    let (patched_vfs, vfs_report) = patch_pe_bytes(&bytes, &vfs_cfg).unwrap();
    assert!(vfs_report.integrity_verified);
    assert_eq!(vfs_report.remapped_dlls.len(), 17);
    assert_eq!(vfs_report.total_remapped_imports, 145);
    let after_vfs = analyze_pe(&patched_vfs).unwrap();
    assert_eq!(after_vfs.total_import_count, 587);

    // 3. LoadLibrary + GetProcAddress resolution of 100% of console imports from real IAT
    let remap = default_console_dll_remap();
    let mut loaded_handles: BTreeMap<String, HMODULE> = BTreeMap::new();
    let mut resolved_console_count = 0usize;

    for imp_mod in &before.imports {
        let lower = imp_mod.dll.to_ascii_lowercase();
        let Some(pc_dll) = remap.get(&lower) else {
            continue;
        };
        let handle = *loaded_handles
            .entry(pc_dll.clone())
            .or_insert_with(|| load_dll(&out_dir, pc_dll));
        for entry in &imp_mod.entries {
            let proc = resolve_symbol(handle, &entry.symbol);
            assert_ne!(
                proc, 0,
                "failed GetProcAddress for {}!{} in {}",
                imp_mod.dll, entry.symbol, pc_dll
            );
            resolved_console_count += 1;
        }
    }
    assert_eq!(resolved_console_count, 110);

    // Verify GameInput.dll (unremapped name) resolves ordinal #1
    let gi_orig = load_dll(&out_dir, "GameInput.dll");
    assert_ne!(
        resolve_symbol(gi_orig, &ImportSymbolKind::Ordinal(1)),
        0,
        "GameInput.dll #1 failed"
    );
    unsafe { FreeLibrary(gi_orig) };

    // Verify vfs_pc.dll resolves 100% (35/35) of api-ms-win-core-file, libraryloader, and advapi32 imports
    let vfs_h = load_dll(&out_dir, "vfs_pc.dll");
    let vfs_sources: Vec<_> = vfs_hook_dll_remap().iter().map(|(k, _)| *k).collect();
    let mut vfs_resolved = 0usize;
    for imp_mod in &before.imports {
        if vfs_sources.contains(&imp_mod.dll.to_ascii_lowercase().as_str()) {
            for entry in &imp_mod.entries {
                let proc = resolve_symbol(vfs_h, &entry.symbol);
                assert_ne!(
                    proc, 0,
                    "failed VFS GetProcAddress for {}!{}",
                    imp_mod.dll, entry.symbol
                );
                vfs_resolved += 1;
            }
        }
    }
    assert_eq!(vfs_resolved, 35);
    unsafe { FreeLibrary(vfs_h) };

    // Verify xgameruntime.dll resolves all 6/6 GDK runtime gateway exports
    let xgr_h = load_dll(&out_dir, "xgameruntime.dll");
    let xgr_exports = [
        "QueryApiImpl",
        "InitializeApiImpl",
        "InitializeApiImplEx",
        "InitializeApiImplEx2",
        "XErrorReport",
        "UninitializeApiImpl",
    ];
    for name in xgr_exports {
        let sym = ImportSymbolKind::Name {
            hint: 0,
            name: name.to_string(),
        };
        assert_ne!(
            resolve_symbol(xgr_h, &sym),
            0,
            "xgameruntime.dll missing export {name}"
        );
    }
    unsafe { FreeLibrary(xgr_h) };

    for (_, h) in loaded_handles {
        unsafe { FreeLibrary(h) };
    }
}

#[test]
fn xmem_pc_has_exact_12_xmem_exports_and_functional_core() {
    let dll_dir = find_built_dll_dir();
    let out_dir = stage_shims_to_out(&dll_dir);
    let xmem_path = out_dir.join("xmem_pc.dll");

    let dll_bytes = std::fs::read(&xmem_path).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*dll_bytes).unwrap();
    let exports = pe.export_table().unwrap().unwrap().exports().unwrap();
    let xmem_names: Vec<String> = exports
        .iter()
        .filter_map(|e| e.name.map(|n| String::from_utf8_lossy(n).into_owned()))
        .filter(|n| n.starts_with("XMem"))
        .collect();
    assert_eq!(xmem_names.len(), 12, "XMem* exports: {xmem_names:?}");

    let h = load_dll(&out_dir, "xmem_pc.dll");
    type XMemAllocFn = unsafe extern "system" fn(usize, u64) -> *mut c_void;
    type XMemFreeFn = unsafe extern "system" fn(*mut c_void, u64);
    type XMemIsToolsFn = unsafe extern "system" fn() -> i32;
    type XMemStatsFn = unsafe extern "system" fn(u32, *mut [u8; 0x50]) -> i32;

    let alloc: XMemAllocFn = unsafe {
        std::mem::transmute(GetProcAddress(h, c"XMemAlloc".as_ptr().cast()).unwrap())
    };
    let free: XMemFreeFn = unsafe {
        std::mem::transmute(GetProcAddress(h, c"XMemFree".as_ptr().cast()).unwrap())
    };
    let tools: XMemIsToolsFn = unsafe {
        std::mem::transmute(GetProcAddress(h, c"XMemIsToolsMemAvailable".as_ptr().cast()).unwrap())
    };
    let stats_fn: XMemStatsFn = unsafe {
        std::mem::transmute(GetProcAddress(h, c"XMemGetWorkingSetStatistics".as_ptr().cast()).unwrap())
    };

    unsafe {
        assert_eq!(tools(), 0);
        let p = alloc(8192, 16u64 << 24);
        assert!(!p.is_null());
        assert_eq!((p as usize) % 65536, 0);
        p.cast::<u8>().write_bytes(0xCD, 8192);
        let mut buf = [0u8; 0x50];
        assert_eq!(stats_fn(0x2000_0001, &mut buf), 1);
        let title_limit = usize::from_le_bytes(buf[0..8].try_into().unwrap());
        assert!(title_limit > 0);
        free(p, 16u64 << 24);
        FreeLibrary(h);
    }
}

#[test]
fn vfs_pc_and_ffx_pc_live_dll_functional_smoke() {
    let dll_dir = find_built_dll_dir();
    let out_dir = stage_shims_to_out(&dll_dir);

    let ffx_h = load_dll(&out_dir, "ffx_pc.dll");
    #[repr(C)]
    struct Hdr {
        t: u64,
        next: *mut c_void,
    }
    type CreateFn = unsafe extern "C" fn(*mut *mut c_void, *const Hdr, *const c_void) -> u32;
    type DispatchFn = unsafe extern "C" fn(*mut *mut c_void, *const Hdr) -> u32;
    type DestroyFn = unsafe extern "C" fn(*mut *mut c_void, *const c_void) -> u32;

    unsafe {
        let create: CreateFn =
            std::mem::transmute(GetProcAddress(ffx_h, c"ffxCreateContext".as_ptr().cast()).unwrap());
        let dispatch: DispatchFn =
            std::mem::transmute(GetProcAddress(ffx_h, c"ffxDispatch".as_ptr().cast()).unwrap());
        let destroy: DestroyFn =
            std::mem::transmute(GetProcAddress(ffx_h, c"ffxDestroyContext".as_ptr().cast()).unwrap());
        let mut ctx = std::ptr::null_mut();
        let hdr = Hdr {
            t: 0x10000,
            next: std::ptr::null_mut(),
        };
        assert_eq!(create(&mut ctx, &hdr, std::ptr::null()), 0);
        assert!(!ctx.is_null());
        assert_eq!(dispatch(&mut ctx, &hdr), 0);
        assert_eq!(destroy(&mut ctx, std::ptr::null()), 0);
        assert!(ctx.is_null());
        FreeLibrary(ffx_h);
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("boot.cfg"), b"ok").unwrap();
    let vfs_h = load_dll(&out_dir, "vfs_pc.dll");
    type MountFn = unsafe extern "system" fn(u16, *const u16) -> i32;
    type UnmountFn = unsafe extern "system" fn();
    type CreateFileWFn = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *const c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;

    unsafe {
        let mount: MountFn =
            std::mem::transmute(GetProcAddress(vfs_h, c"VfsMountDriveW".as_ptr().cast()).unwrap());
        let unmount: UnmountFn =
            std::mem::transmute(GetProcAddress(vfs_h, c"VfsUnmountAll".as_ptr().cast()).unwrap());
        let cf: CreateFileWFn =
            std::mem::transmute(GetProcAddress(vfs_h, c"CreateFileW".as_ptr().cast()).unwrap());

        let root_w: Vec<u16> = tmp
            .path()
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        assert_eq!(mount(b'G' as u16, root_w.as_ptr()), 1);

        let g_file: Vec<u16> = "G:\\boot.cfg\0".encode_utf16().collect();
        let fh = cf(
            g_file.as_ptr(),
            0x8000_0000,
            1,
            std::ptr::null(),
            3,
            0x80,
            std::ptr::null_mut(),
        );
        assert_ne!(fh, INVALID_HANDLE_VALUE);
        CloseHandle(fh);
        unmount();

        // Verify live RegOpenKeyW / RegQueryValueExW / RegCloseKey exports return ConsoleMode=0x60 (Series S)
        type RegOpenWFn = unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> u32;
        type RegQueryWFn = unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            *mut u32,
            *mut u32,
            *mut u8,
            *mut u32,
        ) -> u32;
        type RegCloseFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let reg_open: RegOpenWFn =
            std::mem::transmute(GetProcAddress(vfs_h, c"RegOpenKeyW".as_ptr().cast()).unwrap());
        let reg_query: RegQueryWFn =
            std::mem::transmute(GetProcAddress(vfs_h, c"RegQueryValueExW".as_ptr().cast()).unwrap());
        let reg_close: RegCloseFn =
            std::mem::transmute(GetProcAddress(vfs_h, c"RegCloseKey".as_ptr().cast()).unwrap());

        std::env::remove_var("LUCIAS_CONSOLE_MODE");
        let hklm = 0xffff_ffff_8000_0002_u64 as *mut c_void;
        let oem: Vec<u16> = "Software\\Microsoft\\Windows NT\\CurrentVersion\\OEM\0"
            .encode_utf16()
            .collect();
        let val_name: Vec<u16> = "ConsoleMode\0".encode_utf16().collect();
        let mut hkey = std::ptr::null_mut();
        assert_eq!(reg_open(hklm, oem.as_ptr(), &mut hkey), 0);
        assert!(!hkey.is_null());
        let mut reg_ty = 0u32;
        let mut mode_val = 0u32;
        let mut mode_sz = 4u32;
        assert_eq!(
            reg_query(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut reg_ty,
                (&raw mut mode_val).cast(),
                &mut mode_sz,
            ),
            0
        );
        assert_eq!(reg_ty, 4);
        assert_eq!(mode_val, 0x60);
        assert_eq!(reg_close(hkey), 0);

        FreeLibrary(vfs_h);
    }
}

#[test]
fn live_functional_dx12xs_xg_xbvh_and_xgameruntime() {
    let dll_dir = find_built_dll_dir();
    let out_dir = stage_shims_to_out(&dll_dir);

    // 1) dx12xs_pc.dll: VirtualMemoryX, SerializeVersionedRootSignature (Xbox flag strip),
    //    and D3D12XboxCreateDevice (0x50B param struct + IID_ID3D12Device11).
    let dx12_h = load_dll(&out_dir, "dx12xs_pc.dll");
    #[repr(C)]
    struct VmCfg {
        flags: u32,
        reserved: u32,
        title_va_size: u64,
        system_va_size: u64,
        extra: u64,
    }
    #[repr(C)]
    struct XboxParams {
        version: u32,
        device_flags: u32,
        p_scratch: *mut c_void,
        scratch_size: usize,
        ring_size: u64,
        cmd_alloc_size: u64,
        reserved_28: [u64; 2],
        reserved_38: u32,
        flags_3c: u32,
        reserved_40: [u64; 2],
    }
    #[repr(C)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }
    #[repr(C)]
    struct VersionedRootSig {
        version: u32,
        _pad: u32,
        num_params: u32,
        _p0: u32,
        params: *const c_void,
        num_samplers: u32,
        _p1: u32,
        samplers: *const c_void,
        flags: u32,
        _p2: u32,
    }

    type CfgVmFn = unsafe extern "system" fn(*const VmCfg) -> i32;
    type SerRootFn = unsafe extern "system" fn(*const c_void, *mut *mut c_void, *mut *mut c_void) -> i32;
    type CreateDevFn = unsafe extern "system" fn(*mut c_void, *const XboxParams, *const Guid, *mut *mut c_void) -> i32;
    type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;

    unsafe {
        let cfg_vm: CfgVmFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"D3D12ConfigureVirtualMemoryX".as_ptr().cast()).unwrap(),
        );
        let ser_root: SerRootFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"D3D12SerializeVersionedRootSignature".as_ptr().cast()).unwrap(),
        );
        let create_dev: CreateDevFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"D3D12XboxCreateDevice".as_ptr().cast()).unwrap(),
        );

        let vm = VmCfg {
            flags: 1,
            reserved: 0,
            title_va_size: 0x1_0000_0000,
            system_va_size: 0x2000_0000,
            extra: 0,
        };
        assert_eq!(cfg_vm(&vm), 0);

        let rs = VersionedRootSig {
            version: 2,
            _pad: 0,
            num_params: 0,
            _p0: 0,
            params: std::ptr::null(),
            num_samplers: 0,
            _p1: 0,
            samplers: std::ptr::null(),
            flags: 0xFF00_0000,
            _p2: 0,
        };
        let mut blob = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(ser_root((&raw const rs).cast(), &mut blob, &mut err), 0);
        assert!(!blob.is_null());
        let b_vtbl = *blob.cast::<*const *const c_void>();
        let b_rel: RelFn = std::mem::transmute(*b_vtbl.add(2));
        b_rel(blob);

        let params = XboxParams {
            version: 0x20004,
            device_flags: 0,
            p_scratch: std::ptr::null_mut(),
            scratch_size: 0x10_0000,
            ring_size: 0,
            cmd_alloc_size: 0,
            reserved_28: [0; 2],
            reserved_38: 0,
            flags_3c: 0x20,
            reserved_40: [0; 2],
        };
        let iid_dev11 = Guid {
            d1: 0x5405_c344,
            d2: 0xd457,
            d3: 0x444e,
            d4: [0xb4, 0xdd, 0x23, 0x66, 0xe4, 0x5a, 0xee, 0x39],
        };
        let tmp_json = tempfile::tempdir().unwrap();
        let json_path = tmp_json.path().join("telemetry_latest.json");
        std::env::set_var("LUCIAS_TELEMETRY_JSON", &json_path);

        let mut dev = std::ptr::null_mut();
        let hr = create_dev(std::ptr::null_mut(), &params, &iid_dev11, &mut dev);
        assert_eq!(hr, 0, "D3D12XboxCreateDevice(ID3D12Device11) failed: 0x{hr:08x}");
        assert!(!dev.is_null());
        // Verify Xbox DeviceX+0x18 non-null context field, GetNodeCount (slot 7),
        // sret-first GetCustomHeapProperties (slot 26), and scalar u64 handle return.
        assert_ne!(*(dev as *const usize).byte_add(0x18), 0);
        let d_vtbl = *dev.cast::<*const *const c_void>();
        type GetNodeCountFn = unsafe extern "system" fn(*mut c_void) -> u32;
        let get_nodes: GetNodeCountFn = std::mem::transmute(*d_vtbl.add(7));
        assert_eq!(get_nodes(dev), 1);

        #[repr(C)]
        #[derive(Default)]
        struct HeapProps {
            ty: u32,
            cpu_page_prop: u32,
            memory_pool: u32,
            creation_mask: u32,
            visible_mask: u32,
        }
        type GetCustomHeapFn =
            unsafe extern "system" fn(*mut HeapProps, *mut c_void, u32, u32) -> *mut HeapProps;
        let get_custom_heap: GetCustomHeapFn = std::mem::transmute(*d_vtbl.add(26));
        let mut hp = HeapProps::default();
        let ret_hp = get_custom_heap(&mut hp, dev, 0, 1);
        assert_eq!(ret_hp, &mut hp as *mut HeapProps);
        assert_eq!(hp.ty, 4); // Real D3D12 returns D3D12_HEAP_TYPE_CUSTOM (4)

        type AttachFn = unsafe extern "system" fn(*mut c_void) -> i32;
        type TickFn = unsafe extern "system" fn() -> i32;
        type ToggleFn = unsafe extern "system" fn() -> u32;
        type ErrHudFn = unsafe extern "system" fn(u64, *const i8, i32) -> i32;
        type ShutdownFn = unsafe extern "system" fn() -> i32;

        let hud_attach: AttachFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"LuciasOverlayAttachWindow".as_ptr().cast()).unwrap(),
        );
        let hud_tick: TickFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"LuciasOverlayTick".as_ptr().cast()).unwrap(),
        );
        let hud_toggle: ToggleFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"LuciasOverlayToggle".as_ptr().cast()).unwrap(),
        );
        let hud_err: ErrHudFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"LuciasOverlayRecordShaderError".as_ptr().cast()).unwrap(),
        );
        let hud_shutdown: ShutdownFn = std::mem::transmute(
            GetProcAddress(dx12_h, c"LuciasOverlayShutdown".as_ptr().cast()).unwrap(),
        );
        assert_eq!(hud_attach(std::ptr::null_mut()), 0);
        assert_eq!(hud_err(0x1234_5678_9ABC_DEF0, c"VS".as_ptr(), -1), 0);
        assert_eq!(hud_tick(), 0);
        assert_eq!(hud_toggle(), 0);
        assert_eq!(hud_toggle(), 1);
        assert_eq!(hud_shutdown(), 0);

        // Verify Xbox CreateCommandSignature (slot 41) with console argument type 12 succeeds.
        #[repr(C)]
        struct SigDesc {
            stride: u32,
            count: u32,
            args: *const [u32; 4],
            node_mask: u32,
        }
        type CreateCmdSigFn = unsafe extern "system" fn(
            *mut c_void,
            *const SigDesc,
            *mut c_void,
            *const Guid,
            *mut *mut c_void,
        ) -> i32;
        let create_sig: CreateCmdSigFn = std::mem::transmute(*d_vtbl.add(41));
        let iid_sig = Guid {
            d1: 0xc36a_797c,
            d2: 0xec80,
            d3: 0x4f0a,
            d4: [0x89, 0x85, 0xa7, 0xb2, 0x47, 0x50, 0x82, 0xd1],
        };
        let args = [[12u32, 0, 0, 0]];
        let sig_desc = SigDesc {
            stride: 4,
            count: 1,
            args: args.as_ptr(),
            node_mask: 0,
        };
        let mut sig_obj = std::ptr::null_mut();
        assert_eq!(
            create_sig(dev, &sig_desc, std::ptr::null_mut(), &iid_sig, &mut sig_obj),
            0
        );
        assert!(!sig_obj.is_null());
        let s_vtbl = *sig_obj.cast::<*const *const c_void>();
        let s_rel: RelFn = std::mem::transmute(*s_vtbl.add(2));
        s_rel(sig_obj);

        let d_rel: RelFn = std::mem::transmute(*d_vtbl.add(2));
        d_rel(dev);

        FreeLibrary(dx12_h);
    }

    // Verify DXPK O(1) + binary-search reader against active LUCIAS_PROJECT / fallback cache if present
    let dxpk_path = dx12xs_pc::dxpk::resolve_shader_pack_path();
    if dxpk_path.exists() {
        let reader = DxpkReader::open(&dxpk_path).unwrap();
        assert!(reader.entry_count() > 0);
        let first_hash = reader.entries()[0].hash;
        assert_eq!(
            reader.find_entry(first_hash),
            reader.find_entry_binary_search(first_hash)
        );
        let (_, blob) = reader.read_blob_by_hash(first_hash).unwrap().unwrap();
        assert!(!blob.is_empty());
    }

    // 2) xg_pc.dll: XGSuggestSwizzleMode + XGCreateTextureComputer + COM GetResourceLayout & Release
    let xg_h = load_dll(&out_dir, "xg_pc.dll");
    #[repr(C)]
    struct XgDesc {
        dimension: u32,
        alignment: u64,
        width: u64,
        height: u32,
        depth_or_array: u16,
        mips: u16,
        format: u32,
        samples: u32,
        quality: u32,
        layout: u32,
        flags: u32,
    }
    type SuggestFn = unsafe extern "system" fn(*const XgDesc, u32, *mut u32) -> i32;
    type CreateCompFn = unsafe extern "system" fn(*const XgDesc, *mut *mut c_void) -> i32;
    type GetLayoutFn = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
    type GetSizeFn = unsafe extern "system" fn(*mut c_void) -> u64;
    type CompRelFn = unsafe extern "system" fn(*mut c_void) -> u32;

    unsafe {
        let suggest: SuggestFn = std::mem::transmute(
            GetProcAddress(xg_h, c"XGSuggestSwizzleMode".as_ptr().cast()).unwrap(),
        );
        let create_comp: CreateCompFn = std::mem::transmute(
            GetProcAddress(xg_h, c"XGCreateTextureComputer".as_ptr().cast()).unwrap(),
        );
        let desc = XgDesc {
            dimension: 3, // Texture2D
            alignment: 0,
            width: 256,
            height: 256,
            depth_or_array: 1,
            mips: 3,
            format: 71, // BC1_UNORM
            samples: 1,
            quality: 0,
            layout: 0,
            flags: 1, // RenderTarget
        };
        let mut swizzle = 0u32;
        assert_eq!(suggest(&desc, 0, &mut swizzle), 0);
        assert_eq!(swizzle, 0x100 | 27); // SW_64KB_R_X

        let mut comp = std::ptr::null_mut();
        assert_eq!(create_comp(&desc, &mut comp), 0);
        assert!(!comp.is_null());
        let vtbl = *comp.cast::<*const *const c_void>();
        let get_layout: GetLayoutFn = std::mem::transmute(*vtbl.add(2));
        let get_size: GetSizeFn = std::mem::transmute(*vtbl.add(3));
        let release: CompRelFn = std::mem::transmute(*vtbl.add(1));

        let mut layout_buf = vec![0u8; 0x1b40];
        assert_eq!(get_layout(comp, layout_buf.as_mut_ptr()), 0);
        let layout_size = u64::from_le_bytes(layout_buf[0..8].try_into().unwrap());
        assert_eq!(layout_size, get_size(comp));
        assert!(layout_size >= 65536);
        assert_eq!(release(comp), 0);
        FreeLibrary(xg_h);
    }

    // 3) xbvh_pc.dll: 7 mangled exports wired to 0x50B batched descriptor translation
    let xbvh_h = load_dll(&out_dir, "xbvh_pc.dll");
    #[repr(C)]
    struct BatchedDesc {
        dest_va: u64,
        inputs_ty: u32,
        inputs_flags: u32,
        num_descs: u32,
        descs_layout: u32,
        descs_ptr: u64,
        source_va: u64,
        scratch_va: u64,
        num_postbuild: u32,
        _pad34: u32,
        postbuild_ptr: u64,
        _reserved: [u64; 2],
    }
    #[repr(C)]
    #[derive(Default)]
    struct PrebuildInfo {
        result_bytes: u64,
        scratch_bytes: u64,
        update_bytes: u64,
    }
    type CtorFn = unsafe extern "C" fn(*mut u8, *mut c_void, bool) -> *mut u8;
    type DtorFn = unsafe extern "C" fn(*mut u8);
    type MortonFn = unsafe extern "C" fn(*mut u8, bool);
    type PrebuildFn = unsafe extern "C" fn(*mut u8, *const c_void, *const c_void, *mut PrebuildInfo);
    type BuildFn = unsafe extern "C" fn(*mut u8, *mut c_void, u32, *const BatchedDesc);
    type RehydrateFn = unsafe extern "C" fn(*mut u8, *mut c_void, u32, *const c_void, *const u64) -> i32;

    unsafe {
        let ctor: CtorFn = std::mem::transmute(
            GetProcAddress(xbvh_h, c"??0XboxBvhBuilder@@QEAA@PEAUID3D12Device11@@_N@Z".as_ptr().cast()).unwrap(),
        );
        let dtor: DtorFn = std::mem::transmute(
            GetProcAddress(xbvh_h, c"??1XboxBvhBuilder@@QEAA@XZ".as_ptr().cast()).unwrap(),
        );
        let morton: MortonFn = std::mem::transmute(
            GetProcAddress(xbvh_h, c"?Set64BitMortonCodes@XboxBvhBuilder@@QEAAX_N@Z".as_ptr().cast()).unwrap(),
        );
        let prebuild: PrebuildFn = std::mem::transmute(
            GetProcAddress(xbvh_h, c"?GetRaytracingAccelerationStructurePrebuildInfo@XboxBvhBuilder@@QEAAXPEBUD3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS@@PEBUD3D12XBOX_XDXR_STREAM_DESC@@PEAUD3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO@@@Z".as_ptr().cast()).unwrap(),
        );
        let build: BuildFn = std::mem::transmute(
            GetProcAddress(xbvh_h, c"?BuildRaytracingAccelerationStructureBatched2X@XboxBvhBuilder@@QEAAXPEAUID3D12GraphicsCommandList6@@IPEBUD3D12XBOX_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_BATCHED_DESC2@@@Z".as_ptr().cast()).unwrap(),
        );
        let rehydrate: RehydrateFn = std::mem::transmute(
            GetProcAddress(xbvh_h, c"?RehydrateRaytracingAccelerationStructureBatched2X@XboxBvhBuilder@@QEAAJPEAUID3D12GraphicsCommandList8@@IPEBUD3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC@@PEB_K@Z".as_ptr().cast()).unwrap(),
        );

        let mut builder = [0u8; 16];
        ctor(builder.as_mut_ptr(), std::ptr::null_mut(), true);
        morton(builder.as_mut_ptr(), true);

        let mut info = PrebuildInfo::default();
        prebuild(builder.as_mut_ptr(), std::ptr::null(), std::ptr::null(), &mut info);
        assert!(info.result_bytes >= 256 && info.result_bytes % 256 == 0);

        let desc = BatchedDesc {
            dest_va: 0x1000,
            inputs_ty: 1,
            inputs_flags: 0x22,
            num_descs: 8,
            descs_layout: 0,
            descs_ptr: 0x2000,
            source_va: 0,
            scratch_va: 0x3000,
            num_postbuild: 1,
            _pad34: 0,
            postbuild_ptr: 0x4000,
            _reserved: [0; 2],
        };
        build(builder.as_mut_ptr(), std::ptr::null_mut(), 1, &desc);
        let vas = [0x1000u64];
        assert_eq!(
            rehydrate(builder.as_mut_ptr(), std::ptr::null_mut(), 1, std::ptr::null(), vas.as_ptr()),
            0
        );
        dtor(builder.as_mut_ptr());
        FreeLibrary(xbvh_h);
    }

    // 4) xgameruntime.dll: InitializeApiImplEx2 -> QueryApiImpl -> XErrorReport -> UninitializeApiImpl
    let tmp_appdata = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("LUCIAS_PROJECT_DATA_DIR", tmp_appdata.path()) };
    let xgr_h = load_dll(&out_dir, "xgameruntime.dll");
    type InitEx2Fn = unsafe extern "system" fn(u64, u64, u64, *const c_void) -> i32;
    type QueryFn = unsafe extern "system" fn(*const Guid, *const Guid, *mut *mut c_void) -> i32;
    type ErrRepFn = unsafe extern "system" fn(i32, *const i8) -> i32;
    type UninitFn = unsafe extern "system" fn() -> i32;

    unsafe {
        let init: InitEx2Fn = std::mem::transmute(
            GetProcAddress(xgr_h, c"InitializeApiImplEx2".as_ptr().cast()).unwrap(),
        );
        let query: QueryFn = std::mem::transmute(
            GetProcAddress(xgr_h, c"QueryApiImpl".as_ptr().cast()).unwrap(),
        );
        let err_rep: ErrRepFn = std::mem::transmute(
            GetProcAddress(xgr_h, c"XErrorReport".as_ptr().cast()).unwrap(),
        );
        let uninit: UninitFn = std::mem::transmute(
            GetProcAddress(xgr_h, c"UninitializeApiImpl".as_ptr().cast()).unwrap(),
        );

        assert_eq!(init(26100, 7901, 0, std::ptr::null()), 0);
        let xsys_prov = Guid {
            d1: 0xe349_bd1a,
            d2: 0xfc20,
            d3: 0x4e40,
            d4: [0xb9, 0x9c, 0x41, 0x78, 0xcc, 0x6b, 0x40, 0x9f],
        };
        let xsys_iid = Guid {
            d1: 0x1861_cf2e,
            d2: 0xe18b,
            d3: 0x4834,
            d4: [0xa9, 0xf5, 0xb4, 0xa4, 0xe6, 0xef, 0xb4, 0xcf],
        };
        let mut sys_obj = std::ptr::null_mut();
        assert_eq!(query(&xsys_prov, &xsys_iid, &mut sys_obj), 0);
        assert!(!sys_obj.is_null());

        assert_eq!(err_rep(-1, c"integration smoke".as_ptr()), 0);
        assert!(tmp_appdata.path().join("xerror_report.log").exists());
        assert_eq!(uninit(), 0);
        FreeLibrary(xgr_h);
    }
}

#[test]
fn cli_end_to_end_patches_synthetic_pe_into_out_dir() {
    let dll_dir = find_built_dll_dir();
    let out_dir = stage_shims_to_out(&dll_dir);
    let xmem_info = analyze_file(&out_dir.join("xmem_pc.dll")).unwrap();
    assert_eq!(xmem_info.subsystem, subsystem::WINDOWS_GUI);

    // 1) xcrd_pc.dll DStorageGetFactory
    let xcrd_h = load_dll(&out_dir, "xcrd_pc.dll");
    #[repr(C)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }
    let iid_factory = Guid {
        d1: 0x6295_9D11,
        d2: 0xD45F,
        d3: 0x4884,
        d4: [0xA0, 0xA3, 0xF7, 0x86, 0x2E, 0xA2, 0x43, 0xAE],
    };
    type GetFactoryFn = unsafe extern "system" fn(*const Guid, *mut *mut c_void) -> i32;
    unsafe {
        let get_factory: GetFactoryFn =
            std::mem::transmute(GetProcAddress(xcrd_h, c"DStorageGetFactory".as_ptr().cast()).unwrap());
        let mut fac = std::ptr::null_mut();
        assert_eq!(get_factory(&iid_factory, &mut fac), 0);
        assert!(!fac.is_null());
        FreeLibrary(xcrd_h);
    }

    // 2) gi_pc.dll #1 ordinal GameInputCreate + COM QI
    let gi_h = load_dll(&out_dir, "gi_pc.dll");
    type GiCreateFn = unsafe extern "system" fn(*mut *mut c_void) -> i32;
    type RelFn = unsafe extern "system" fn(*mut c_void) -> u32;
    unsafe {
        let gi_create: GiCreateFn = std::mem::transmute(
            GetProcAddress(gi_h, std::ptr::without_provenance::<u8>(1)).unwrap(),
        );
        let mut gi = std::ptr::null_mut();
        assert_eq!(gi_create(&mut gi), 0);
        assert!(!gi.is_null());
        let vtbl = *gi.cast::<*const *const c_void>();
        let rel: RelFn = std::mem::transmute(*vtbl.add(2));
        assert_eq!(rel(gi), 0);
        FreeLibrary(gi_h);
    }

    // 3) audio_pc.dll ApuCreateHeap + ApuAlloc + ApuMapVirtualAddress + ApuFree
    let aud_h = load_dll(&out_dir, "audio_pc.dll");
    type ApuCreateFn = unsafe extern "system" fn(u32, u32) -> i32;
    type ApuAllocFn = unsafe extern "system" fn(*mut *mut c_void, *mut u32, u32, u32) -> i32;
    type ApuMapFn = unsafe extern "system" fn(*const c_void) -> u32;
    type ApuFreeFn = unsafe extern "system" fn(*mut c_void) -> i32;
    unsafe {
        let create: ApuCreateFn =
            std::mem::transmute(GetProcAddress(aud_h, c"ApuCreateHeap".as_ptr().cast()).unwrap());
        let alloc: ApuAllocFn =
            std::mem::transmute(GetProcAddress(aud_h, c"ApuAlloc".as_ptr().cast()).unwrap());
        let map: ApuMapFn =
            std::mem::transmute(GetProcAddress(aud_h, c"ApuMapVirtualAddress".as_ptr().cast()).unwrap());
        let free: ApuFreeFn =
            std::mem::transmute(GetProcAddress(aud_h, c"ApuFree".as_ptr().cast()).unwrap());
        assert_eq!(create(0, 0), 0);
        let mut va = std::ptr::null_mut();
        let mut apu = 0u32;
        assert_eq!(alloc(&mut va, &mut apu, 4096, 64), 0);
        assert!(!va.is_null() && apu != 0);
        assert_eq!(map(va), apu);
        assert_eq!(free(va), 0);
        FreeLibrary(aud_h);
    }

    // 4) Run pe_native_patcher.exe --dry-run against real game_scarlett_master.exe
    let cli_exe = dll_dir.join("pe_native_patcher.exe");
    assert!(cli_exe.exists(), "missing pe_native_patcher.exe at {}", cli_exe.display());
    if Path::new(REAL_EXE_PATH).exists() {
        let out = std::process::Command::new(&cli_exe)
            .args(["patch", "--input", REAL_EXE_PATH, "--dry-run"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "pe_native_patcher CLI failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("\"integrity_verified\": true"));
        assert!(stdout.contains("\"total_remapped_imports\": 110"));
    }
}
