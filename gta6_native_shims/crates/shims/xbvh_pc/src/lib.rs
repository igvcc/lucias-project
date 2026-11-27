#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use shim_common::{E_INVALIDARG, HRESULT, S_OK};

pub const XBOX_BVH_ALIGN: u64 = 256;
pub const XBOX_BVH_MAX_BATCH: usize = 16;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtAsType {
    TopLevel = 0,
    BottomLevel = 1,
}

pub mod build_flags {
    pub const NONE: u32 = 0;
    pub const ALLOW_UPDATE: u32 = 1 << 0;
    pub const ALLOW_COMPACTION: u32 = 1 << 1;
    pub const PREFER_FAST_TRACE: u32 = 1 << 2;
    pub const PREFER_FAST_BUILD: u32 = 1 << 3;
    pub const MINIMIZE_MEMORY: u32 = 1 << 4;
    pub const PERFORM_UPDATE: u32 = 1 << 5;
    pub const PC_STANDARD_MASK: u32 =
        ALLOW_UPDATE | ALLOW_COMPACTION | PREFER_FAST_TRACE | PREFER_FAST_BUILD | MINIMIZE_MEMORY;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12RaytracingInputs {
    pub ty: u32,
    pub flags: u32,
    pub num_descs: u32,
    pub descs_layout: u32,
    pub descs_ptr: u64,
    pub _pad: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12PostbuildInfoDesc {
    pub dest_buffer: u64,
    pub info_type: u32,
    pub _pad: u32,
}
const _: () = assert!(size_of::<D3D12PostbuildInfoDesc>() == 0x10);

/// Exact `0x50`-byte Xbox batched build descriptor.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12XboxBuildRtBatchedDesc2 {
    pub dest_acceleration_structure_data: u64,    // +0x00
    pub inputs_ty: u32,                           // +0x08
    pub inputs_flags: u32,                        // +0x0c
    pub num_descs: u32,                           // +0x10
    pub descs_layout: u32,                        // +0x14
    pub descs_ptr: u64,                           // +0x18
    pub source_acceleration_structure_data: u64,  // +0x20
    pub scratch_acceleration_structure_data: u64, // +0x28
    pub num_postbuild_info_descs: u32,            // +0x30
    pub _pad34: u32,                              // +0x34
    pub postbuild_info_descs: u64,                // +0x38
    pub _xbox_reserved: [u64; 2],                 // +0x40..0x50
}
const _: () = assert!(size_of::<D3D12XboxBuildRtBatchedDesc2>() == 0x50);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrebuildInfo {
    pub result_data_max_size_in_bytes: u64,
    pub scratch_data_size_in_bytes: u64,
    pub update_scratch_data_size_in_bytes: u64,
}
const _: () = assert!(size_of::<PrebuildInfo>() == 0x18);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12XboxXdxrStreamDesc {
    pub serialized_size_bytes: u64,
    pub flags: u32,
    pub max_node_count: u32,
    pub min_vertex_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcDxrBuildCall {
    pub as_type: RtAsType,
    pub dest_va: u64,
    pub source_va: u64,
    pub scratch_va: u64,
    pub pc_flags: u32,
    pub num_descs: u32,
    pub descs_layout: u32,
    pub descs_ptr: u64,
    pub emit_compacted_size_query: bool,
    pub postbuild_info_count: u32,
    pub postbuild_info_ptr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BvhTranslateError {
    BatchTooLarge { count: usize, max: usize },
    UnalignedAddress { field: &'static str, addr: u64 },
    InvalidAsType(u32),
}

pub fn translate_batched_builds(
    batch: &[D3D12XboxBuildRtBatchedDesc2],
) -> Result<Vec<PcDxrBuildCall>, BvhTranslateError> {
    if batch.len() > XBOX_BVH_MAX_BATCH {
        return Err(BvhTranslateError::BatchTooLarge {
            count: batch.len(),
            max: XBOX_BVH_MAX_BATCH,
        });
    }

    let mut out = Vec::with_capacity(batch.len());
    for desc in batch {
        if desc.dest_acceleration_structure_data % XBOX_BVH_ALIGN != 0 {
            return Err(BvhTranslateError::UnalignedAddress {
                field: "dest_acceleration_structure_data",
                addr: desc.dest_acceleration_structure_data,
            });
        }
        if desc.scratch_acceleration_structure_data % XBOX_BVH_ALIGN != 0 {
            return Err(BvhTranslateError::UnalignedAddress {
                field: "scratch_acceleration_structure_data",
                addr: desc.scratch_acceleration_structure_data,
            });
        }
        if desc.source_acceleration_structure_data != 0
            && desc.source_acceleration_structure_data % XBOX_BVH_ALIGN != 0
        {
            return Err(BvhTranslateError::UnalignedAddress {
                field: "source_acceleration_structure_data",
                addr: desc.source_acceleration_structure_data,
            });
        }

        let as_type = match desc.inputs_ty {
            0 => RtAsType::TopLevel,
            1 => RtAsType::BottomLevel,
            other => return Err(BvhTranslateError::InvalidAsType(other)),
        };

        let mut pc_flags = desc.inputs_flags & build_flags::PC_STANDARD_MASK;
        if desc.source_acceleration_structure_data != 0 {
            if (desc.inputs_flags & build_flags::PERFORM_UPDATE) != 0 {
                pc_flags |= build_flags::PERFORM_UPDATE;
            }
        } else if (desc.inputs_flags & build_flags::PERFORM_UPDATE) != 0
            && desc.num_postbuild_info_descs > 0
        {
            pc_flags |= build_flags::ALLOW_COMPACTION;
        }

        out.push(PcDxrBuildCall {
            as_type,
            dest_va: desc.dest_acceleration_structure_data,
            source_va: desc.source_acceleration_structure_data,
            scratch_va: desc.scratch_acceleration_structure_data,
            pc_flags,
            num_descs: desc.num_descs,
            descs_layout: desc.descs_layout,
            descs_ptr: desc.descs_ptr,
            emit_compacted_size_query: (pc_flags & build_flags::ALLOW_COMPACTION) != 0
                && desc.num_postbuild_info_descs > 0,
            postbuild_info_count: desc.num_postbuild_info_descs,
            postbuild_info_ptr: desc.postbuild_info_descs,
        });
    }
    Ok(out)
}

pub fn estimate_pc_dxr_prebuild(
    as_type: RtAsType,
    num_descs: u32,
    flags: u32,
    stream: Option<&D3D12XboxXdxrStreamDesc>,
) -> PrebuildInfo {
    let base_elements = match stream {
        Some(s) if s.max_node_count > 0 => u64::from(s.max_node_count),
        _ => u64::from(num_descs.max(1)),
    };
    let per_unit_result = match as_type {
        RtAsType::TopLevel => 128u64,
        RtAsType::BottomLevel => 96u64,
    };
    let fast_build = (flags & build_flags::PREFER_FAST_BUILD) != 0;
    let minimize = (flags & build_flags::MINIMIZE_MEMORY) != 0;
    let raw_result = base_elements * per_unit_result;
    let result_bytes = if minimize {
        (raw_result * 3 / 4).max(256)
    } else {
        raw_result.max(256)
    }
    .next_multiple_of(XBOX_BVH_ALIGN);

    let scratch_bytes = if fast_build {
        (result_bytes / 2).max(256)
    } else {
        result_bytes
    }
    .next_multiple_of(XBOX_BVH_ALIGN);

    let update_scratch = if (flags & build_flags::ALLOW_UPDATE) != 0 {
        (scratch_bytes / 4).max(256).next_multiple_of(XBOX_BVH_ALIGN)
    } else {
        0
    };

    PrebuildInfo {
        result_data_max_size_in_bytes: result_bytes,
        scratch_data_size_in_bytes: scratch_bytes,
        update_scratch_data_size_in_bytes: update_scratch,
    }
}

#[repr(C)]
pub struct XboxBvhBuilderState {
    pub device: *mut c_void,
    pub use_64bit_morton: u8,
    pub flag: u8,
    pub reserved: [u8; 6],
}

#[derive(Default)]
struct BvhSession {
    last_batch: Vec<PcDxrBuildCall>,
    copies: u64,
    rehydrates: u64,
}

static SESSIONS: LazyLock<Mutex<HashMap<usize, BvhSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TOTAL_TRANSLATED_BUILDS: AtomicU64 = AtomicU64::new(0);

pub fn total_translated_builds() -> u64 {
    TOTAL_TRANSLATED_BUILDS.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_ctor(
    this: *mut XboxBvhBuilderState,
    device: *mut c_void,
    flag: bool,
) -> *mut XboxBvhBuilderState {
    if !this.is_null() {
        unsafe {
            (*this).device = device;
            (*this).use_64bit_morton = 0;
            (*this).flag = flag as u8;
            (*this).reserved = [0; 6];
        }
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.insert(this as usize, BvhSession::default());
        shim_common::boot_trace("xbvh_pc", "XboxBvhBuilder::ctor", &format!("flag={flag}"));
    }
    this
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_dtor(this: *mut XboxBvhBuilderState) {
    if !this.is_null() {
        unsafe { (*this).device = std::ptr::null_mut() };
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.remove(&(this as usize));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_build_batched_2x(
    this: *mut XboxBvhBuilderState,
    _cmd_list: *mut c_void,
    num_descs: u32,
    descs: *const c_void,
) {
    if descs.is_null() || num_descs == 0 || (num_descs as usize) > XBOX_BVH_MAX_BATCH {
        return;
    }
    let slice = unsafe {
        std::slice::from_raw_parts(descs.cast::<D3D12XboxBuildRtBatchedDesc2>(), num_descs as usize)
    };
    if let Ok(calls) = translate_batched_builds(slice) {
        TOTAL_TRANSLATED_BUILDS.fetch_add(calls.len() as u64, Ordering::Relaxed);
        if !this.is_null() {
            let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
            sessions.entry(this as usize).or_default().last_batch = calls;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_copy_rtas(
    this: *mut XboxBvhBuilderState,
    _cmd_list: *mut c_void,
    dest_va: u64,
    src_va: u64,
    _mode: u32,
) {
    if !dest_va.is_multiple_of(XBOX_BVH_ALIGN) || !src_va.is_multiple_of(XBOX_BVH_ALIGN) {
        return;
    }
    if !this.is_null() {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.entry(this as usize).or_default().copies += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_get_prebuild_info(
    _this: *mut XboxBvhBuilderState,
    inputs: *const c_void,
    stream_desc: *const c_void,
    info_out: *mut PrebuildInfo,
) {
    let Some(out) = (unsafe { info_out.as_mut() }) else {
        return;
    };
    let (as_type, num_descs, flags) = match unsafe { inputs.cast::<D3D12RaytracingInputs>().as_ref() } {
        Some(inp) => {
            let ty = if inp.ty == 0 {
                RtAsType::TopLevel
            } else {
                RtAsType::BottomLevel
            };
            (ty, inp.num_descs, inp.flags)
        }
        None => (RtAsType::BottomLevel, 1, 0),
    };
    let stream = unsafe { stream_desc.cast::<D3D12XboxXdxrStreamDesc>().as_ref() };
    *out = estimate_pc_dxr_prebuild(as_type, num_descs, flags, stream);
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_rehydrate_batched_2x(
    this: *mut XboxBvhBuilderState,
    _cmd_list: *mut c_void,
    num_descs: u32,
    _descs: *const c_void,
    gpu_vas: *const u64,
) -> HRESULT {
    if (num_descs as usize) > XBOX_BVH_MAX_BATCH {
        return E_INVALIDARG;
    }
    if num_descs > 0 && !gpu_vas.is_null() {
        let vas = unsafe { std::slice::from_raw_parts(gpu_vas, num_descs as usize) };
        if vas.iter().any(|&va| va % XBOX_BVH_ALIGN != 0) {
            return E_INVALIDARG;
        }
    }
    if !this.is_null() {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.entry(this as usize).or_default().rehydrates += u64::from(num_descs);
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn xbvh_set_64bit_morton_codes(this: *mut XboxBvhBuilderState, enabled: bool) {
    if !this.is_null() {
        unsafe { (*this).use_64bit_morton = enabled as u8 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_batched_descs_and_strips_xbox_bit5_without_source() {
        let desc = D3D12XboxBuildRtBatchedDesc2 {
            dest_acceleration_structure_data: 0x1000,
            inputs_ty: 1,
            inputs_flags: build_flags::ALLOW_COMPACTION | build_flags::PERFORM_UPDATE,
            num_descs: 4,
            descs_layout: 0,
            descs_ptr: 0x2000,
            source_acceleration_structure_data: 0,
            scratch_acceleration_structure_data: 0x3000,
            num_postbuild_info_descs: 1,
            _pad34: 0,
            postbuild_info_descs: 0x4000,
            _xbox_reserved: [0; 2],
        };
        let calls = translate_batched_builds(&[desc]).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].pc_flags & build_flags::PERFORM_UPDATE, 0);
        assert_ne!(calls[0].pc_flags & build_flags::ALLOW_COMPACTION, 0);
        assert!(calls[0].emit_compacted_size_query);
    }

    #[test]
    fn builder_lifecycle_and_prebuild_estimate_work() {
        let mut state = XboxBvhBuilderState {
            device: std::ptr::null_mut(),
            use_64bit_morton: 0,
            flag: 0,
            reserved: [0; 6],
        };
        xbvh_ctor(&mut state, std::ptr::null_mut(), true);
        xbvh_set_64bit_morton_codes(&mut state, true);
        assert_eq!(state.use_64bit_morton, 1);

        let inputs = D3D12RaytracingInputs {
            ty: 1,
            flags: build_flags::ALLOW_UPDATE,
            num_descs: 100,
            descs_layout: 0,
            descs_ptr: 0,
            _pad: 0,
        };
        let mut info = PrebuildInfo::default();
        xbvh_get_prebuild_info(
            &mut state,
            (&raw const inputs).cast(),
            std::ptr::null(),
            &mut info,
        );
        assert_eq!(info.result_data_max_size_in_bytes % 256, 0);
        assert!(info.result_data_max_size_in_bytes >= 9600);
        assert!(info.update_scratch_data_size_in_bytes >= 256);

        let desc = D3D12XboxBuildRtBatchedDesc2 {
            dest_acceleration_structure_data: 0x1000,
            inputs_ty: 1,
            inputs_flags: build_flags::PREFER_FAST_TRACE,
            num_descs: 10,
            scratch_acceleration_structure_data: 0x2000,
            ..Default::default()
        };
        let before = total_translated_builds();
        xbvh_build_batched_2x(&mut state, std::ptr::null_mut(), 1, (&raw const desc).cast());
        assert_eq!(total_translated_builds(), before + 1);
        assert_eq!(
            xbvh_rehydrate_batched_2x(&mut state, std::ptr::null_mut(), 1, std::ptr::null(), &0x1000),
            S_OK
        );
        xbvh_dtor(&mut state);
    }
}
