//! **LUCIAS PROJECT** — `XboxBvhBuilder.dll` -> PC DXR 1.1 BLAS / TLAS parameter translator.
//!
//! Verified against `game_scarlett_master.exe` call-sites:
//! - `BuildRaytracingAccelerationStructureBatched2X` (`0xfe4fec`, `0x24902ac`):
//!   `D3D12XBOX_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_BATCHED_DESC2` has an exact
//!   `0x50` (80-byte) stride (`lea rax, [rax+rax*4]; shl rax, 4`) and a 16-entry
//!   batch cap (`cmp ebx, 0xf`), with 256-byte aligned destination and scratch buffers.
//! - `RehydrateRaytracingAccelerationStructureBatched2X` (`0xea6d5a`) also caps at 16
//!   (`cmp r8d, 0x10`).
//! - `GetRaytracingAccelerationStructurePrebuildInfo` (`0x7595c`, `0x4ee2b31`, `0x56ac171`)
//!   returns the 24-byte `D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO`.

pub const XBOX_BVH_ALIGN: u64 = 256;
pub const XBOX_BVH_MAX_BATCH: usize = 16;

/// `D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE`
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtAsType {
    TopLevel = 0,
    BottomLevel = 1,
}

/// `D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAGS` (standard PC bits 0..=4)
/// plus Xbox Scarlett bit 5 (`0x20`) observed at RVA `0xfe50e6..0xfe50fd`.
pub mod build_flags {
    pub const NONE: u32 = 0;
    pub const ALLOW_UPDATE: u32 = 1 << 0;
    pub const ALLOW_COMPACTION: u32 = 1 << 1;
    pub const PREFER_FAST_TRACE: u32 = 1 << 2;
    pub const PREFER_FAST_BUILD: u32 = 1 << 3;
    pub const MINIMIZE_MEMORY: u32 = 1 << 4;
    pub const PERFORM_UPDATE: u32 = 1 << 5; // On Xbox, OR'd with (stream_flag << 5) at 0xfe50e6!
    pub const PC_STANDARD_MASK: u32 =
        ALLOW_UPDATE | ALLOW_COMPACTION | PREFER_FAST_TRACE | PREFER_FAST_BUILD | MINIMIZE_MEMORY;
}

/// `D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS` (32 bytes on Win64).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12RaytracingInputs {
    pub ty: u32,
    pub flags: u32,
    pub num_descs: u32,
    pub descs_layout: u32,
    /// Union: `pGeometryDescs` (array of pointers or structs) or `InstanceDescs` GPU VA.
    pub descs_ptr: u64,
    pub _pad: u64, // aligns struct to 32 bytes; matches `[r14]` xmm0 + `[r14+0x10]` load at 0xfe50c3..0xfe50d5
}

/// `D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC` (16 bytes, `0x10` stride at `0xfe5126`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12PostbuildInfoDesc {
    pub dest_buffer: u64,
    pub info_type: u32,
    pub _pad: u32,
}
const _: () = assert!(std::mem::size_of::<D3D12PostbuildInfoDesc>() == 0x10);

/// Exact `0x50`-byte (80-byte) Xbox batched build descriptor observed at `0xfe509c..0xfe5179`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12XboxBuildRtBatchedDesc2 {
    pub dest_acceleration_structure_data: u64,    // +0x00
    pub inputs_ty: u32,                           // +0x08
    pub inputs_flags: u32,                        // +0x0c (OR'd with r9d<<5 at 0xfe50fd)
    pub num_descs: u32,                           // +0x10
    pub descs_layout: u32,                        // +0x14
    pub descs_ptr: u64,                           // +0x18
    pub source_acceleration_structure_data: u64,  // +0x20
    pub scratch_acceleration_structure_data: u64, // +0x28
    pub num_postbuild_info_descs: u32,            // +0x30
    pub _pad34: u32,                              // +0x34
    pub postbuild_info_descs: u64,                // +0x38
    pub _xbox_reserved: [u64; 2],                 // +0x40..0x50 (zeroed via vmovups [r12+rax+0x30])
}
const _: () = assert!(std::mem::size_of::<D3D12XboxBuildRtBatchedDesc2>() == 0x50);

/// `D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO` (24 bytes, zeroed at `0x75953..0x75958`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12RaytracingPrebuildInfo {
    pub result_data_max_size_in_bytes: u64,
    pub scratch_data_size_in_bytes: u64,
    pub update_scratch_data_size_in_bytes: u64,
}
const _: () = assert!(std::mem::size_of::<D3D12RaytracingPrebuildInfo>() == 0x18);

/// `D3D12XBOX_XDXR_STREAM_DESC` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3D12XboxXdxrStreamDesc {
    pub serialized_size_bytes: u64,
    pub flags: u32,
    pub max_node_count: u32,
    pub min_vertex_count: u64,
}

/// Translated standard PC DXR 1.1 `ID3D12GraphicsCommandList4::BuildRaytracingAccelerationStructure` call.
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
    MissingUpdateSource,
}

/// Translates a batch of `D3D12XboxBuildRtBatchedDesc2` into PC DXR 1.1 build descriptors.
///
/// Rules enforced:
/// - Rejects batches > 16 entries (matching Scarlett `cmp ebx, 0xf` limit).
/// - Validates 256-byte alignment on non-zero `dest`, `source`, `scratch` GPU VAs.
/// - Strips Xbox-only stream/rehydration bit 5 (`0x20`) unless `source_va != 0` (real `PERFORM_UPDATE`),
///   preventing invalid-flag DX12 debug-layer errors on RTX 3070!
/// - Preserves `ALLOW_COMPACTION` and postbuild `COMPACTED_SIZE` queries.
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
        } else if (desc.inputs_flags & build_flags::PERFORM_UPDATE) != 0 {
            // At 0xfe50e6, GTA VI sets bit 5 (0x20) via `shl r10d, 5` even when source_va == 0
            // (rehydration/compaction signal on Xbox, NOT a DXR 1.1 PERFORM_UPDATE).
            // Strip bit 5 when source_va == 0, and enable ALLOW_COMPACTION if postbuild info is requested.
            if desc.num_postbuild_info_descs > 0 {
                pc_flags |= build_flags::ALLOW_COMPACTION;
            }
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

/// Estimates PC DXR 1.1 BLAS/TLAS prebuild sizes for RTX 3070 (Ampere RT Core Gen2)
/// given `XboxBvhBuilder::GetRaytracingAccelerationStructurePrebuildInfo` inputs.
/// Conservative 64-byte-per-triangle / 64-byte-per-instance upper bound aligned to 256 bytes,
/// used when intercepting dehydrated `XDXR` stream queries (`0x7595c`).
pub fn estimate_pc_dxr_prebuild(
    as_type: RtAsType,
    num_descs: u32,
    flags: u32,
    stream: Option<&D3D12XboxXdxrStreamDesc>,
) -> D3D12RaytracingPrebuildInfo {
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

    D3D12RaytracingPrebuildInfo {
        result_data_max_size_in_bytes: result_bytes,
        scratch_data_size_in_bytes: scratch_bytes,
        update_scratch_data_size_in_bytes: update_scratch,
    }
}
