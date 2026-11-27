//! `gta6_native_renderer` — **LUCIAS PROJECT** Native Win32 PC D3D12 Memory Model,
//! DXR 1.1 BVH Bridge, XG Surface Mapper, and `.text` Signature Verifier
//! for `game_scarlett_master.exe` (`LuciasProject.exe`).

pub const PROJECT_NAME: &str = "LUCIAS PROJECT";
pub const PROJECT_HARDWARE_BANNER: &str = "RTX 3070 8GB | R9 5900X | 16GB DDR4";

pub mod bvh_dxr_bridge;
pub mod memory_bridge;
pub mod sig_scanner;
pub mod uma_audit;
pub mod xg_surface_mapper;

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use crate::bvh_dxr_bridge::{
        build_flags, estimate_pc_dxr_prebuild, translate_batched_builds, BvhTranslateError,
        D3D12XboxBuildRtBatchedDesc2, D3D12XboxXdxrStreamDesc, RtAsType,
    };
    use crate::memory_bridge::{
        AllocError, DefaultVramResidencyManager, HardwareProfile, PcHeapPlacement, ResourceKind,
        ScarlettVirtualMemoryConfig, ScarlettVmTranslator, UploadRingAllocator, GIB, KIB, MIB,
    };
    use crate::sig_scanner::{
        verify_manifest_on_file, verify_manifest_read_only, BytePattern, Pe64Summary,
        SignatureManifestEntry, SCARLETT_MANIFEST,
    };
    use crate::uma_audit::{constants, UmaDependencyKind, UMA_AUDIT_CATALOG};
    use crate::xg_surface_mapper::{
        compute_pc_placed_footprint, detile_2d_thin_s_to_pc_footprint, map_xbox_to_pc_resource_desc,
        rdna2_thin_s_offset, suggest_swizzle_mode, PcTextureLayout, XboxResourceDesc,
        XgSwizzleMode, DIM_TEXTURE1D, DIM_TEXTURE2D, FLAG_ALLOW_DEPTH_STENCIL,
        FLAG_ALLOW_RENDER_TARGET,
    };

    #[test]
    fn uma_catalog_covers_all_six_scarlett_categories() {
        let required = [
            UmaDependencyKind::WriteWatchDirtyTracking,
            UmaDependencyKind::CpuShadowMirroring,
            UmaDependencyKind::VirtualMemoryAndPhysicalPages,
            UmaDependencyKind::XgTextureSwizzleLayout,
            UmaDependencyKind::XboxBvhBuilderAndRaytracing,
            UmaDependencyKind::Rdna2ToDxilShaderTraps,
        ];
        for kind in required {
            assert!(
                UMA_AUDIT_CATALOG.iter().any(|e| e.kind == kind),
                "missing audit entry for {kind:?}"
            );
        }
        assert_eq!(constants::XBOX_BVH_BATCH_DESC2_STRIDE, 0x50);
        assert_eq!(constants::XBOX_BVH_MAX_BATCH_SIZE, 16);
        assert_eq!(constants::XMEM_RESERVE_64K_PAGES, 0x2040_2000);
    }

    #[test]
    fn byte_pattern_parser_and_synthetic_pe64_scanner() {
        let pat = BytePattern::parse("48 83 EC 20 ?? ?? FF 15 ?? ?? ?? ??").unwrap();
        let hay = [0x90, 0x48, 0x83, 0xEC, 0x20, 0xAA, 0xBB, 0xFF, 0x15, 1, 2, 3, 4, 0xC3];
        let hits = pat.scan_all(&hay, 0x1000);
        assert_eq!(hits, vec![0x1001]);

        // Build minimal synthetic PE32+ image with 1 `.text` section at RVA 0x1000, raw 0x200.
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x80 + 6..0x80 + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        pe[0x80 + 20..0x80 + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // OptionalHeader size
        let opt = 0x80 + 24;
        pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EP
        pe[opt + 24..opt + 32].copy_from_slice(&0x0001_4000_0000_u64.to_le_bytes()); // ImageBase
        let sec = opt + 0xF0;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // Place `48 83 EC 20 E8 <disp32 to 0x1100>` at RVA 0x1010 (raw 0x210):
        // call at 0x1014 -> next IP 0x1019 -> target 0x1100 => disp32 = 0xE7.
        pe[0x210..0x215].copy_from_slice(&[0x48, 0x83, 0xEC, 0x20, 0xE8]);
        pe[0x215..0x219].copy_from_slice(&0xE7i32.to_le_bytes());

        let mut cursor = Cursor::new(pe.as_slice());
        let summary = Pe64Summary::parse(&mut cursor).unwrap();
        assert_eq!(summary.image_base, 0x0001_4000_0000);
        assert_eq!(summary.rva_to_file_offset(0x1010), Some(0x210));

        let manifest = [SignatureManifestEntry {
            id: "SYNTH_CALL",
            dll: "test.dll",
            symbol: "TestCall",
            iat_rva: 0x2000,
            thunk_rva: Some(0x1100),
            site_rva: 0x1010,
            call_rva: 0x1014,
            pattern: "48 83 EC 20 E8 ?? ?? ?? ??",
            notes: "synthetic check",
        }];
        let reports = verify_manifest_read_only(&mut cursor, &manifest).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].matched_at_rva);
        assert!(reports[0].call_rel32_verified);
    }

    #[test]
    fn scarlett_exe_manifest_verifies_100_percent_read_only() {
        let exe_path = Path::new(r"S:\gta\Gta6fordevelopersacces\game_scarlett_master.exe");
        if !exe_path.exists() {
            // Allow portable CI when S:\ is unmounted; on this machine S:\ is mounted and must run.
            return;
        }
        let reports = verify_manifest_on_file(exe_path).expect("PE verification failed");
        assert_eq!(reports.len(), SCARLETT_MANIFEST.len());
        for rep in &reports {
            assert!(
                rep.matched_at_rva,
                "signature mismatch at RVA {:#x} for {}",
                rep.site_rva, rep.id
            );
            assert!(
                rep.call_rel32_verified,
                "call target mismatch for {} at RVA {:#x}",
                rep.id, rep.site_rva
            );
        }

        // Also verify IID_ID3D12Device11 in .rdata at RVA 0x61e0638 read-only.
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(exe_path).unwrap();
        let summary = Pe64Summary::parse(&mut f).unwrap();
        let iid_off = summary.rva_to_file_offset(0x61e0638).unwrap();
        f.seek(SeekFrom::Start(iid_off)).unwrap();
        let mut iid = [0u8; 16];
        f.read_exact(&mut iid).unwrap();
        assert_eq!(iid, constants::IID_ID3D12_DEVICE_11);
    }

    #[test]
    fn scarlett_vm_and_xmem_map_to_explicit_pc_heaps_without_writewatch() {
        let mut cfg = ScarlettVirtualMemoryConfig::default();
        ScarlettVmTranslator::configure_virtual_memory(&mut cfg);
        assert_eq!(cfg.lowest_gpu_va, 0x1_0000);
        assert_eq!(cfg.highest_gpu_va, 0x7FFF_FFFE_FFFF);

        // Verified at 0x1e1cff5 (flags=0x21, kind=0x20402000, protect=0x4)
        assert_eq!(
            ScarlettVmTranslator::classify_xmem_alloc(0x2040_2000, 0x21, 0x04),
            PcHeapPlacement::AliasablePlacedHeap {
                granularity_bytes: 64 * KIB
            }
        );
        // Verified at 0x1e1d031 (flags=0x03, kind=0x20402000, protect=0x801)
        assert_eq!(
            ScarlettVmTranslator::classify_xmem_alloc(0x2040_2000, 0x03, 0x801),
            PcHeapPlacement::AliasablePlacedHeap {
                granularity_bytes: 64 * KIB
            }
        );
        // Committed GPU-visible 2M allocation -> DefaultVram(2 MiB)
        assert_eq!(
            ScarlettVmTranslator::classify_xmem_alloc(0x2000_1000, 0x03, 0x804),
            PcHeapPlacement::DefaultVram {
                page_alignment: 2 * MIB
            }
        );
        // Write-combined -> UploadRing
        assert_eq!(
            ScarlettVmTranslator::classify_xmem_alloc(0x1000, 0x03, 0x404),
            PcHeapPlacement::UploadRing
        );
        // Pure CPU system memory
        assert_eq!(
            ScarlettVmTranslator::classify_xmem_alloc(0x1000, 0x00, 0x04),
            PcHeapPlacement::CpuSystemOnly
        );
    }

    #[test]
    fn upload_ring_handles_alignment_wraparound_and_fence_retirement() {
        let mut ring = UploadRingAllocator::new(MIB);
        let s1 = ring.allocate(400 * KIB, 256, 1).unwrap();
        assert_eq!(s1.offset, 0);
        let s2 = ring.allocate(400 * KIB, 512, 2).unwrap();
        assert_eq!(s2.offset, 400 * KIB);

        // Next 400 KiB doesn't fit in remaining 224 KiB and tail is still at 0.
        assert!(matches!(
            ring.allocate(400 * KIB, 256, 3),
            Err(AllocError::RingFull { .. })
        ));

        // Retire fence 1 -> tail advances to 400 KiB; 300 KiB wraps around cleanly to offset 0!
        ring.retire_fence(1);
        let s3 = ring.allocate(300 * KIB, 256, 3).unwrap();
        assert_eq!(s3.offset, 0);
        assert_eq!(s3.size, 300 * KIB);

        // Retire remaining fences -> full reset.
        ring.retire_fence(3);
        assert_eq!(ring.used_bytes(), 0);
        assert_eq!(ring.free_bytes(), MIB);
    }

    #[test]
    fn rtx3070_vram_residency_enforces_8gb_budget_with_lru_eviction() {
        let profile = HardwareProfile::rtx3070_16gb_ddr4();
        assert_eq!(profile.vram_physical_bytes, 8 * GIB);
        assert_eq!(profile.system_ram_bytes, 16 * GIB);
        assert_eq!(profile.vram_usable_budget_bytes, 7200 * MIB);

        let mut vram = DefaultVramResidencyManager::new(profile);
        // Pin 3000 MiB of render targets / BVHs in frame 1.
        let rt_pinned = vram
            .allocate(ResourceKind::RenderTargetOrDepth, 3000 * MIB, 4 * MIB, true, 1)
            .unwrap();
        // Stream 2000 MiB texture chunk at frame 2, and another 2000 MiB at frame 5.
        let tex_old = vram
            .allocate(ResourceKind::Texture2D, 2000 * MIB, 64 * KIB, false, 2)
            .unwrap();
        let tex_newer = vram
            .allocate(ResourceKind::Texture2D, 2000 * MIB, 64 * KIB, false, 5)
            .unwrap();
        assert_eq!(vram.resident_bytes(), 7000 * MIB);

        // Frame 10 needs 1000 MiB -> exceeds 7200 MiB budget -> must evict `tex_old` (frame 2) first!
        let tex_new = vram
            .allocate(ResourceKind::Texture2D, 1000 * MIB, 64 * KIB, false, 10)
            .unwrap();
        assert!(!vram.get(tex_old).unwrap().resident);
        assert!(vram.get(tex_newer).unwrap().resident);
        assert!(vram.get(rt_pinned).unwrap().resident);
        assert!(vram.get(tex_new).unwrap().resident);
        assert_eq!(vram.evictions_total(), 1);
        assert_eq!(vram.resident_bytes(), 6000 * MIB);

        // Touching evicted `tex_old` in frame 11 makes it resident again (evicting `tex_newer` if needed).
        vram.free(tex_new).unwrap();
        let brought_back = vram.touch(tex_old, 11).unwrap();
        assert!(brought_back);
        assert!(vram.get(tex_old).unwrap().resident);

        // Requesting 5000 MiB when 3000 MiB is pinned in frame 11 + 2000 MiB used in frame 11 -> OOM budget error.
        let err = vram.allocate(ResourceKind::Buffer, 5000 * MIB, 64 * KIB, false, 11);
        assert!(matches!(err, Err(AllocError::OutOfVramBudget { .. })));
    }

    #[test]
    fn xbox_bvh_batched_translator_enforces_limits_and_cleans_xbox_flags() {
        // 1. Valid BLAS build where GTA VI sets Xbox stream bit 5 (0x20) with source_va == 0
        //    and requests 1 PostbuildInfoDesc (COMPACTED_SIZE).
        let desc_blas = D3D12XboxBuildRtBatchedDesc2 {
            dest_acceleration_structure_data: 0x1_0000_0000,
            inputs_ty: 1,
            inputs_flags: build_flags::PREFER_FAST_TRACE | build_flags::PERFORM_UPDATE,
            num_descs: 4,
            descs_layout: 0,
            descs_ptr: 0x2_0000_0000,
            source_acceleration_structure_data: 0,
            scratch_acceleration_structure_data: 0x3_0000_0000,
            num_postbuild_info_descs: 1,
            _pad34: 0,
            postbuild_info_descs: 0x4_0000_0000,
            _xbox_reserved: [0, 0],
        };
        // 2. Valid TLAS in-place update with source_va != 0 keeps PERFORM_UPDATE.
        let desc_tlas_upd = D3D12XboxBuildRtBatchedDesc2 {
            dest_acceleration_structure_data: 0x5_0000_0100,
            inputs_ty: 0,
            inputs_flags: build_flags::ALLOW_UPDATE | build_flags::PERFORM_UPDATE,
            num_descs: 256,
            descs_layout: 0,
            descs_ptr: 0x6_0000_0000,
            source_acceleration_structure_data: 0x5_0000_0100,
            scratch_acceleration_structure_data: 0x7_0000_0200,
            num_postbuild_info_descs: 0,
            _pad34: 0,
            postbuild_info_descs: 0,
            _xbox_reserved: [0, 0],
        };

        let calls = translate_batched_builds(&[desc_blas, desc_tlas_upd]).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].as_type, RtAsType::BottomLevel);
        assert_eq!(
            calls[0].pc_flags,
            build_flags::PREFER_FAST_TRACE | build_flags::ALLOW_COMPACTION
        );
        assert!(calls[0].emit_compacted_size_query);

        assert_eq!(calls[1].as_type, RtAsType::TopLevel);
        assert_eq!(
            calls[1].pc_flags,
            build_flags::ALLOW_UPDATE | build_flags::PERFORM_UPDATE
        );
        assert!(!calls[1].emit_compacted_size_query);

        // Reject >16 batch entries.
        let too_many = vec![desc_blas; 17];
        assert_eq!(
            translate_batched_builds(&too_many),
            Err(BvhTranslateError::BatchTooLarge { count: 17, max: 16 })
        );

        // Reject unaligned scratch address.
        let mut bad_align = desc_blas;
        bad_align.scratch_acceleration_structure_data = 0x3_0000_0080;
        assert_eq!(
            translate_batched_builds(&[bad_align]),
            Err(BvhTranslateError::UnalignedAddress {
                field: "scratch_acceleration_structure_data",
                addr: 0x3_0000_0080
            })
        );

        // Prebuild estimate uses XDXR stream max_node_count and 256B alignment.
        let stream = D3D12XboxXdxrStreamDesc {
            serialized_size_bytes: 64 * KIB,
            flags: 0,
            max_node_count: 1000,
            min_vertex_count: 3000,
        };
        let info = estimate_pc_dxr_prebuild(
            RtAsType::BottomLevel,
            1,
            build_flags::ALLOW_UPDATE | build_flags::MINIMIZE_MEMORY,
            Some(&stream),
        );
        assert_eq!(info.result_data_max_size_in_bytes % 256, 0);
        assert_eq!(info.scratch_data_size_in_bytes % 256, 0);
        assert!(info.update_scratch_data_size_in_bytes > 0);
    }

    #[test]
    fn xg_surface_mapper_and_rdna2_detiler_produce_valid_pc_footprints() {
        let rt_desc = XboxResourceDesc {
            dimension: DIM_TEXTURE2D,
            alignment: 0,
            width: 1920,
            height: 1080,
            depth_or_array: 1,
            mip_levels: 1,
            format: 119, // Xbox D16_UNORM_S8_UINT -> PC D24_UNORM_S8_UINT (46)
            sample_count: 1,
            sample_quality: 0,
            layout: 0,
            flags: FLAG_ALLOW_DEPTH_STENCIL,
        };
        assert_eq!(suggest_swizzle_mode(&rt_desc), XgSwizzleMode::Sw64KBZX);
        let pc_rt = map_xbox_to_pc_resource_desc(&rt_desc, false).unwrap();
        assert_eq!(pc_rt.pc_dxgi_format, 46);
        assert_eq!(pc_rt.layout, PcTextureLayout::Unknown);
        assert_eq!(pc_rt.alignment, 64 * 1024);

        let tex1d = XboxResourceDesc {
            dimension: DIM_TEXTURE1D,
            width: 256,
            height: 1,
            depth_or_array: 1,
            mip_levels: 1,
            format: 28,
            ..Default::default()
        };
        assert_eq!(suggest_swizzle_mode(&tex1d), XgSwizzleMode::Linear);

        let bc7_desc = XboxResourceDesc {
            dimension: DIM_TEXTURE2D,
            alignment: 0,
            width: 64,
            height: 64,
            depth_or_array: 1,
            mip_levels: 1,
            format: 98, // BC7_UNORM (16 bytes per 4x4 block => 16x16 elements)
            sample_count: 1,
            sample_quality: 0,
            layout: 0x100 | 5, // SW_4KB_S
            flags: FLAG_ALLOW_RENDER_TARGET,
        };
        let pc_bc7 = map_xbox_to_pc_resource_desc(&bc7_desc, false).unwrap();
        let fp = compute_pc_placed_footprint(&pc_bc7, 0, 100).unwrap();
        // 16 elements * 16 bytes = 256 bytes row pitch; offset 100 rounds up to 512!
        assert_eq!(fp.offset, 512);
        assert_eq!(fp.row_pitch, 256);
        assert_eq!(fp.total_bytes, 256 * 16);

        // Detile test: place unique bytes per element in SW_4KB_S (16x16 elements of 16 bytes = 4096B)
        let mut tiled = vec![0u8; 4096];
        for y in 0..16u32 {
            for x in 0..16u32 {
                let off = rdna2_thin_s_offset(x, y, 16, 12).unwrap();
                tiled[off] = (y * 16 + x) as u8;
                tiled[off + 15] = (x ^ y) as u8;
            }
        }
        let linear = detile_2d_thin_s_to_pc_footprint(
            &tiled,
            16,
            16,
            16,
            XgSwizzleMode::Sw4KBS,
            fp.row_pitch,
        )
        .unwrap();
        for y in 0..16u32 {
            for x in 0..16u32 {
                let row_off = (y * fp.row_pitch + x * 16) as usize;
                assert_eq!(linear[row_off], (y * 16 + x) as u8);
                assert_eq!(linear[row_off + 15], (x ^ y) as u8);
            }
        }
    }

    #[test]
    fn lucias_project_branding_and_profile_labels() {
        let profile = HardwareProfile::rtx3070_16gb_ddr4();
        assert_eq!(crate::PROJECT_NAME, "LUCIAS PROJECT");
        assert_eq!(crate::PROJECT_HARDWARE_BANNER, "RTX 3070 8GB | R9 5900X | 16GB DDR4");
        assert_eq!(
            profile.label(),
            "LUCIAS PROJECT | RTX 3070 8GB | R9 5900X | 16GB DDR4"
        );
    }
}
