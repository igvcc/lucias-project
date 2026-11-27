use std::path::Path;

use gta6_native_tools::{dxpk, layout, media, rpf9, shader, ttpf};
use zlib_rs::{DeflateConfig, ReturnCode, compress_slice};

fn compress_zlib(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; zlib_rs::compress_bound(data.len()) + 32];
    let (out, rc) = compress_slice(&mut buf, data, DeflateConfig::new(6));
    assert_eq!(rc, ReturnCode::Ok);
    out.to_vec()
}

fn compress_raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; zlib_rs::compress_bound(data.len()) + 32];
    let cfg = DeflateConfig {
        window_bits: -15,
        ..DeflateConfig::new(6)
    };
    let (out, rc) = compress_slice(&mut buf, data, cfg);
    assert_eq!(rc, ReturnCode::Ok);
    out.to_vec()
}

#[test]
fn rpf9_header_and_stream_carver_classifies_entries() {
    let mut buf = vec![0u8; 0x100];
    buf[0..4].copy_from_slice(&rpf9::RPF9_MAGIC.to_le_bytes());
    buf[0x04..0x08].copy_from_slice(&0x360u32.to_le_bytes());
    buf[0x08..0x0C].copy_from_slice(&0x340u32.to_le_bytes());
    buf[0x0C..0x10].copy_from_slice(&0x40u32.to_le_bytes());
    buf[0x18..0x1C].copy_from_slice(&rpf9::EXPECTED_CONST_18.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&rpf9::EXPECTED_CONST_1C.to_le_bytes());
    buf[0x24..0x28].copy_from_slice(&42u32.to_le_bytes());
    buf[0x28..0x2C].copy_from_slice(&0xDA72_573Eu32.to_le_bytes());
    buf[0x2C..0x30].copy_from_slice(&0x0009_0F01u32.to_le_bytes());
    buf[0x30..0x34].copy_from_slice(&rpf9::EXPECTED_CONST_30.to_le_bytes());
    buf[0x40..0x60].copy_from_slice(&rpf9::RPF9_AES_CBC_PREAMBLE);

    let xml_z = compress_zlib(b"<CVehicleModelInfo><Name>TestCar</Name></CVehicleModelInfo>");
    let psin_z = compress_zlib(b"PSIN\x01\x00\x00\x00CHKS_DATA");
    let mut nav_payload = vec![0u8; 0xE0];
    nav_payload[0x14..0x18].copy_from_slice(&0x0001_0015u32.to_le_bytes());
    nav_payload[0xC4..0xC8].copy_from_slice(&123u32.to_le_bytes());
    nav_payload[0xC8..0xCC].copy_from_slice(&456u32.to_le_bytes());
    let nav_z = compress_zlib(&nav_payload);

    for stream in [xml_z, psin_z, nav_z] {
        buf.extend_from_slice(&stream);
        let pad = (16 - (buf.len() % 16)) % 16;
        buf.resize(buf.len() + pad, 0);
    }

    let hdr = rpf9::Rpf9Header::parse(&buf).unwrap();
    assert!(hdr.constants_match);
    assert!(hdr.toc_encrypted_aes_cbc);
    assert_eq!(hdr.entry_count, 42);
    assert_eq!(hdr.key_id, 0xDA72_573E);

    let report = rpf9::inventory_rpf9_slice(
        &buf,
        "common.rpf",
        Path::new("common.rpf"),
        buf.len() as u64,
        &hdr,
        10,
    );
    assert_eq!(report.carved_streams, 3);
    assert_eq!(report.class_counts.get("xml_meta"), Some(&1));
    assert_eq!(report.class_counts.get("scripts"), Some(&1));
    assert_eq!(report.class_counts.get("navmesh"), Some(&1));
}

#[test]
fn ttpf_zlib_texture_deswizzles_to_valid_dds_dx10() {
    // Construct a minimal synthetic RDS5 + ETPF archive with a 64x64 BC7_UNORM (DXGI 98) texture.
    let width = 64u32;
    let height = 64u32;
    let dxgi = 98u8; // BC7_UNORM, 16 bytes/block -> 16x16 blocks = 4096 bytes = 1 4KB-D tile
    let info = ttpf::dxgi_info(dxgi).unwrap();

    let mut tiled = vec![0u8; 4096];
    for (i, chunk) in tiled.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        chunk[0] = (i & 0xFF) as u8;
        chunk[15] = ((i >> 4) & 0xFF) as u8;
    }
    let compressed = compress_zlib(&tiled);

    // Header + chunk table + ETPF + 1 descriptor + 1 hash
    // Put ETPF at 0x100 (hdr_pages = 1)
    let etpf_offset = 0x100usize;
    let chunk_data_start = 0x200usize;
    let chunk_data_end = (chunk_data_start + compressed.len()).next_multiple_of(0x100);

    let mut file = vec![0u8; chunk_data_end];
    file[0..4].copy_from_slice(b"RDS5");
    file[4..8].copy_from_slice(&2u32.to_le_bytes()); // 2 chunk entries (dummy prefix + chunk 0)
    file[8..16].copy_from_slice(&4096u64.to_le_bytes());
    file[16..20].copy_from_slice(&1u32.to_le_bytes()); // hdr_pages = 1 -> 0x100

    // Chunk table entry 0: transitions from prev_c=0x100 to chunk_data_start (Raw/skip), next_codec = Zlib (8)
    let lo0 = ((chunk_data_start / 0x100) as u32) | (8u32 << 26);
    file[24..28].copy_from_slice(&lo0.to_le_bytes());
    file[28..32].copy_from_slice(&0u32.to_le_bytes());

    // Chunk table entry 1: ends at chunk_data_end, virt_end = 4096 (r=1, hi=0)
    let lo1 = ((chunk_data_end / 0x100) as u32) | (1u32 << 30);
    file[32..36].copy_from_slice(&lo1.to_le_bytes());
    file[36..40].copy_from_slice(&0u32.to_le_bytes());

    // ETPF at 0x100
    file[etpf_offset..etpf_offset + 4].copy_from_slice(b"ETPF");
    file[etpf_offset + 4..etpf_offset + 8].copy_from_slice(&1u32.to_le_bytes());
    file[etpf_offset + 8..etpf_offset + 12].copy_from_slice(&1u32.to_le_bytes()); // 1 texture
    // Descriptor: w-1 | ((h-1)<<14)
    let u0 = (width - 1) | ((height - 1) << 14);
    let u1 = u32::from(dxgi) << 3;
    let d_off = etpf_offset + 16;
    file[d_off..d_off + 4].copy_from_slice(&u0.to_le_bytes());
    file[d_off + 4..d_off + 8].copy_from_slice(&u1.to_le_bytes());
    // Hash
    file[d_off + 16..d_off + 24].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    // Compressed chunk payload
    file[chunk_data_start..chunk_data_start + compressed.len()].copy_from_slice(&compressed);

    let dir = tempfile::tempdir().unwrap();
    let ttpf_path = dir.path().join("test.ttpf");
    std::fs::write(&ttpf_path, &file).unwrap();

    let out_dir = dir.path().join("dds");
    let summary = ttpf::convert_ttpf_samples(&ttpf_path, &out_dir, 5).unwrap();
    assert_eq!(summary.exported_count, 1);
    assert_eq!(summary.failed_count, 0);

    let dds = std::fs::read(out_dir.join(&summary.items[0].file_name)).unwrap();
    assert_eq!(&dds[0..4], b"DDS ");
    assert_eq!(&dds[84..88], b"DX10");
    assert_eq!(
        u32::from_le_bytes(dds[128..132].try_into().unwrap()),
        u32::from(dxgi)
    );
    assert_eq!(dds.len(), 148 + ttpf::compute_mip_size(width, height, info));
}

#[test]
fn bink2_adat_and_riff_xma2_headers_parse_cleanly() {
    // 1. Synthetic Bink2 KB2j header
    let mut bk2 = vec![0u8; 64];
    bk2[0..4].copy_from_slice(b"KB2j");
    bk2[4..8].copy_from_slice(&4096u32.to_le_bytes());
    bk2[8..12].copy_from_slice(&900u32.to_le_bytes());
    bk2[12..16].copy_from_slice(&65536u32.to_le_bytes());
    bk2[16..20].copy_from_slice(&900u32.to_le_bytes());
    bk2[20..24].copy_from_slice(&1920u32.to_le_bytes());
    bk2[24..28].copy_from_slice(&1080u32.to_le_bytes());
    bk2[28..32].copy_from_slice(&30000u32.to_le_bytes());
    bk2[32..36].copy_from_slice(&1000u32.to_le_bytes());
    bk2[40..44].copy_from_slice(&1u32.to_le_bytes());

    let parsed_bk2 = media::parse_bink2_header(&bk2, 0, 100_000).unwrap();
    assert_eq!(parsed_bk2.width, 1920);
    assert_eq!(parsed_bk2.height, 1080);
    assert_eq!(parsed_bk2.fps, 30.0);
    assert_eq!(parsed_bk2.duration_sec, 30.0);

    // 2. Synthetic ADAT bank with 1 track + format chunk (48000 Hz)
    let mut adat = vec![0u8; 128];
    adat[0..4].copy_from_slice(b"ADAT");
    adat[4..8].copy_from_slice(&1u32.to_le_bytes()); // version 1
    adat[8..12].copy_from_slice(&1u32.to_le_bytes()); // 1 stream
    adat[12..16].copy_from_slice(&40u32.to_le_bytes()); // header_size = 40
    adat[16..20].copy_from_slice(&0xABCD_1234u32.to_le_bytes()); // stream_id
    // 0x55 data chunk at offset 64, size 32
    let data_entry: u64 = (0x55u64 << 56) | (32u64 << 28) | 64u64;
    adat[20..28].copy_from_slice(&data_entry.to_le_bytes());
    // 0x76 format chunk at offset 48, size 12
    let fmt_entry: u64 = (0x76u64 << 56) | (12u64 << 28) | 48u64;
    adat[28..36].copy_from_slice(&fmt_entry.to_le_bytes());
    adat[48 + 8..48 + 10].copy_from_slice(&48000u16.to_le_bytes());
    adat[64] = 0xFC; // Opus TOC stereo

    let bank = media::parse_adat_bank(&adat, 0).unwrap();
    assert_eq!(bank.tracks.len(), 1);
    assert_eq!(bank.tracks[0].sample_rate, 48000);
    assert_eq!(bank.tracks[0].codec, "Opus");

    // 3. Synthetic RIFF/WAVE XMA2 header + 1 2048-byte XMA2 packet
    let mut wav = vec![0u8; 44 + 2048];
    let riff_sz = (wav.len() - 8) as u32;
    wav[0..4].copy_from_slice(b"RIFF");
    wav[4..8].copy_from_slice(&riff_sz.to_le_bytes());
    wav[8..12].copy_from_slice(b"WAVE");
    wav[12..16].copy_from_slice(b"fmt ");
    wav[16..20].copy_from_slice(&16u32.to_le_bytes());
    wav[20..22].copy_from_slice(&0x0166u16.to_le_bytes()); // XMA2
    wav[22..24].copy_from_slice(&2u16.to_le_bytes());
    wav[24..28].copy_from_slice(&48000u32.to_le_bytes());
    wav[36..40].copy_from_slice(b"data");
    wav[40..44].copy_from_slice(&2048u32.to_le_bytes());

    let wem = media::parse_riff_wem(&wav, 0).unwrap();
    assert_eq!(wem.format_name, "XMA2");
    assert_eq!(wem.sample_rate, 48000);
    assert_eq!(wem.xma2_packets_probed, 1);
}

#[test]
fn sgd5_record_parser_rejects_corrupt_and_reads_valid_payload() {
    let payload = b"DXBC_STUB_CONTAINER";
    let packed = compress_raw_deflate(payload);
    let n = (packed.len() + 12) as u32;
    let name = b"PS_TestShader_0123abcd_Wrapped";

    let mut sgd = b"SGD5\x01\x00\x00\x00".to_vec();
    sgd.push((name.len() + 1) as u8);
    sgd.extend_from_slice(name);
    sgd.push(0);
    sgd.push(0x32);
    for v in [n, 0x000D_DCE7u32, n, payload.len() as u32] {
        sgd.extend_from_slice(&v.to_le_bytes());
    }
    sgd.extend_from_slice(&packed);

    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("test_shaders.bin");
    let out_dir = dir.path().join("out");
    std::fs::write(&in_path, &sgd).unwrap();

    let summary = shader::convert_shaders_from_file(&in_path, &out_dir, 4).unwrap();
    assert_eq!(summary.total_candidates, 1);
    assert_eq!(summary.processed, 1);
    // Stub is not a full DXBC with XDAT/XBCH, so it reports a clean error rather than panicking.
    assert_eq!(summary.failed, 1);
    assert!(summary.records[0].error.is_some());
}

#[test]
fn dual_ssd_layout_estimator_calculates_exact_budgets() {
    let inv = rpf9::BuildInventory {
        root: r"S:\gta\Gta6fordevelopersacces".into(),
        total_files: 225,
        total_bytes: 224_086_000_000,
        rpf_count: 3,
        rpf_total_bytes: 161_307_137_472,
        ttpf_count: 57,
        ttpf_total_bytes: 62_216_000_000,
        exe_dll_count: 77,
        exe_dll_total_bytes: 205_000_000,
        other_count: 69,
        other_total_bytes: 357_000_000,
        rpf_headers: vec![
            rpf9::RpfFileSummary {
                rel_path: "levels.rpf".into(),
                file_size: 160_800_000_000,
                header: rpf9::Rpf9Header::parse(&dummy_rpf9_hdr()).unwrap(),
            },
            rpf9::RpfFileSummary {
                rel_path: "shaders.rpf".into(),
                file_size: 411_695_600,
                header: rpf9::Rpf9Header::parse(&dummy_rpf9_hdr()).unwrap(),
            },
            rpf9::RpfFileSummary {
                rel_path: "common.rpf".into(),
                file_size: 95_441_872,
                header: rpf9::Rpf9Header::parse(&dummy_rpf9_hdr()).unwrap(),
            },
        ],
        ttpf_files: vec![],
    };

    let e_cap = layout::DriveCapacity {
        drive: "E:\\".into(),
        total_bytes: 512_110_190_592,
        free_bytes: 343_629_000_000,
        total_gib: 476.94,
        free_gib: 320.03,
    };
    let v_cap = layout::DriveCapacity {
        drive: "V:\\".into(),
        total_bytes: 127_904_000_000,
        free_bytes: 108_770_000_000,
        total_gib: 119.12,
        free_gib: 101.30,
    };

    let plan = layout::estimate_dual_ssd_layout(&inv, None, None, Some(1.7), Some((e_cap, v_cap)))
        .unwrap();
    assert_eq!(plan.project, "LUCIAS PROJECT");
    assert!(plan.fits_within_dual_ssd);
    assert!(plan.e_drive_remaining_free_gib > 100.0);
    assert!(plan.v_drive_remaining_free_gib > 20.0);
}

#[test]
fn real_build_smoke_if_present() {
    let root = Path::new(r"S:\gta\Gta6fordevelopersacces");
    if !root.is_dir() {
        return;
    }

    // Read-only header & small-archive verification
    let (sz, hdr) = rpf9::read_rpf9_header(&root.join("common.rpf")).unwrap();
    assert_eq!(sz, 6_642_192);
    assert!(hdr.constants_match);
    assert!(hdr.toc_encrypted_aes_cbc);

    let common_rep = rpf9::inventory_rpf9_file(&root.join("common.rpf"), None, 5).unwrap();
    assert!(common_rep.carved_streams > 100);

    // Real TTPF + BCPack/Zlib -> PC DDS verification (in temp dir so workspace stays clean)
    let tmp = tempfile::tempdir().unwrap();
    let ttpf_res = ttpf::convert_ttpf_samples(
        &root.join(r"pack\core_restofworld001\data\ttdb\ui\ttdb_ui.ttpf"),
        &tmp.path().join("dds"),
        3,
    )
    .unwrap();
    assert!(ttpf_res.exported_count >= 1);

    let vfx_res = ttpf::convert_ttpf_samples(
        &root.join(r"pack\core_restofworld\data\ttdb\vfx\ttdb_vfx.ttpf"),
        &tmp.path().join("vfx_dds"),
        4,
    )
    .unwrap();
    assert_eq!(vfx_res.exported_count, 4);
    assert_eq!(vfx_res.failed_count, 0);
    assert!(
        vfx_res
            .items
            .iter()
            .any(|i| i.codec.starts_with("BCPack_")),
        "expected at least one real BCPack texture decoded"
    );

    // Real SGD5 + ACCC shader translation verification
    let accc_res = shader::convert_shaders_from_file(
        &root.join("amd_fidelityfx_upscaler_xbox.dll"),
        &tmp.path().join("accc"),
        4,
    )
    .unwrap();
    assert_eq!(accc_res.translated_ok, 4);
    assert_eq!(accc_res.failed, 0);
}

fn dummy_rpf9_hdr() -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(&rpf9::RPF9_MAGIC.to_le_bytes());
    b[0x18..0x1C].copy_from_slice(&rpf9::EXPECTED_CONST_18.to_le_bytes());
    b[0x1C..0x20].copy_from_slice(&rpf9::EXPECTED_CONST_1C.to_le_bytes());
    b[0x30..0x34].copy_from_slice(&rpf9::EXPECTED_CONST_30.to_le_bytes());
    b
}

fn build_synthetic_ttpf(width: u32, height: u32, dxgi: u8, hash: u64, min_size: usize) -> Vec<u8> {
    let mut tiled = vec![0u8; 4096];
    for (i, chunk) in tiled.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        chunk[0] = (i & 0xFF) as u8;
        chunk[15] = ((i >> 4) & 0xFF) as u8;
    }
    let mut compressed = compress_zlib(&tiled);
    if compressed.len() < min_size {
        compressed.resize(min_size, 0);
    }

    let etpf_offset = 0x100usize;
    let chunk_data_start = 0x200usize;
    let chunk_data_end = (chunk_data_start + compressed.len()).next_multiple_of(0x100);

    let mut file = vec![0u8; chunk_data_end];
    file[0..4].copy_from_slice(b"RDS5");
    file[4..8].copy_from_slice(&2u32.to_le_bytes());
    file[8..16].copy_from_slice(&4096u64.to_le_bytes());
    file[16..20].copy_from_slice(&1u32.to_le_bytes());

    let lo0 = ((chunk_data_start / 0x100) as u32) | (8u32 << 26);
    file[24..28].copy_from_slice(&lo0.to_le_bytes());
    file[28..32].copy_from_slice(&0u32.to_le_bytes());

    let lo1 = ((chunk_data_end / 0x100) as u32) | (1u32 << 30);
    file[32..36].copy_from_slice(&lo1.to_le_bytes());
    file[36..40].copy_from_slice(&0u32.to_le_bytes());

    file[etpf_offset..etpf_offset + 4].copy_from_slice(b"ETPF");
    file[etpf_offset + 4..etpf_offset + 8].copy_from_slice(&1u32.to_le_bytes());
    file[etpf_offset + 8..etpf_offset + 12].copy_from_slice(&1u32.to_le_bytes());

    let u0 = (width - 1) | ((height - 1) << 14);
    let u1 = u32::from(dxgi) << 3;
    let d_off = etpf_offset + 16;
    file[d_off..d_off + 4].copy_from_slice(&u0.to_le_bytes());
    file[d_off + 4..d_off + 8].copy_from_slice(&u1.to_le_bytes());
    file[d_off + 16..d_off + 24].copy_from_slice(&hash.to_le_bytes());
    file[chunk_data_start..chunk_data_start + compressed.len()].copy_from_slice(&compressed);
    file
}

#[test]
fn dxpk_pack_write_read_dedup_and_hash_lookup() {
    let dxbc_a = b"DXBC_XBOX_VERTEX_SHADER_ALPHA";
    let dxbc_b = b"DXBC_XBOX_PIXEL_SHADER_BETA";
    let dxbc_c = b"DXBC_XBOX_COMPUTE_SHADER_GAMMA";
    let dxil_a = b"DXBC_PC_SM66_DXIL_A_001".to_vec();
    let dxil_b = b"DXBC_PC_SM66_DXIL_B_0002".to_vec();

    let mut pack = dxpk::DxpkPack::new();
    assert!(pack.insert(dxbc_a, dxil_a.clone(), dxpk::DxpkStage::Vs, dxpk::DxpkSourceKind::Sgd5));
    // Duplicate DXBC bytes -> deduplicated by FNV-1a-64 hash
    assert!(!pack.insert(dxbc_a, dxil_a.clone(), dxpk::DxpkStage::Vs, dxpk::DxpkSourceKind::Sgd5));
    assert!(pack.insert(dxbc_b, dxil_b.clone(), dxpk::DxpkStage::Ps, dxpk::DxpkSourceKind::Sgd5));
    // Different DXBC producing identical DXIL blob -> separate index entry, shared blob
    assert!(pack.insert(dxbc_c, dxil_a.clone(), dxpk::DxpkStage::Cs, dxpk::DxpkSourceKind::AcccFspx));

    assert_eq!(pack.len(), 3);
    assert_eq!(pack.unique_blob_count(), 2);

    let dir = tempfile::tempdir().unwrap();
    let pack_path = dir.path().join("test_shaders.dxilpack");
    let (file_bytes, unique_dxil_bytes) = pack.write_to_file(&pack_path).unwrap();
    assert_eq!(unique_dxil_bytes, (dxil_a.len() + dxil_b.len()) as u64);
    assert_eq!(std::fs::metadata(&pack_path).unwrap().len(), file_bytes);

    let reader = dxpk::DxpkReader::open(&pack_path).unwrap();
    assert_eq!(reader.version, 1);
    assert_eq!(reader.entry_count, 3);
    assert_eq!(reader.index_offset, 32);
    assert_eq!(reader.data_offset, 32 + 3 * 24);
    assert!(reader.is_sorted_unique());

    // Verify binary-search lookup returns exact DXIL bytes & metadata
    assert_eq!(reader.lookup_dxbc(dxbc_a).unwrap().as_deref(), Some(dxil_a.as_slice()));
    assert_eq!(reader.lookup_dxbc(dxbc_b).unwrap().as_deref(), Some(dxil_b.as_slice()));
    assert_eq!(reader.lookup_dxbc(dxbc_c).unwrap().as_deref(), Some(dxil_a.as_slice()));
    assert_eq!(reader.lookup_dxbc(b"UNKNOWN_SHADER").unwrap(), None);

    let e_c = reader.find_entry(dxpk::fnv1a64(dxbc_c)).unwrap();
    assert_eq!(e_c.stage, dxpk::DxpkStage::Cs);
    assert_eq!(e_c.source_kind, dxpk::DxpkSourceKind::AcccFspx);
    assert_eq!(e_c.offset % 4, 0);
    assert!(e_c.offset >= reader.data_offset);
}

#[test]
fn convert_ttpf_batch_max_mb_and_resume_skips_completed() {
    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("ttdb");
    let sub1 = in_dir.join("ui");
    let sub2 = in_dir.join("vfx");
    std::fs::create_dir_all(&sub1).unwrap();
    std::fs::create_dir_all(&sub2).unwrap();

    // Two ~650 KB synthetic TTPFs -> combined ~1.3 MB, so --max-mb 1 converts only the first
    let t1 = build_synthetic_ttpf(64, 64, 98, 0x1111_2222_3333_4444, 650 * 1024);
    let t2 = build_synthetic_ttpf(64, 64, 98, 0x5555_6666_7777_8888, 700 * 1024);
    std::fs::write(sub1.join("a_small.ttpf"), &t1).unwrap();
    std::fs::write(sub2.join("b_larger.ttpf"), &t2).unwrap();

    let out_dir = dir.path().join("ttdb_pc");

    // Pass 1: bounded by --max-mb 1 -> processes only a_small.ttpf
    let rep1 = ttpf::convert_ttpf_batch(&in_dir, &out_dir, Some(1), false, 2).unwrap();
    assert_eq!(rep1.archives_discovered, 2);
    assert_eq!(rep1.archives_skipped_resumed, 0);
    assert_eq!(rep1.archives_processed_this_run, 1);
    assert_eq!(rep1.archives_completed_total, 1);
    assert_eq!(rep1.total_textures_exported_this_run, 1);
    assert_eq!(rep1.total_textures_failed_this_run, 0);

    // Pass 2: --resume with no --max-mb -> skips a_small.ttpf, converts b_larger.ttpf
    let rep2 = ttpf::convert_ttpf_batch(&in_dir, &out_dir, None, true, 2).unwrap();
    assert_eq!(rep2.archives_discovered, 2);
    assert_eq!(rep2.archives_skipped_resumed, 1);
    assert_eq!(rep2.archives_processed_this_run, 1);
    assert_eq!(rep2.archives_completed_total, 2);
    assert_eq!(rep2.total_textures_exported_this_run, 1);
    assert_eq!(rep2.total_textures_failed_this_run, 0);

    // Pass 3: --resume again -> skips both
    let rep3 = ttpf::convert_ttpf_batch(&in_dir, &out_dir, None, true, 2).unwrap();
    assert_eq!(rep3.archives_skipped_resumed, 2);
    assert_eq!(rep3.archives_processed_this_run, 0);
    assert_eq!(rep3.archives_completed_total, 2);
}

#[test]
fn convert_ttpf_batch_zstd_compress_resume_and_min_free_gb_guard() {
    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("ttdb");
    let sub = in_dir.join("ui");
    std::fs::create_dir_all(&sub).unwrap();

    let raw_ttpf = build_synthetic_ttpf(64, 64, 98, 0xABCD_1234_5678_90EF, 4096);
    std::fs::write(sub.join("sample.ttpf"), &raw_ttpf).unwrap();

    let out_dir = dir.path().join("ttdb_pc_zst");

    // 1. min_free_gb guard stops cleanly before writing when threshold exceeds free disk space.
    let guarded = ttpf::convert_ttpf_batch_with_options(&ttpf::TtpfBatchOptions {
        input_root: in_dir.clone(),
        out_dir: out_dir.clone(),
        max_mb: None,
        resume: false,
        threads: 2,
        compression: ttpf::TtpfCompression::Zstd,
        zstd_level: 3,
        min_free_gb: Some(999_999),
    })
    .unwrap();
    assert!(guarded.stopped_for_min_free_gb);
    assert!(guarded.stop_reason.is_some());
    assert_eq!(guarded.archives_processed_this_run, 0);

    // 2. Zstd pass writes valid .dds.zst frame smaller than raw DDS.
    let rep_zst = ttpf::convert_ttpf_batch_with_options(&ttpf::TtpfBatchOptions {
        input_root: in_dir.clone(),
        out_dir: out_dir.clone(),
        max_mb: None,
        resume: false,
        threads: 2,
        compression: ttpf::TtpfCompression::Zstd,
        zstd_level: 3,
        min_free_gb: Some(1),
    })
    .unwrap();
    assert!(!rep_zst.stopped_for_min_free_gb);
    assert_eq!(rep_zst.project, "LUCIAS PROJECT");
    assert_eq!(rep_zst.total_textures_exported_this_run, 1);
    assert_eq!(rep_zst.total_textures_failed_this_run, 0);
    assert!(rep_zst.total_output_written_bytes_this_run < rep_zst.total_output_dds_bytes_this_run);

    let zst_file = out_dir
        .join("ui")
        .join("sample")
        .join("tex_00000_64x64_BC7_UNORM_abcd1234567890ef.dds.zst");
    assert!(zst_file.is_file());
    let compressed_bytes = std::fs::read(&zst_file).unwrap();
    let dds = zstd::stream::decode_all(compressed_bytes.as_slice()).unwrap();
    assert_eq!(&dds[0..4], b"DDS ");
    assert_eq!(&dds[84..88], b"DX10");

    // 3. Resume in zstd mode skips the completed archive.
    let rep_resumed = ttpf::convert_ttpf_batch_with_options(&ttpf::TtpfBatchOptions {
        input_root: in_dir,
        out_dir,
        max_mb: None,
        resume: true,
        threads: 2,
        compression: ttpf::TtpfCompression::Zstd,
        zstd_level: 3,
        min_free_gb: Some(1),
    })
    .unwrap();
    assert_eq!(rep_resumed.archives_skipped_resumed, 1);
    assert_eq!(rep_resumed.archives_processed_this_run, 0);
}
