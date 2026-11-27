//! **LUCIAS PROJECT** — `xg_xs.dll` (`XGCreateTextureComputer` / `XGSuggestSwizzleMode`) -> Native PC
//! `D3D12_RESOURCE_DESC` & `D3D12_PLACED_SUBRESOURCE_FOOTPRINT` surface mapper.
//!
//! Verified against `victory-hle/src/modules/xg.rs`, `victory-formats/src/texture.rs`,
//! and `game_scarlett_master.exe` call-site `0x16f7141` (`0x38`-byte `ResourceDesc`)
//! + RAGE texture header converter `0x4ecc940`.

/// Xbox Scarlett `D3D12_RESOURCE_DESC` (`0x38` = 56 bytes, verified at `0x16f7113..0x16f7141`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XboxResourceDesc {
    pub dimension: u32,
    pub alignment: u64,
    pub width: u64,
    pub height: u32,
    pub depth_or_array: u16,
    pub mip_levels: u16,
    pub format: u32,
    pub sample_count: u32,
    pub sample_quality: u32,
    pub layout: u32,
    pub flags: u32,
}
const _: () = assert!(std::mem::size_of::<XboxResourceDesc>() == 0x38);

/// Standard PC `D3D12_TEXTURE_LAYOUT` values.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcTextureLayout {
    Unknown = 0,
    RowMajor = 1,
    Undefined64KbSwizzle = 2,
    Standard64KbSwizzle = 3,
}

/// PC `D3D12_RESOURCE_DESC` translation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcResourceDesc {
    pub dimension: u32,
    pub alignment: u64,
    pub width: u64,
    pub height: u32,
    pub depth_or_array: u16,
    pub mip_levels: u16,
    pub pc_dxgi_format: u32,
    pub sample_count: u32,
    pub sample_quality: u32,
    pub layout: PcTextureLayout,
    pub flags: u32,
    pub source_swizzle: XgSwizzleMode,
}

/// RDNA2 / GFX10.3 hardware swizzle modes (`XG_SWIZZLE_MODE` / `ADDR_SW_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XgSwizzleMode {
    Linear,
    Sw256BS,
    Sw256BD,
    Sw4KBS,
    Sw4KBD,
    Sw64KBS,
    Sw64KBD,
    Sw64KBST,
    Sw64KBDT,
    Sw4KBSX,
    Sw4KBDX,
    Sw4KBRX,
    Sw64KBZX,
    Sw64KBSX,
    Sw64KBDX,
    Sw64KBRX,
    Unknown(u32),
}

impl XgSwizzleMode {
    pub fn from_raw(code: u32) -> Self {
        match code {
            0 => Self::Linear,
            1 => Self::Sw256BS,
            2 => Self::Sw256BD,
            5 => Self::Sw4KBS,
            6 => Self::Sw4KBD,
            9 => Self::Sw64KBS,
            10 => Self::Sw64KBD,
            17 => Self::Sw64KBST,
            18 => Self::Sw64KBDT,
            21 => Self::Sw4KBSX,
            22 => Self::Sw4KBDX,
            23 => Self::Sw4KBRX,
            24 => Self::Sw64KBZX,
            25 => Self::Sw64KBSX,
            26 => Self::Sw64KBDX,
            27 => Self::Sw64KBRX,
            other => Self::Unknown(other),
        }
    }

    pub fn raw(self) -> u32 {
        match self {
            Self::Linear => 0,
            Self::Sw256BS => 1,
            Self::Sw256BD => 2,
            Self::Sw4KBS => 5,
            Self::Sw4KBD => 6,
            Self::Sw64KBS => 9,
            Self::Sw64KBD => 10,
            Self::Sw64KBST => 17,
            Self::Sw64KBDT => 18,
            Self::Sw4KBSX => 21,
            Self::Sw4KBDX => 22,
            Self::Sw4KBRX => 23,
            Self::Sw64KBZX => 24,
            Self::Sw64KBSX => 25,
            Self::Sw64KBDX => 26,
            Self::Sw64KBRX => 27,
            Self::Unknown(v) => v,
        }
    }

    pub fn block_size_bytes(self) -> Option<u32> {
        Some(match self {
            Self::Linear => 1,
            Self::Sw256BS | Self::Sw256BD => 256,
            Self::Sw4KBS | Self::Sw4KBD | Self::Sw4KBSX | Self::Sw4KBDX | Self::Sw4KBRX => 4096,
            Self::Sw64KBS
            | Self::Sw64KBD
            | Self::Sw64KBST
            | Self::Sw64KBDT
            | Self::Sw64KBZX
            | Self::Sw64KBSX
            | Self::Sw64KBDX
            | Self::Sw64KBRX => 65536,
            Self::Unknown(_) => return None,
        })
    }
}

pub const DIM_BUFFER: u32 = 1;
pub const DIM_TEXTURE1D: u32 = 2;
pub const DIM_TEXTURE2D: u32 = 3;
pub const DIM_TEXTURE3D: u32 = 4;

pub const FLAG_ALLOW_RENDER_TARGET: u32 = 1;
pub const FLAG_ALLOW_DEPTH_STENCIL: u32 = 2;
pub const XBOX_SWIZZLED_LAYOUT_BIT: u32 = 0x100;

/// Remaps Xbox Scarlett console-only DXGI formats to PC equivalents (`resource.rs:245`).
pub fn map_xbox_dxgi_format_to_pc(xbox_fmt: u32) -> u32 {
    match xbox_fmt {
        118 => 45, // D16_UNORM_S8_UINT -> R24G8_TYPELESS
        119 => 46, // D16_UNORM_S8_UINT -> D24_UNORM_S8_UINT
        120 => 47, // R16_UNORM_X8_TYPELESS -> R24_UNORM_X8_TYPELESS
        116 | 117 => 24, // 10-bit console float color -> R10G10B10A2_UNORM fallback
        other => other,
    }
}

/// Returns `(bytes_per_element, texel_block_side)` for a DXGI format.
pub fn format_element_info(dxgi_fmt: u32) -> Option<(u32, u32)> {
    Some(match dxgi_fmt {
        1..=4 => (16, 1),
        5..=8 => (12, 1),
        9..=22 => (8, 1),
        23..=47 | 67 | 87..=93 | 116 | 117 | 189 | 191 => (4, 1),
        118..=120 => (3, 1),
        48..=59 | 68 | 69 | 85 | 86 | 115 => (2, 1),
        60..=65 | 190 => (1, 1),
        70..=72 | 79..=81 => (8, 4),   // BC1, BC4
        73..=78 | 82..=84 | 94..=99 => (16, 4), // BC2, BC3, BC5, BC6H, BC7
        _ => return None,
    })
}

/// Implements `XGSuggestSwizzleMode` semantics (`xg.rs:58`).
pub fn suggest_swizzle_mode(desc: &XboxResourceDesc) -> XgSwizzleMode {
    if desc.dimension == DIM_TEXTURE1D || desc.dimension == DIM_BUFFER {
        XgSwizzleMode::Linear
    } else if (desc.flags & FLAG_ALLOW_DEPTH_STENCIL) != 0 {
        XgSwizzleMode::Sw64KBZX
    } else if (desc.flags & FLAG_ALLOW_RENDER_TARGET) != 0 {
        XgSwizzleMode::Sw64KBRX
    } else {
        XgSwizzleMode::Sw4KBS
    }
}

/// Translates an `XboxResourceDesc` (`layout` = `0`, `1`, or `0x100 | swizzle`) into a PC `D3D12_RESOURCE_DESC`.
pub fn map_xbox_to_pc_resource_desc(
    desc: &XboxResourceDesc,
    staging_linear: bool,
) -> Result<PcResourceDesc, String> {
    let source_swizzle = match desc.layout {
        0 => suggest_swizzle_mode(desc),
        1 => XgSwizzleMode::Linear,
        l if (l & !0xff) == XBOX_SWIZZLED_LAYOUT_BIT => XgSwizzleMode::from_raw(l & 0xff),
        other => return Err(format!("invalid Xbox layout {other:#x}")),
    };

    let layout = if desc.dimension == DIM_BUFFER || staging_linear || source_swizzle == XgSwizzleMode::Linear {
        PcTextureLayout::RowMajor
    } else {
        PcTextureLayout::Unknown
    };

    let min_pc_align = if desc.sample_count > 1 {
        4 * 1024 * 1024
    } else {
        64 * 1024
    };
    let alignment = desc.alignment.max(min_pc_align);

    Ok(PcResourceDesc {
        dimension: desc.dimension,
        alignment,
        width: desc.width,
        height: desc.height,
        depth_or_array: desc.depth_or_array,
        mip_levels: desc.mip_levels,
        pc_dxgi_format: map_xbox_dxgi_format_to_pc(desc.format),
        sample_count: desc.sample_count.max(1),
        sample_quality: desc.sample_quality,
        layout,
        flags: desc.flags,
        source_swizzle,
    })
}

/// PC `D3D12_PLACED_SUBRESOURCE_FOOTPRINT` parameters for `UPLOAD` -> `CopyTextureRegion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcSubresourceFootprint {
    pub offset: u64,
    pub format: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub row_pitch: u32,
    pub total_bytes: u64,
}

/// Computes `D3D12_PLACED_SUBRESOURCE_FOOTPRINT` aligned to D3D12's 256-byte row pitch
/// and 512-byte subresource placement rules.
pub fn compute_pc_placed_footprint(
    pc_desc: &PcResourceDesc,
    mip_level: u32,
    base_offset: u64,
) -> Option<PcSubresourceFootprint> {
    let (elem_bytes, block_side) = format_element_info(pc_desc.pc_dxgi_format)?;
    let mip_w = ((pc_desc.width as u32) >> mip_level).max(1);
    let mip_h = (pc_desc.height >> mip_level).max(1);
    let mip_d = if pc_desc.dimension == DIM_TEXTURE3D {
        (u32::from(pc_desc.depth_or_array) >> mip_level).max(1)
    } else {
        1
    };

    let elems_x = mip_w.div_ceil(block_side);
    let elems_y = mip_h.div_ceil(block_side);
    let unaligned_row = elems_x * elem_bytes;
    let row_pitch = unaligned_row.next_multiple_of(256);
    let offset = base_offset.next_multiple_of(512);
    let total_bytes = u64::from(row_pitch) * u64::from(elems_y) * u64::from(mip_d);

    Some(PcSubresourceFootprint {
        offset,
        format: pc_desc.pc_dxgi_format,
        width: mip_w,
        height: mip_h,
        depth: mip_d,
        row_pitch,
        total_bytes,
    })
}

/// Computes the RDNA2 thin-standard (`_S`) byte offset inside a 256B / 4KB / 64KB tile
/// for element `(x, y)` with `element_bytes` in `{1, 2, 4, 8, 16}` (`victory-formats/src/texture.rs`).
pub fn rdna2_thin_s_offset(x: u32, y: u32, element_bytes: u32, block_log2: u32) -> Option<usize> {
    let elem_log2 = element_bytes.trailing_zeros();
    if !element_bytes.is_power_of_two() || elem_log2 > 4 || !(8..=16).contains(&block_log2) {
        return None;
    }
    const MICRO_S: [&[u8; 16]; 5] = [
        b"x0x1x2x3y0y1y2y3",
        b"--x0x1x2y0y1y2x3",
        b"----x0x1y0y1y2x2",
        b"------x0y0y1x1x2",
        b"--------y0y1x0x1",
    ];
    let micro = MICRO_S[elem_log2 as usize];
    let mut x_bits_used = 0u32;
    let mut y_bits_used = 0u32;
    let mut addr = 0usize;
    for bit in 0..8u32 {
        let axis = micro[2 * bit as usize];
        let idx = micro[2 * bit as usize + 1];
        if axis == b'x' {
            let k = u32::from(idx - b'0');
            x_bits_used = x_bits_used.max(k + 1);
            addr |= (((x >> k) & 1) as usize) << bit;
        } else if axis == b'y' {
            let k = u32::from(idx - b'0');
            y_bits_used = y_bits_used.max(k + 1);
            addr |= (((y >> k) & 1) as usize) << bit;
        }
    }
    // Larger blocks (4KB=12, 64KB=16) alternate Y then X from bit 8 upward.
    for bit in 8..block_log2 {
        if (bit - 8) % 2 == 0 {
            addr |= (((y >> y_bits_used) & 1) as usize) << bit;
            y_bits_used += 1;
        } else {
            addr |= (((x >> x_bits_used) & 1) as usize) << bit;
            x_bits_used += 1;
        }
    }
    Some(addr)
}

/// Detiles a single 2D RDNA2 `_S` tiled mip (256B, 4KB, or 64KB) into a PC 256-byte row-pitch
/// `D3D12_PLACED_SUBRESOURCE_FOOTPRINT` linear buffer ready for `CopyTextureRegion`.
pub fn detile_2d_thin_s_to_pc_footprint(
    tiled_src: &[u8],
    elems_w: u32,
    elems_h: u32,
    element_bytes: u32,
    swizzle: XgSwizzleMode,
    pc_row_pitch: u32,
) -> Option<Vec<u8>> {
    let block_log2 = match swizzle {
        XgSwizzleMode::Sw256BS => 8,
        XgSwizzleMode::Sw4KBS => 12,
        XgSwizzleMode::Sw64KBS => 16,
        _ => return None,
    };
    let elem_log2 = element_bytes.trailing_zeros();
    if !element_bytes.is_power_of_two() || elem_log2 > 4 {
        return None;
    }
    // Block dimensions in elements: total bits in block = block_log2 - elem_log2;
    // split evenly with Y taking the extra bit if odd (matches addrlib thin _S).
    let total_elem_bits = block_log2 - elem_log2;
    let x_bits = total_elem_bits / 2;
    let y_bits = total_elem_bits - x_bits;
    let blk_w = 1u32 << x_bits;
    let blk_h = 1u32 << y_bits;
    let blk_bytes = 1usize << block_log2;
    let pitch_blocks = elems_w.div_ceil(blk_w);
    let rows_blocks = elems_h.div_ceil(blk_h);
    if tiled_src.len() < (pitch_blocks as usize) * (rows_blocks as usize) * blk_bytes {
        return None;
    }

    let mut dst = vec![0u8; (pc_row_pitch as usize) * (elems_h as usize)];
    let ebytes = element_bytes as usize;
    for y in 0..elems_h {
        let by = y / blk_h;
        let ly = y % blk_h;
        let dst_row = (y as usize) * (pc_row_pitch as usize);
        for x in 0..elems_w {
            let bx = x / blk_w;
            let lx = x % blk_w;
            let blk_base = ((by * pitch_blocks + bx) as usize) * blk_bytes;
            let in_blk = rdna2_thin_s_offset(lx, ly, element_bytes, block_log2)?;
            let src_off = blk_base + in_blk;
            let dst_off = dst_row + (x as usize) * ebytes;
            dst[dst_off..dst_off + ebytes].copy_from_slice(&tiled_src[src_off..src_off + ebytes]);
        }
    }
    Some(dst)
}
