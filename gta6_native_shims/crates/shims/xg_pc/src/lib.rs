#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

use shim_common::{E_INVALIDARG, E_NOTIMPL, E_POINTER, HRESULT, S_OK, VtableHeader};

pub const DIM_BUFFER: u32 = 1;
pub const DIM_TEXTURE1D: u32 = 2;
pub const DIM_TEXTURE2D: u32 = 3;
pub const DIM_TEXTURE3D: u32 = 4;

pub const FLAG_ALLOW_RENDER_TARGET: u32 = 1;
pub const FLAG_ALLOW_DEPTH_STENCIL: u32 = 2;
pub const XBOX_SWIZZLED_LAYOUT_BIT: u32 = 0x100;
const MIPS_MAX: usize = 15;

/// Xbox Scarlett `D3D12_RESOURCE_DESC` (`0x38` bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XgResourceDesc {
    pub dimension: u32,
    pub alignment: u64,
    pub width: u64,
    pub height: u32,
    pub depth_or_array: u16,
    pub mips: u16,
    pub format: u32,
    pub samples: u32,
    pub quality: u32,
    pub layout: u32,
    pub flags: u32,
}

const _: () = assert!(size_of::<XgResourceDesc>() == 0x38);

/// Standard PC `D3D12_TEXTURE_LAYOUT` values.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcTextureLayout {
    Unknown = 0,
    RowMajor = 1,
    Undefined64KbSwizzle = 2,
    Standard64KbSwizzle = 3,
}

/// RDNA2 / GFX10.3 hardware swizzle modes (`XG_SWIZZLE_MODE`).
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

/// Remaps Xbox Scarlett console-only DXGI formats to PC equivalents.
pub fn map_xbox_dxgi_format_to_pc(xbox_fmt: u32) -> u32 {
    match xbox_fmt {
        118 => 45,     // D16_UNORM_S8_UINT -> R24G8_TYPELESS
        119 => 46,     // D16_UNORM_S8_UINT -> D24_UNORM_S8_UINT
        120 => 47,     // R16_UNORM_X8_TYPELESS -> R24_UNORM_X8_TYPELESS
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
        70..=72 | 79..=81 => (8, 4),          // BC1, BC4
        73..=78 | 82..=84 | 94..=99 => (16, 4), // BC2, BC3, BC5, BC6H, BC7
        _ => return None,
    })
}

pub fn suggest_swizzle_mode(desc: &XgResourceDesc) -> XgSwizzleMode {
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

pub fn map_xbox_to_pc_resource_desc(
    desc: &XgResourceDesc,
    staging_linear: bool,
) -> Result<PcResourceDesc, String> {
    let source_swizzle = match desc.layout {
        0 => suggest_swizzle_mode(desc),
        1 => XgSwizzleMode::Linear,
        l if (l & !0xff) == XBOX_SWIZZLED_LAYOUT_BIT => XgSwizzleMode::from_raw(l & 0xff),
        other => return Err(format!("invalid Xbox layout {other:#x}")),
    };

    let layout = if desc.dimension == DIM_BUFFER
        || staging_linear
        || source_swizzle == XgSwizzleMode::Linear
    {
        PcTextureLayout::RowMajor
    } else {
        PcTextureLayout::Unknown
    };

    let min_pc_align = if desc.samples > 1 {
        4 * 1024 * 1024
    } else {
        64 * 1024
    };
    let alignment = desc.alignment.max(min_pc_align);

    Ok(PcResourceDesc {
        dimension: desc.dimension,
        alignment,
        width: desc.width.max(1),
        height: desc.height.max(1),
        depth_or_array: desc.depth_or_array.max(1),
        mip_levels: desc.mips.max(1),
        pc_dxgi_format: map_xbox_dxgi_format_to_pc(desc.format),
        sample_count: desc.samples.max(1),
        sample_quality: desc.quality,
        layout,
        flags: desc.flags,
        source_swizzle,
    })
}

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

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XgMipLayout {
    pub size: u64,
    pub offset: u64,
    pub slice_size: u64,
    pub pitch_texels: u32,
    pub pitch_bytes: u32,
    pub alignment: u32,
    pub padded: [u32; 3],
    pub elements: [u32; 2],
    pub texels: [u32; 2],
    pub depth_or_array: u32,
    pub samples: u32,
    pub swizzle: u32,
    pub bank_rotation: [u64; 2],
    pub slice_depth: u32,
    pub in_tail: u32,
    pub tail_position: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XgPlaneLayout {
    pub usage: u32,
    pub size: u64,
    pub slice_size: u64,
    pub offset: u64,
    pub alignment: u64,
    pub element_bytes: u32,
    pub standard_mips: u32,
    pub tail_mips: u32,
    pub mips: [XgMipLayout; MIPS_MAX],
}

impl Default for XgPlaneLayout {
    fn default() -> Self {
        Self {
            usage: 1,
            size: 0,
            slice_size: 0,
            offset: 0,
            alignment: 0,
            element_bytes: 0,
            standard_mips: 0,
            tail_mips: 0,
            mips: [XgMipLayout::default(); MIPS_MAX],
        }
    }
}

/// Xbox `XG_RESOURCE_LAYOUT` (`0x1b40` bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XgResourceLayout {
    pub size: u64,
    pub alignment: u64,
    pub mips: u32,
    pub planes: u32,
    pub plane: [XgPlaneLayout; 4],
    pub dimension: u32,
}

const _: () = assert!(size_of::<XgMipLayout>() == 0x70);
const _: () = assert!(size_of::<XgPlaneLayout>() == 0x6c8);
const _: () = assert!(size_of::<XgResourceLayout>() == 0x1b40);

#[repr(C)]
pub struct XgPackedMips {
    pub standard: u8,
    pub packed: u8,
    pub tiles: u32,
    pub start: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XgSubresourceTiling {
    pub width: u32,
    pub height: u16,
    pub depth: u16,
    pub start: u32,
}

#[repr(C)]
pub struct TextureComputer {
    vtable: *const *const c_void,
    refs: AtomicU32,
    desc: XgResourceDesc,
    pc_desc: PcResourceDesc,
    mips: u32,
    elem_bytes: u32,
    block_side: u32,
    footprints: [PcSubresourceFootprint; MIPS_MAX],
    total_bytes: u64,
}

static COMPUTER_VTABLE: VtableHeader<13> = VtableHeader([
    comp_add_ref as *const c_void,             // 0x00 AddRef
    comp_release as *const c_void,             // 0x08 Release
    comp_get_resource_layout as *const c_void, // 0x10 GetResourceLayout
    comp_get_size_bytes as *const c_void,      // 0x18 GetResourceSizeBytes
    comp_get_alignment_bytes as *const c_void, // 0x20 GetResourceAlignmentBytes
    comp_get_mip_offset as *const c_void,      // 0x28 GetMipLevelOffsetBytes
    comp_get_element_offset as *const c_void,  // 0x30 GetTexelElementOffsetBytes
    comp_stub as *const c_void,                // 0x38 GetTexelCoordinate
    comp_copy_into as *const c_void,           // 0x40 CopyIntoSubresource
    comp_copy_from as *const c_void,           // 0x48 CopyFromSubresource
    comp_get_tiling as *const c_void,          // 0x50 GetResourceTiling
    comp_stub as *const c_void,                // 0x58
    comp_stub as *const c_void,                // 0x60
]);

extern "system" fn comp_add_ref(this: *mut TextureComputer) -> u32 {
    unsafe { &*this }.refs.fetch_add(1, Ordering::Relaxed) + 1
}

extern "system" fn comp_release(this: *mut TextureComputer) -> u32 {
    let left = unsafe { &*this }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

extern "system" fn comp_get_resource_layout(
    this: *mut TextureComputer,
    out_layout: *mut XgResourceLayout,
) -> HRESULT {
    let (Some(c), false) = (unsafe { this.as_ref() }, out_layout.is_null()) else {
        return E_INVALIDARG;
    };
    unsafe { out_layout.write_bytes(0, 1) };
    let out = unsafe { &mut *out_layout };
    out.size = c.total_bytes;
    out.alignment = c.pc_desc.alignment;
    out.mips = c.mips;
    out.planes = 1;
    out.dimension = c.desc.dimension;

    let plane = &mut out.plane[0];
    plane.usage = if (c.desc.flags & FLAG_ALLOW_DEPTH_STENCIL) != 0 {
        7
    } else {
        1
    };
    plane.size = c.total_bytes;
    plane.slice_size = c.total_bytes;
    plane.offset = 0;
    plane.alignment = c.pc_desc.alignment;
    plane.element_bytes = c.elem_bytes;
    plane.standard_mips = c.mips;
    plane.tail_mips = 0;

    let array = u32::from(c.pc_desc.depth_or_array);
    for i in 0..(c.mips as usize) {
        let fp = &c.footprints[i];
        let elems_x = fp.width.div_ceil(c.block_side);
        let elems_y = fp.height.div_ceil(c.block_side);
        plane.mips[i] = XgMipLayout {
            size: fp.total_bytes,
            offset: fp.offset,
            slice_size: fp.total_bytes,
            pitch_texels: (fp.row_pitch / c.elem_bytes.max(1)) * c.block_side,
            pitch_bytes: fp.row_pitch,
            alignment: 512,
            padded: [fp.row_pitch / c.elem_bytes.max(1), elems_y, fp.depth],
            elements: [elems_x, elems_y],
            texels: [fp.width, fp.height],
            depth_or_array: if c.pc_desc.dimension == DIM_TEXTURE3D {
                fp.depth
            } else {
                array
            },
            samples: c.pc_desc.sample_count,
            swizzle: c.pc_desc.source_swizzle.raw(),
            bank_rotation: [0, 0],
            slice_depth: 1,
            in_tail: 0,
            tail_position: 0,
        };
    }
    S_OK
}

extern "system" fn comp_get_size_bytes(this: *mut TextureComputer) -> u64 {
    unsafe { this.as_ref() }.map_or(0, |c| c.total_bytes)
}

extern "system" fn comp_get_alignment_bytes(this: *mut TextureComputer) -> u64 {
    unsafe { this.as_ref() }.map_or(0, |c| c.pc_desc.alignment)
}

extern "system" fn comp_get_mip_offset(
    this: *mut TextureComputer,
    plane: u32,
    mip: u32,
) -> u64 {
    let Some(c) = (unsafe { this.as_ref() }) else {
        return 0;
    };
    if plane != 0 || mip >= c.mips {
        return 0;
    }
    c.footprints[mip as usize].offset
}

extern "system" fn comp_get_element_offset(
    this: *mut TextureComputer,
    plane: u32,
    mip: u32,
    x: u64,
    y: u32,
    z: u32,
    _sample: u32,
    bit: *mut u32,
) -> u64 {
    if !bit.is_null() {
        unsafe { bit.write(0) };
    }
    let Some(c) = (unsafe { this.as_ref() }) else {
        return 0;
    };
    if plane != 0 || mip >= c.mips {
        return 0;
    }
    let fp = &c.footprints[mip as usize];
    let x32 = u32::try_from(x).unwrap_or(u32::MAX);
    let slice_off = u64::from(z) * u64::from(fp.row_pitch) * u64::from(fp.height.div_ceil(c.block_side));
    let in_slice = match c.pc_desc.source_swizzle {
        XgSwizzleMode::Sw256BS | XgSwizzleMode::Sw4KBS | XgSwizzleMode::Sw64KBS => {
            let block_log2 = match c.pc_desc.source_swizzle {
                XgSwizzleMode::Sw256BS => 8,
                XgSwizzleMode::Sw4KBS => 12,
                _ => 16,
            };
            rdna2_thin_s_offset(x32, y, c.elem_bytes, block_log2).unwrap_or(0) as u64
        }
        _ => u64::from(y) * u64::from(fp.row_pitch) + u64::from(x32) * u64::from(c.elem_bytes),
    };
    fp.offset + slice_off + in_slice
}

extern "system" fn comp_copy_into(
    this: *mut TextureComputer,
    tiled: *mut u8,
    plane: u32,
    subresource: u32,
    linear: *const u8,
    row_pitch: u32,
    _depth_pitch: u32,
) -> HRESULT {
    let Some(c) = (unsafe { this.as_ref() }) else {
        return E_INVALIDARG;
    };
    if tiled.is_null() || linear.is_null() || plane != 0 {
        return E_INVALIDARG;
    }
    let mip = (subresource % c.mips) as usize;
    let slice = subresource / c.mips;
    let fp = &c.footprints[mip];
    let elems_x = fp.width.div_ceil(c.block_side) as usize;
    let elems_y = fp.height.div_ceil(c.block_side) as usize;
    let row_bytes = elems_x * (c.elem_bytes as usize);
    let src_stride = (row_pitch as usize).max(row_bytes);
    let dst_stride = fp.row_pitch as usize;
    let slice_base = fp.offset as usize + (slice as usize) * fp.total_bytes as usize;

    for row in 0..elems_y {
        let src_ptr = unsafe { linear.add(row * src_stride) };
        let dst_ptr = unsafe { tiled.add(slice_base + row * dst_stride) };
        unsafe { std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, row_bytes) };
    }
    S_OK
}

extern "system" fn comp_copy_from(
    this: *mut TextureComputer,
    linear: *mut u8,
    plane: u32,
    subresource: u32,
    _sample: u32,
    tiled: *const u8,
    row_pitch: u32,
    _depth_pitch: u32,
) -> HRESULT {
    let Some(c) = (unsafe { this.as_ref() }) else {
        return E_INVALIDARG;
    };
    if tiled.is_null() || linear.is_null() || plane != 0 {
        return E_INVALIDARG;
    }
    let mip = (subresource % c.mips) as usize;
    let slice = subresource / c.mips;
    let fp = &c.footprints[mip];
    let elems_x = fp.width.div_ceil(c.block_side);
    let elems_y = fp.height.div_ceil(c.block_side);
    let row_bytes = (elems_x as usize) * (c.elem_bytes as usize);
    let dst_stride = (row_pitch as usize).max(row_bytes);
    let slice_base = fp.offset as usize + (slice as usize) * fp.total_bytes as usize;

    if matches!(
        c.pc_desc.source_swizzle,
        XgSwizzleMode::Sw256BS | XgSwizzleMode::Sw4KBS | XgSwizzleMode::Sw64KBS
    ) {
        let tiled_slice = unsafe {
            std::slice::from_raw_parts(tiled.add(slice_base), fp.total_bytes as usize)
        };
        if let Some(detiled) = detile_2d_thin_s_to_pc_footprint(
            tiled_slice,
            elems_x,
            elems_y,
            c.elem_bytes,
            c.pc_desc.source_swizzle,
            dst_stride as u32,
        ) {
            let copy_len = (elems_y as usize) * dst_stride;
            unsafe {
                std::ptr::copy_nonoverlapping(detiled.as_ptr(), linear, copy_len);
            }
            return S_OK;
        }
    }

    let src_stride = fp.row_pitch as usize;
    for row in 0..(elems_y as usize) {
        let src_ptr = unsafe { tiled.add(slice_base + row * src_stride) };
        let dst_ptr = unsafe { linear.add(row * dst_stride) };
        unsafe { std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, row_bytes) };
    }
    S_OK
}

fn standard_tile_shape(elem_bytes: u32, block_side: u32, dimension: u32) -> [u32; 3] {
    match dimension {
        DIM_TEXTURE2D => {
            if block_side == 4 {
                if elem_bytes <= 8 {
                    [512, 256, 1]
                } else {
                    [256, 256, 1]
                }
            } else if block_side == 1 {
                match elem_bytes {
                    1 => [256, 256, 1],
                    2 => [256, 128, 1],
                    4 => [128, 128, 1],
                    8 => [128, 64, 1],
                    _ => [64, 64, 1],
                }
            } else {
                [64, 64, 1]
            }
        }
        DIM_TEXTURE3D => {
            if elem_bytes <= 2 {
                [64, 32, 16]
            } else if elem_bytes >= 16 {
                [16, 16, 16]
            } else {
                [32, 32, 16]
            }
        }
        _ => [64, 64, 1],
    }
}

extern "system" fn comp_get_tiling(
    this: *mut TextureComputer,
    tiles: *mut u32,
    packed: *mut XgPackedMips,
    shape: *mut [u32; 3],
    count: *mut u32,
    first: u32,
    out: *mut XgSubresourceTiling,
) -> HRESULT {
    let Some(c) = (unsafe { this.as_ref() }) else {
        return E_INVALIDARG;
    };
    let [tile_w, tile_h, tile_d] = standard_tile_shape(c.elem_bytes, c.block_side, c.desc.dimension);
    let mips = c.mips.max(1);
    let mut full_tile_mips = 0u32;
    for m in 0..(mips as usize) {
        let fp = &c.footprints[m];
        if fp.width >= tile_w && fp.height >= tile_h && fp.depth >= tile_d {
            full_tile_mips += 1;
        } else {
            break;
        }
    }
    let max_standard = if mips > 6 { 5 } else { mips.min(6) };
    let standard = full_tile_mips.clamp(1, max_standard);
    let packed_mips = mips.saturating_sub(standard);

    let mut std_tilings = Vec::with_capacity(standard as usize);
    let mut std_tiles_sum = 0u32;
    for m in 0..(standard as usize) {
        let fp = &c.footprints[m];
        let width = fp.width.div_ceil(tile_w).max(1);
        let height = fp.height.div_ceil(tile_h).max(1);
        let depth = fp.depth.div_ceil(tile_d).max(1);
        std_tilings.push(XgSubresourceTiling {
            width,
            height: height as u16,
            depth: depth as u16,
            start: std_tiles_sum,
        });
        std_tiles_sum = std_tiles_sum.saturating_add(width.saturating_mul(height).saturating_mul(depth));
    }
    let packed_tiles = u32::from(packed_mips > 0);
    let total_tiles = std_tiles_sum.saturating_add(packed_tiles);

    if !tiles.is_null() {
        unsafe { *tiles = total_tiles };
    }
    if !packed.is_null() {
        unsafe {
            *packed = XgPackedMips {
                standard: standard as u8,
                packed: packed_mips as u8,
                tiles: packed_tiles,
                start: std_tiles_sum,
            };
        }
    }
    if !shape.is_null() {
        unsafe { *shape = [tile_w, tile_h, tile_d] };
    }
    if !count.is_null() {
        let avail = unsafe { *count };
        let needed = mips.saturating_sub(first);
        let written = avail.min(needed);
        if !out.is_null() {
            for i in 0..written {
                let mip_idx = (first + i) as usize;
                let entry = if mip_idx < std_tilings.len() {
                    std_tilings[mip_idx]
                } else {
                    XgSubresourceTiling {
                        width: 0,
                        height: 0,
                        depth: 0,
                        start: 0xFFFF,
                    }
                };
                unsafe { *out.add(i as usize) = entry };
            }
        }
        unsafe { *count = needed };
    }
    S_OK
}

extern "system" fn comp_stub() -> HRESULT {
    E_NOTIMPL
}

#[unsafe(no_mangle)]
pub extern "system" fn XGSuggestSwizzleMode(
    desc: *const XgResourceDesc,
    _flags: u32,
    out_layout: *mut u32,
) -> HRESULT {
    let (Some(d), Some(out)) = (unsafe { desc.as_ref() }, unsafe { out_layout.as_mut() }) else {
        return E_INVALIDARG;
    };
    *out = XBOX_SWIZZLED_LAYOUT_BIT | suggest_swizzle_mode(d).raw();
    S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn XGCreateTextureComputer(
    desc: *const XgResourceDesc,
    out: *mut *mut TextureComputer,
) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let Some(&d) = (unsafe { desc.as_ref() }) else {
        return E_INVALIDARG;
    };
    let Ok(pc_desc) = map_xbox_to_pc_resource_desc(&d, false) else {
        return E_INVALIDARG;
    };
    let mips = u32::from(pc_desc.mip_levels).clamp(1, MIPS_MAX as u32);
    let (elem_bytes, block_side) = format_element_info(pc_desc.pc_dxgi_format).unwrap_or((4, 1));

    let mut footprints = [PcSubresourceFootprint {
        offset: 0,
        format: pc_desc.pc_dxgi_format,
        width: 1,
        height: 1,
        depth: 1,
        row_pitch: 256,
        total_bytes: 256,
    }; MIPS_MAX];

    let mut cursor = 0u64;
    for mip in 0..mips {
        let fp = compute_pc_placed_footprint(&pc_desc, mip, cursor).unwrap_or_else(|| {
            let w = ((pc_desc.width as u32) >> mip).max(1);
            let h = (pc_desc.height >> mip).max(1);
            let row_pitch = (w * elem_bytes).next_multiple_of(256);
            PcSubresourceFootprint {
                offset: cursor.next_multiple_of(512),
                format: pc_desc.pc_dxgi_format,
                width: w,
                height: h,
                depth: 1,
                row_pitch,
                total_bytes: u64::from(row_pitch) * u64::from(h),
            }
        });
        footprints[mip as usize] = fp;
        cursor = fp.offset + fp.total_bytes;
    }

    let array_slices = if pc_desc.dimension == DIM_TEXTURE3D {
        1u64
    } else {
        u64::from(pc_desc.depth_or_array)
    };
    let raw_total = cursor.saturating_mul(array_slices).max(256);
    let total_bytes = raw_total.next_multiple_of(pc_desc.alignment);

    let obj = Box::new(TextureComputer {
        vtable: COMPUTER_VTABLE.0.as_ptr(),
        refs: AtomicU32::new(1),
        desc: d,
        pc_desc,
        mips,
        elem_bytes,
        block_side,
        footprints,
        total_bytes,
    });
    shim_common::boot_trace(
        "xg_pc",
        "XGCreateTextureComputer",
        &format!("dim={} {}x{} fmt={} total={total_bytes}", d.dimension, d.width, d.height, d.format),
    );
    unsafe { *out = Box::into_raw(obj) };
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_swizzle_and_creates_real_layout_computer() {
        let desc = XgResourceDesc {
            dimension: DIM_TEXTURE2D,
            alignment: 0,
            width: 512,
            height: 512,
            depth_or_array: 1,
            mips: 4,
            format: 71, // BC1_UNORM
            samples: 1,
            quality: 0,
            layout: 0,
            flags: FLAG_ALLOW_RENDER_TARGET,
        };
        let mut swizzle = 0u32;
        assert_eq!(XGSuggestSwizzleMode(&desc, 0, &mut swizzle), S_OK);
        assert_eq!(swizzle, XBOX_SWIZZLED_LAYOUT_BIT | XgSwizzleMode::Sw64KBRX.raw());

        let mut comp: *mut TextureComputer = std::ptr::null_mut();
        assert_eq!(XGCreateTextureComputer(&desc, &mut comp), S_OK);
        assert!(!comp.is_null());

        let mut layout = unsafe { std::mem::zeroed::<XgResourceLayout>() };
        assert_eq!(comp_get_resource_layout(comp, &mut layout), S_OK);
        assert_eq!(layout.mips, 4);
        assert_eq!(layout.alignment, 64 * 1024);
        assert!(layout.size >= 64 * 1024);
        assert_eq!(layout.plane[0].mips[0].texels, [512, 512]);
        assert_eq!(layout.plane[0].mips[0].pitch_bytes % 256, 0);
        assert_eq!(comp_get_size_bytes(comp), layout.size);
        assert_eq!(comp_release(comp), 0);
    }

    #[test]
    fn comp_get_tiling_packs_tail_mips_for_rage_bounds() {
        let check_case = |w: u64, h: u32, mips: u16, format: u32, exp_std: u8, exp_packed: u8, exp_shape: [u32; 3]| {
            let desc = XgResourceDesc {
                dimension: DIM_TEXTURE2D,
                alignment: 0,
                width: w,
                height: h,
                depth_or_array: 1,
                mips,
                format,
                samples: 1,
                quality: 0,
                layout: 0,
                flags: 0,
            };
            let mut comp: *mut TextureComputer = std::ptr::null_mut();
            assert_eq!(XGCreateTextureComputer(&desc, &mut comp), S_OK);
            let mut total_tiles = 0u32;
            let mut packed = XgPackedMips {
                standard: 0,
                packed: 0,
                tiles: 0,
                start: 0,
            };
            let mut shape = [0u32; 3];
            let mut sub_count = mips as u32;
            let mut tilings = vec![
                XgSubresourceTiling {
                    width: 0,
                    height: 0,
                    depth: 0,
                    start: 0,
                };
                mips as usize
            ];
            assert_eq!(
                comp_get_tiling(
                    comp,
                    &mut total_tiles,
                    &mut packed,
                    &mut shape,
                    &mut sub_count,
                    0,
                    tilings.as_mut_ptr(),
                ),
                S_OK
            );
            assert_eq!(shape, exp_shape);
            assert_eq!(packed.standard, exp_std);
            assert_eq!(packed.packed, exp_packed);
            assert!(packed.standard >= 1);
            assert!(u32::from(packed.standard) + u32::from(packed.packed > 0) < 7);
            assert_eq!(packed.tiles, u32::from(exp_packed > 0));
            assert_eq!(total_tiles, packed.start + packed.tiles);
            for (idx, t) in tilings.iter().enumerate() {
                if idx < exp_std as usize {
                    assert!(t.width >= 1 && t.height >= 1 && t.depth >= 1 && t.start < packed.start);
                } else {
                    assert_eq!((t.width, t.height, t.depth, t.start), (0, 0, 0, 0xFFFF));
                }
            }
            assert_eq!(comp_release(comp), 0);
        };

        // 2048x2048 BC7 (fmt=98), 12 mips -> standard=4, packed=8
        check_case(2048, 2048, 12, 98, 4, 8, [256, 256, 1]);
        // 256x256 BC5 (fmt=83), 9 mips -> standard=1, packed=8
        check_case(256, 256, 9, 83, 1, 8, [256, 256, 1]);
        // 64x64 RGBA8 (fmt=28), 7 mips -> standard=1, packed=6
        check_case(64, 64, 7, 28, 1, 6, [128, 128, 1]);
    }
}
