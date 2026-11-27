//! **LUCIAS PROJECT** — Native PC RTX 3070 8 GiB VRAM + Ryzen 9 5900X + 16 GiB DDR4
//! Memory & Residency Bridge.
//!
//! Replaces Scarlett's `WriteWatch` + CPU `Shadow` buffer mirroring + 4095-slot
//! raw UAV memory directory with explicit PC D3D12 heaps:
//! - `DEFAULT` VRAM heap allocator with strict 8 GiB budget & LRU residency eviction
//! - `UPLOAD` fence-tracked PCIe write-combined ring buffer
//! - `READBACK` bounded ring for occasional GPU->CPU compaction queries
//! - `ScarlettVmTranslator` mapping `D3D12ConfigureVirtualMemoryX` & `XMemVirtualAlloc`
//!   flags (`0x20402000`, `0x21`/`0x03`, `0x801`) directly into PC heap placements.

use std::collections::{BTreeMap, VecDeque};

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * 1024 * 1024;

/// Target hardware profile used for budget and staging ring sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareProfile {
    pub vram_physical_bytes: u64,
    pub vram_usable_budget_bytes: u64,
    pub system_ram_bytes: u64,
    pub upload_ring_bytes: u64,
    pub readback_ring_bytes: u64,
    pub compact_host_ram: bool,
}

impl HardwareProfile {
    /// **LUCIAS PROJECT** target PC profile: RTX 3070 8 GiB GDDR6 + Ryzen 9 5900X + 16 GiB DDR4.
    /// Reserves ~992 MiB of local VRAM for WDDM / DWM / DXGI swapchain overhead
    /// and caps the UPLOAD staging ring at 192 MiB to preserve 16 GiB DDR4 headroom.
    pub const fn rtx3070_16gb_ddr4() -> Self {
        Self {
            vram_physical_bytes: 8 * GIB,
            vram_usable_budget_bytes: 7200 * MIB,
            system_ram_bytes: 16 * GIB,
            upload_ring_bytes: 192 * MIB,
            readback_ring_bytes: 16 * MIB,
            compact_host_ram: true,
        }
    }

    /// Display label formatted for LUCIAS PROJECT diagnostics and HUD overlays.
    pub const fn label(&self) -> &'static str {
        "LUCIAS PROJECT | RTX 3070 8GB | R9 5900X | 16GB DDR4"
    }
}

/// Exact `0x20`-byte layout passed to `d3d12_xs!D3D12ConfigureVirtualMemoryX`
/// verified at RVA `0x1e1cfa9..0x1e1cfe0`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScarlettVirtualMemoryConfig {
    pub flags: u32,
    pub page_table_pages: u32,
    pub preserved_bytes: u32,
    pub _pad: u32,
    pub lowest_gpu_va: u64,
    pub highest_gpu_va: u64,
}
const _: () = assert!(std::mem::size_of::<ScarlettVirtualMemoryConfig>() == 0x20);

/// Explicit PC D3D12 heap placement chosen for an `XMemVirtualAlloc` / `CreateCommittedResource` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcHeapPlacement {
    /// GPU-only / GPU-primary resources (`D3D12_HEAP_TYPE_DEFAULT`), e.g. protect `0x801` / flags `0x03`.
    DefaultVram { page_alignment: u64 },
    /// CPU-written / GPU-read dynamic data (`D3D12_HEAP_TYPE_UPLOAD` ring buffer), e.g. write-combined (`0x400`).
    UploadRing,
    /// Pure CPU-side pool (`VirtualAlloc2`, not shadowed to GPU unless explicitly copied).
    CpuSystemOnly,
    /// `D3D12_HEAP_TYPE_DEFAULT` aliasable placed heap (`XMemVirtualAlloc` `0x20402000` placeholder).
    AliasablePlacedHeap { granularity_bytes: u64 },
}

/// Translates Scarlett `D3D12ConfigureVirtualMemoryX` & `XMemVirtualAlloc` calls
/// to explicit PC D3D12 heap placements (zero `MEM_WRITE_WATCH`).
#[derive(Debug, Clone, Copy)]
pub struct ScarlettVmTranslator;

impl ScarlettVmTranslator {
    /// Fills PC 47-bit user VA bounds for `D3D12ConfigureVirtualMemoryX`.
    pub fn configure_virtual_memory(cfg: &mut ScarlettVirtualMemoryConfig) {
        cfg.lowest_gpu_va = 0x0000_0000_0001_0000;
        cfg.highest_gpu_va = 0x0000_7FFF_FFFE_FFFF;
    }

    /// Maps `XMemVirtualAlloc(size, kind, flags, protect)` observed at `0x1e1cfea` / `0x1e6c25d`
    /// onto PC heap placement without `MEM_WRITE_WATCH`.
    pub fn classify_xmem_alloc(kind: u32, flags: u64, protect: u32) -> PcHeapPlacement {
        const PAGES_2M: u32 = 0x2000_0000;
        const PAGES_64K_BIT: u32 = 0x0040_0000;
        const MEM_COMMIT: u32 = 0x0000_1000;
        const PROTECT_WRITE_COMBINE: u32 = 0x400;
        const PROTECT_GPU_ACCESS_MASK: u32 = 0x800; // e.g. 0x801 observed at 0x1e1d031
        const XMEM_GRAPHICS_BITS: u64 = 0x3;

        let is_64k_placeholder =
            (kind & (PAGES_2M | PAGES_64K_BIT)) == (PAGES_2M | PAGES_64K_BIT) && (kind & MEM_COMMIT) == 0;
        if is_64k_placeholder && (flags & XMEM_GRAPHICS_BITS) != 0 {
            return PcHeapPlacement::AliasablePlacedHeap {
                granularity_bytes: 64 * KIB,
            };
        }
        if (protect & PROTECT_WRITE_COMBINE) != 0 {
            return PcHeapPlacement::UploadRing;
        }
        if (protect & PROTECT_GPU_ACCESS_MASK) != 0 || (flags & XMEM_GRAPHICS_BITS) == 0x3 {
            let align = if (kind & PAGES_2M) != 0 {
                2 * MIB
            } else {
                64 * KIB
            };
            return PcHeapPlacement::DefaultVram {
                page_alignment: align,
            };
        }
        PcHeapPlacement::CpuSystemOnly
    }
}

/// One in-flight fence-tracked slice inside `UploadRingAllocator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadSlice {
    pub offset: u64,
    pub size: u64,
    pub fence_value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    RingFull { requested: u64, available: u64 },
    OutOfVramBudget { requested: u64, free_after_evict: u64 },
    InvalidAlignment,
    UnknownResource(u64),
}

/// Fence-reclaimed `D3D12_HEAP_TYPE_UPLOAD` ring buffer eliminating per-frame `E_OUTOFMEMORY`
/// buffer allocations and `WriteWatch` dirty checks.
#[derive(Debug)]
pub struct UploadRingAllocator {
    capacity: u64,
    head: u64,
    tail: u64,
    used: u64,
    in_flight: VecDeque<UploadSlice>,
}

impl UploadRingAllocator {
    pub fn new(capacity: u64) -> Self {
        assert!(capacity > 0 && capacity.is_power_of_two() || capacity >= 64 * KIB);
        Self {
            capacity,
            head: 0,
            tail: 0,
            used: 0,
            in_flight: VecDeque::new(),
        }
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn used_bytes(&self) -> u64 {
        self.used
    }

    pub fn free_bytes(&self) -> u64 {
        self.capacity - self.used
    }

    /// Suballocates `size` bytes aligned to `alignment` (power of two), tagged with `fence_value`.
    /// Automatically handles ring wraparound without splitting a single contiguous upload slice.
    pub fn allocate(
        &mut self,
        size: u64,
        alignment: u64,
        fence_value: u64,
    ) -> Result<UploadSlice, AllocError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(AllocError::InvalidAlignment);
        }
        if size == 0 {
            return Ok(UploadSlice {
                offset: self.head,
                size: 0,
                fence_value,
            });
        }
        if size > self.capacity {
            return Err(AllocError::RingFull {
                requested: size,
                available: self.free_bytes(),
            });
        }

        let align_mask = alignment - 1;
        let aligned_head = (self.head + align_mask) & !align_mask;

        if self.head >= self.tail {
            // Case 1: [tail .. head) is in use; free space is [head .. capacity) + [0 .. tail).
            let padding = aligned_head - self.head;
            if aligned_head + size <= self.capacity {
                let total = padding + size;
                self.head = (aligned_head + size) % self.capacity;
                self.used += total;
                let slice = UploadSlice {
                    offset: aligned_head,
                    size,
                    fence_value,
                };
                self.in_flight.push_back(UploadSlice {
                    offset: aligned_head - padding,
                    size: total,
                    fence_value,
                });
                return Ok(slice);
            }
            // Wrap around to offset 0; waste [head .. capacity) until tail passes it.
            let waste = self.capacity - self.head;
            if size <= self.tail {
                let total = waste + size;
                self.head = size;
                self.used += total;
                self.in_flight.push_back(UploadSlice {
                    offset: aligned_head.min(self.capacity),
                    size: total,
                    fence_value,
                });
                return Ok(UploadSlice {
                    offset: 0,
                    size,
                    fence_value,
                });
            }
            Err(AllocError::RingFull {
                requested: size,
                available: self.tail.max(self.capacity - self.head),
            })
        } else {
            // Case 2: wrapped; [0 .. head) and [tail .. capacity) are in use, free is [head .. tail).
            let padding = aligned_head - self.head;
            if aligned_head + size <= self.tail {
                let total = padding + size;
                self.head = aligned_head + size;
                self.used += total;
                self.in_flight.push_back(UploadSlice {
                    offset: aligned_head - padding,
                    size: total,
                    fence_value,
                });
                return Ok(UploadSlice {
                    offset: aligned_head,
                    size,
                    fence_value,
                });
            }
            Err(AllocError::RingFull {
                requested: size,
                available: self.tail - self.head,
            })
        }
    }

    /// Reclaims all upload slices whose GPU `fence_value <= completed_fence`.
    pub fn retire_fence(&mut self, completed_fence: u64) -> u64 {
        let mut freed = 0u64;
        while let Some(front) = self.in_flight.front() {
            if front.fence_value <= completed_fence {
                let item = self.in_flight.pop_front().unwrap();
                self.used = self.used.saturating_sub(item.size);
                freed += item.size;
                self.tail = (self.tail + item.size) % self.capacity;
            } else {
                break;
            }
        }
        if self.in_flight.is_empty() {
            self.head = 0;
            self.tail = 0;
            self.used = 0;
        }
        freed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Buffer,
    Texture2D,
    RenderTargetOrDepth,
    BvhAccelerationStructure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VramAllocation {
    pub handle: u64,
    pub kind: ResourceKind,
    pub size_bytes: u64,
    pub alignment: u64,
    pub resident: bool,
    pub pinned: bool,
    pub last_used_frame: u64,
}

/// Manages `D3D12_HEAP_TYPE_DEFAULT` VRAM residency within the RTX 3070 8 GiB budget,
/// tracking active allocations and evicting cold unpinned streaming resources (`Evict()`).
#[derive(Debug)]
pub struct DefaultVramResidencyManager {
    budget_bytes: u64,
    resident_bytes: u64,
    next_handle: u64,
    allocations: BTreeMap<u64, VramAllocation>,
    evictions_total: u64,
    bytes_evicted_total: u64,
}

impl DefaultVramResidencyManager {
    pub fn new(profile: HardwareProfile) -> Self {
        Self {
            budget_bytes: profile.vram_usable_budget_bytes,
            resident_bytes: 0,
            next_handle: 1,
            allocations: BTreeMap::new(),
            evictions_total: 0,
            bytes_evicted_total: 0,
        }
    }

    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    pub fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    pub fn evictions_total(&self) -> u64 {
        self.evictions_total
    }

    pub fn bytes_evicted_total(&self) -> u64 {
        self.bytes_evicted_total
    }

    /// Allocates a `DEFAULT` heap resource (aligning size to `alignment`, min 64 KiB).
    /// If resident VRAM would exceed `budget_bytes`, evicts oldest unpinned resources first.
    pub fn allocate(
        &mut self,
        kind: ResourceKind,
        raw_size: u64,
        alignment: u64,
        pinned: bool,
        frame: u64,
    ) -> Result<u64, AllocError> {
        let align = alignment.max(64 * KIB);
        if !align.is_power_of_two() {
            return Err(AllocError::InvalidAlignment);
        }
        let aligned_size = raw_size.max(align).next_multiple_of(align);

        if self.resident_bytes + aligned_size > self.budget_bytes {
            let needed = (self.resident_bytes + aligned_size) - self.budget_bytes;
            self.evict_lru(needed, frame);
        }

        if self.resident_bytes + aligned_size > self.budget_bytes {
            return Err(AllocError::OutOfVramBudget {
                requested: aligned_size,
                free_after_evict: self.budget_bytes.saturating_sub(self.resident_bytes),
            });
        }

        let handle = self.next_handle;
        self.next_handle += 1;
        self.resident_bytes += aligned_size;
        self.allocations.insert(
            handle,
            VramAllocation {
                handle,
                kind,
                size_bytes: aligned_size,
                alignment: align,
                resident: true,
                pinned,
                last_used_frame: frame,
            },
        );
        Ok(handle)
    }

    /// Marks an existing allocation as touched (MakeResident if previously evicted).
    pub fn touch(&mut self, handle: u64, frame: u64) -> Result<bool, AllocError> {
        let (was_resident, size_bytes) = {
            let entry = self
                .allocations
                .get(&handle)
                .ok_or(AllocError::UnknownResource(handle))?;
            (entry.resident, entry.size_bytes)
        };
        if !was_resident {
            if self.resident_bytes + size_bytes > self.budget_bytes {
                let needed = (self.resident_bytes + size_bytes) - self.budget_bytes;
                self.evict_lru(needed, frame);
            }
            if self.resident_bytes + size_bytes > self.budget_bytes {
                return Err(AllocError::OutOfVramBudget {
                    requested: size_bytes,
                    free_after_evict: self.budget_bytes.saturating_sub(self.resident_bytes),
                });
            }
            self.resident_bytes += size_bytes;
        }
        let entry = self.allocations.get_mut(&handle).unwrap();
        entry.resident = true;
        entry.last_used_frame = frame;
        Ok(!was_resident)
    }

    pub fn free(&mut self, handle: u64) -> Result<(), AllocError> {
        let entry = self
            .allocations
            .remove(&handle)
            .ok_or(AllocError::UnknownResource(handle))?;
        if entry.resident {
            self.resident_bytes = self.resident_bytes.saturating_sub(entry.size_bytes);
        }
        Ok(())
    }

    pub fn get(&self, handle: u64) -> Option<&VramAllocation> {
        self.allocations.get(&handle)
    }

    /// Evicts oldest unpinned resident allocations (not used in `current_frame`) until
    /// at least `bytes_needed` are reclaimed.
    fn evict_lru(&mut self, bytes_needed: u64, current_frame: u64) -> u64 {
        let mut candidates: Vec<(u64, u64, u64)> = self
            .allocations
            .values()
            .filter(|a| a.resident && !a.pinned && a.last_used_frame < current_frame)
            .map(|a| (a.last_used_frame, a.size_bytes, a.handle))
            .collect();
        candidates.sort_unstable_by_key(|&(frame, _, handle)| (frame, handle));

        let mut reclaimed = 0u64;
        for (_, size, handle) in candidates {
            if reclaimed >= bytes_needed {
                break;
            }
            if let Some(alloc) = self.allocations.get_mut(&handle) {
                alloc.resident = false;
                self.resident_bytes = self.resident_bytes.saturating_sub(size);
                self.evictions_total += 1;
                self.bytes_evicted_total += size;
                reclaimed += size;
            }
        }
        reclaimed
    }
}
