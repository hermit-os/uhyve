pub(crate) mod breakpoints;

use std::{fmt::Display, mem::size_of};

use align_address::Align;
use bitflags::bitflags;
use hermit_entry::{UhyveIfVersion, elf::KernelObject};
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};

use crate::{
	mem::MmapMemory,
	mem_layout::{
		BootInfoSection, FdtSection, KernelSection, MemoryLayout, PagetableSection, Section,
		StackSection, generate_guest_start_address,
	},
	paging::{BumpAllocator, PagetableError},
	params::Params,
};

pub(crate) const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x1000_0000);
pub(crate) const V1_MAX_ADDR: u64 = 0x0010_0000_0000u64;
pub(crate) const V1_ADDR_RANGE: (u64, u64) = (RAM_START.as_u64(), V1_MAX_ADDR);
pub(crate) const V2_ADDR_RANGE: (u64, u64) = (0x0001_0000_0000u64, 0x0010_0000_0000u64);

const SIZE_4KIB: u64 = 0x1000;
pub(crate) const GUEST_PAGE_SIZE: u64 = SIZE_4KIB;

/// Pages of the identity mapped MMIO window through which hypercalls are issued.
///
/// Large enough to cover every [`v1`](uhyve_interface::v1::HypercallAddress) and
/// [`v2`](uhyve_interface::v2::HypercallAddress) hypercall address.
pub(crate) const HYPERCALL_WINDOW_PAGES: usize = 2;

// PageTableEntry Flags
/// Present + 4KiB + device memory + inner_sharable + accessed
pub const PT_DEVICE: u64 = 0b11100000111;
/// Present + 4KiB + normal + inner_sharable + accessed
pub const PT_PT: u64 = 0b11100010011;
/// Present + 4KiB + normal + inner_sharable + accessed
pub const PT_MEM: u64 = 0b11100010011;
/// Present + 4KiB + normal + inner_sharable + accessed + contiguous
pub const PT_MEM_CONTIGUOUS: u64 = 0b11100010011 | 1 << 52;
/// Present + 4KiB + device + inner_sharable + accessed + non-cacheable
pub const PT_MEM_CD: u64 = 0b11100001111;
/// Self reference flag
pub const PT_SELF: u64 = 1 << 55;

/*
 * Memory types available.
 */
#[expect(non_upper_case_globals)]
pub const MT_DEVICE_nGnRnE: u64 = 0;
#[expect(non_upper_case_globals)]
pub const MT_DEVICE_nGnRE: u64 = 1;
pub const MT_DEVICE_GRE: u64 = 2;
pub const MT_NORMAL_NC: u64 = 3;
pub const MT_NORMAL: u64 = 4;

/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
const PAGE_BITS: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;

/// Number of bits of the index in each table (L0Table, L1Table, L2Table, L3Table).
const PAGE_MAP_BITS: usize = 9;

/// A mask where PAGE_MAP_BITS are set to calculate a table index.
const PAGE_MAP_MASK: u64 = 0x1FF;

pub(crate) const GICD_BASE_ADDRESS: u64 = 0x800_0000;
pub(crate) const GICD_SIZE: usize = 0x10000;
pub(crate) const GICR_BASE_ADDRESS: u64 = 0x80A_0000;
pub(crate) const GICR_SIZE: usize = 0xf60000;
pub(crate) const MSI_BASE_ADDRESS: u64 = 0x808_0000;
pub(crate) const MSI_SIZE: usize = 0x20000;

#[inline(always)]
pub const fn mair(attr: u64, mt: u64) -> u64 {
	attr << (mt * 8)
}

/*
 * TCR flags
 */
pub const TCR_IRGN_WBWA: u64 = ((1) << 8) | ((1) << 24);
pub const TCR_ORGN_WBWA: u64 = ((1) << 10) | ((1) << 26);
pub const TCR_SHARED: u64 = ((3) << 12) | ((3) << 28);
pub const _TCR_TBI0: u64 = 1 << 37;
pub const _TCR_TBI1: u64 = 1 << 38;
pub const _TCR_ASID16: u64 = 1 << 36;
pub const _TCR_TG1_16K: u64 = 1 << 30;
pub const TCR_TG1_4K: u64 = 0 << 30;
pub const TCR_FLAGS: u64 = TCR_IRGN_WBWA | TCR_ORGN_WBWA | TCR_SHARED;

/// Number of virtual address bits for 4KB page
pub const VA_BITS: u64 = 48;

#[inline(always)]
pub const fn tcr_size(x: u64) -> u64 {
	((64 - x) << 16) | (64 - x)
}

bitflags! {
	pub struct PSR: u64 {
		const MODE_EL1H	= 0x00000005;
		/// FIQ mask bit
		const F_BIT	= 0x00000040;
		/// IRQ mask bit
		const I_BIT	= 0x00000080;
		/// SError mask bit
		const A_BIT	= 0x00000100;
		/// Debug mask bit
		const D_BIT	= 0x00000200;
	}
}

/// An entry in a L0 page table (coarses). Adapted from hermit-os/kernel.
#[derive(Clone, Copy, Debug)]
struct PageTableEntry {
	/// Physical memory address this entry refers, combined with flags from PageTableEntryFlags.
	physical_address_and_flags: GuestPhysAddr,
}

impl PageTableEntry {
	/// Return the stored physical address.
	pub fn address(&self) -> GuestPhysAddr {
		// For other granules than 4KiB or hugepages we should check the DESCRIPTOR_TYPE bit and modify the address translation accordingly.
		GuestPhysAddr::new(
			self.physical_address_and_flags.as_u64() & !(PAGE_SIZE as u64 - 1) & !(u64::MAX << 48),
		)
	}
}
impl From<u64> for PageTableEntry {
	fn from(i: u64) -> Self {
		Self {
			physical_address_and_flags: GuestPhysAddr::new(i),
		}
	}
}

/// Returns whether the given virtual address is a valid one in the AArch64 memory model.
///
/// Current AArch64 supports only 48-bit for virtual memory addresses.
/// The upper bits must always be 0 or 1 and indicate whether TBBR0 or TBBR1 contains the
/// base address. So always enforce 0 here.
fn is_valid_address(virtual_address: GuestVirtAddr) -> bool {
	virtual_address < GuestVirtAddr::new(0x1_0000_0000_0000)
}

/// Converts a virtual address in the guest to a physical address in the guest
pub(crate) fn virt_to_phys(
	addr: GuestVirtAddr,
	mem: &MmapMemory,
	pgt: GuestPhysAddr,
) -> Result<GuestPhysAddr, PagetableError> {
	if !is_valid_address(addr) {
		return Err(PagetableError::InvalidAddress);
	}

	// Assumptions:
	// - We use 4KiB granule
	// - We use maximum VA length
	// => We have 4 level paging

	// Safety:
	// - We are only working in the vm's memory
	// - the memory location of the pagetable is not altered by hermit.
	// - Our indices can't be larger than 512, so we stay in the borders of the page.
	// - We are page_aligned, and thus also PageTableEntry aligned.
	let mut pagetable: &[PageTableEntry] = unsafe {
		std::mem::transmute::<&[u8], &[PageTableEntry]>(mem.slice_at(pgt, PAGE_SIZE).unwrap())
	};
	// TODO: Depending on the virtual address length and granule (defined in TCR register by TG and TxSZ), we could reduce the number of pagetable walks. Hermit doesn't do this at the moment.
	for level in 0..3 {
		let table_index = ((addr.as_u64() >> PAGE_BITS >> ((3 - level) * PAGE_MAP_BITS))
			& PAGE_MAP_MASK) as usize;
		let pte = pagetable[table_index];
		// TODO: We could stop here if we have a "Block Entry" (ARM equivalent to huge page). Currently not supported.

		pagetable = unsafe {
			std::mem::transmute::<&[u8], &[PageTableEntry]>(
				mem.slice_at(pte.address(), PAGE_SIZE).unwrap(),
			)
		};
	}
	let table_index = ((addr.as_u64() >> PAGE_BITS) & PAGE_MAP_MASK) as usize;
	let pte = pagetable[table_index];

	Ok(pte.address() + (addr.as_u64() & !((!0u64) << PAGE_BITS)))
}

pub(crate) fn init_guest_mem(mem: &mut MmapMemory, layout: &Aarch64MemoryLayout, length: u64) {
	const PT_SIZE: usize = 512 * size_of::<u64>();
	assert!(mem.guest_addr() + mem.size() >= layout.pgt_address() + PT_SIZE);

	let pgt_slice = unsafe { mem.get_ref_mut::<[u64; 512]>(layout.pgt_address()).unwrap() };
	pgt_slice.fill(0);
	pgt_slice[511] = layout.pgt_address() | PT_PT | PT_SELF;

	let mut boot_frame_allocator = BumpAllocator::<SIZE_4KIB>::new(
		layout.pagetables().0.start(),
		layout.pagetables().0.length as u64 / SIZE_4KIB,
	);

	// Hypercalls are MMIO reads/writes in the lowest pages of the address space.
	// Thus, we need to provide pagetable entries for this region.
	let pgd0_addr = boot_frame_allocator.allocate().unwrap().as_u64();
	pgt_slice[0] = pgd0_addr | PT_PT;

	let pgd0_slice = unsafe { mem.get_ref_mut::<[u64; 512]>(pgd0_addr.into()).unwrap() };
	pgd0_slice.fill(0);
	let pud0_addr = boot_frame_allocator.allocate().unwrap().as_u64();
	pgd0_slice[0] = pud0_addr | PT_PT;

	let pud0_slice = unsafe { mem.get_ref_mut::<[u64; 512]>(pud0_addr.into()).unwrap() };
	pud0_slice.fill(0);
	let pmd0_addr = boot_frame_allocator.allocate().unwrap().as_u64();
	pud0_slice[0] = pmd0_addr | PT_PT;

	let pmd0_slice = unsafe { mem.get_ref_mut::<[u64; 512]>(pmd0_addr.into()).unwrap() };
	pmd0_slice.fill(0);
	// Hypercall/IO mapping.
	//
	// This is identity mapped rather than pointing into guest RAM: the v2
	// hypercall addresses reach into the second page, which would otherwise
	// collide with the FDT. Identity mapping keeps the whole window below
	// `RAM_START`, where nothing ever backs it, so every access traps out.
	//
	// Device memory, so the abort carries a valid instruction syndrome. Normal
	// memory permits a syndrome-less abort, which a hypervisor cannot decode.
	for (page, entry) in pmd0_slice[..HYPERCALL_WINDOW_PAGES].iter_mut().enumerate() {
		*entry = (page as u64 * SIZE_4KIB) | PT_DEVICE;
	}

	for frame_addr in (layout.guest_address().align_down(SIZE_4KIB).as_u64()
		..(layout.guest_address() + length)
			.align_up(SIZE_4KIB)
			.as_u64())
		.step_by(SIZE_4KIB as usize)
	{
		let frame_addr_usz = frame_addr as usize;
		let indices = [
			/* idx_l4 */ frame_addr_usz >> 39,
			/* idx_l3 */ frame_addr_usz >> 30,
			/* idx_l2 */ frame_addr_usz >> 21,
			/* idx_l1 */ frame_addr_usz >> 12,
		]
		.map(|i| i & 0x1FF);
		let (idx_l4, idx_l3, idx_l2, idx_l1) = (indices[0], indices[1], indices[2], indices[3]);

		debug!("mapping frame {frame_addr:x} to pagetable {idx_l4}-{idx_l3}-{idx_l2}-{idx_l1}");

		let pmd_slice = indices[0..3]
			.iter()
			.fold(&mut *pgt_slice, |prev_slice, &idx| {
				let (pd_addr, new) = if prev_slice[idx] == 0 {
					(boot_frame_allocator.allocate().unwrap().as_u64(), true)
				} else {
					(
						PageTableEntry::from(prev_slice[idx]).address().as_u64(),
						false,
					)
				};
				let pd_slice = unsafe { mem.get_ref_mut::<[u64; 512]>(pd_addr.into()).unwrap() };
				if new {
					pd_slice.fill(0);
					prev_slice[idx] = pd_addr | PT_PT;
				}
				pd_slice
			});

		pmd_slice[idx_l1] = frame_addr
			| if idx_l1 == 0 && idx_l2 == 0 && idx_l3 == 0 && idx_l4 == 0 {
				// Hypercall/IO mapping
				PT_MEM_CD
			} else if idx_l1 == 0 && idx_l2 == 0 && idx_l3 == 0 && idx_l4 < 16 {
				PT_MEM
			} else {
				// set contiguous bit only if the page is mapped contiguous
				// and each 16 * 4 KByte area have the same access property
				PT_MEM_CONTIGUOUS
			};
	}
}

/// aarch64 Memory Layout.
///
/// It looks as follows:
///
/// ```txt
///     0x0000_0000 ┌──────────────────────────┐
///                 │ Hypercalls               │
///                 ├──────────────────────────┤
///                 │ not present              │
///                 │                          │
///    guest_address├──────────────────────────┤ ▲ ▲ ▲ ▲
///                 │                          │ │ │ │ │ FDT_OFFSET
///                 ├──────────────────────────┤ │ │ │ ▼
///                 │ Device Tree (FDT) (4KiB) │ │ │ │ BOOT_INFO_OFFSET
///                 ├──────────────────────────┤ │ │ ▼
///                 │ Boot Info         (1KiB) │ │ │
///                 ├──────────────────────────┤ │ │
///                 │                          │ │ │PAGETABLES_OFFSET
///                 ├──────────────────────────┤ │ ▼
///                 │                          │ │
///                 │ Pagetables               │ │
///                 │                          │ │
///    stack_address├──────────────────────────┤ │
///                 │ Stack                    │ │KERNEL_OFFSET
///   kernel_address├──────────────────────────┤ ▼
///                 │ Kernel                   │
///   entry_point──►│                          │
///                 │                          │
///                 ├──────────────────────────┤
///                 │ Kernel Memory            │
///                 │                          │
///                 └──────────────────────────┘
/// ```
#[derive(Debug, Copy, Clone)]
pub(crate) struct Aarch64MemoryLayout {
	guest_address: GuestPhysAddr,
	kernel_address: GuestPhysAddr,
	kernel_len: usize,
}
impl Aarch64MemoryLayout {
	const FDT_OFFSET: u64 = 0x1000;
	const FDT_SIZE: usize = 4 * PAGE_SIZE;
	const BOOT_INFO_OFFSET: u64 = Self::FDT_OFFSET + Self::FDT_SIZE as u64;

	const PAGETABLES_OFFSET: u64 = 0x11000;
	const PAGETABLES_END: u64 = Self::KERNEL_OFFSET - Self::KERNEL_STACK_SIZE;
	const KERNEL_STACK_SIZE: u64 = 0x8000;
	pub(crate) const KERNEL_OFFSET: u64 = 0x40000;

	pub const PGT_OFFSET: u64 = 0x10000;

	pub fn pgt_address(&self) -> GuestPhysAddr {
		self.guest_address() + Self::PGT_OFFSET
	}
}
impl MemoryLayout for Aarch64MemoryLayout {
	fn new(params: &Params, object: &KernelObject<'_>) -> Self {
		let uhyve_interface_version = object
			.uhyve_interface_version()
			.unwrap_or(UhyveIfVersion(1));

		let memory_size = params.memory_size.get();

		let (guest_address, kernel_address) = generate_guest_start_address(
			uhyve_interface_version,
			params.aslr,
			object.mem_size(),
			object.start_addr(),
			memory_size,
			Self::KERNEL_OFFSET,
		);

		assert!(
			kernel_address.as_u64() > Self::KERNEL_STACK_SIZE,
			"there should be enough space for the boot stack before the kernel start address",
		);

		Self {
			guest_address,
			kernel_address,
			kernel_len: object.mem_size(),
		}
	}

	fn guest_address(&self) -> GuestPhysAddr {
		self.guest_address
	}

	fn stack(&self) -> StackSection {
		StackSection(Section {
			addr: self.kernel_address - Self::KERNEL_STACK_SIZE,
			length: Self::KERNEL_STACK_SIZE as usize,
		})
	}

	fn fdt(&self) -> FdtSection {
		FdtSection(Section {
			addr: self.guest_address + Self::FDT_OFFSET,
			length: Self::FDT_SIZE,
		})
	}

	fn boot_info(&self) -> BootInfoSection {
		BootInfoSection(Section {
			addr: self.guest_address + Self::BOOT_INFO_OFFSET,
			length: PAGE_SIZE,
		})
	}

	fn kernel(&self) -> KernelSection {
		KernelSection(Section {
			addr: self.kernel_address,
			length: self.kernel_len,
		})
	}

	fn pagetables(&self) -> crate::mem_layout::PagetableSection {
		PagetableSection(Section {
			addr: self.guest_address + Self::PAGETABLES_OFFSET,
			length: (Self::PAGETABLES_END - Self::PAGETABLES_OFFSET) as usize,
		})
	}
}
impl Display for Aarch64MemoryLayout {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "Memory Layout:")?;
		writeln!(f, "guest_address:     {:12x}", self.guest_address())?;
		writeln!(f, "boot_info_address: {:12x}", self.boot_info().0.addr)?;
		writeln!(f, "fdt_address:       {:12x}", self.fdt().0.addr)?;
		writeln!(f, "stack_address:     {:12x}", self.stack().0.addr)?;
		writeln!(f, "kernel_address:    {:12x}", self.kernel().0.addr)?;
		writeln!(
			f,
			"guest_heap:        {:12x}",
			self.kernel().0.addr + self.kernel_len
		)
	}
}
