use std::mem::size_of;

use align_address::Align;
use bitflags::bitflags;
use hermit_entry::UhyveIfVersion;
use rand::Rng;
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};

use crate::{
	consts::{KERNEL_OFFSET, PAGETABLES_END, PAGETABLES_OFFSET, PGT_OFFSET},
	mem::MmapMemory,
	paging::{BumpAllocator, PagetableError},
};

pub(crate) const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x1000_0000);

const SIZE_4KIB: u64 = 0x1000;

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
const PAGE_SIZE: usize = 1 << PAGE_BITS;

/// Number of bits of the index in each table (L0Table, L1Table, L2Table, L3Table).
const PAGE_MAP_BITS: usize = 9;

/// A mask where PAGE_MAP_BITS are set to calculate a table index.
const PAGE_MAP_MASK: u64 = 0x1FF;

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
pub const TCR_TBI0: u64 = 1 << 37;
pub const TCR_TBI1: u64 = 1 << 38;
pub const TCR_ASID16: u64 = 1 << 36;
pub const TCR_TG1_16K: u64 = 1 << 30;
pub const TCR_TG1_4K: u64 = 0 << 30;
pub const TCR_FLAGS: u64 = TCR_IRGN_WBWA | TCR_ORGN_WBWA | TCR_SHARED;

/// Number of virtual address bits for 4KB page
pub const VA_BITS: u64 = 48;

/// Generates a random guest address for Uhyve's virtualized memory.
/// This function gets invoked when a new UhyveVM gets created, provided that the object file is relocatable.
pub(crate) fn generate_address(object_mem_size: usize) -> GuestPhysAddr {
	let mut rng = rand::rng();
	let start_address_upper_bound: u64 =
		0x0000_0010_0000_0000 - object_mem_size as u64 - KERNEL_OFFSET;

	GuestPhysAddr::new(
		rng.random_range(RAM_START.as_u64()..start_address_upper_bound)
			.align_down(0x20_0000),
	)
}

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
pub fn virt_to_phys(
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

pub fn init_guest_mem(
	mem: &mut [u8],
	guest_address: GuestPhysAddr,
	length: u64,
	_legacy_mapping: bool,
	_uhyve_interface_version: Option<UhyveIfVersion>,
) {
	let mem_addr = std::ptr::addr_of_mut!(mem[0]);

	assert!(mem.len() >= PGT_OFFSET as usize + 512 * size_of::<u64>());

	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(mem_addr.offset(PGT_OFFSET as isize) as *mut u64, 512)
	};
	pgt_slice.fill(0);
	pgt_slice[511] = (guest_address + PGT_OFFSET) | PT_PT | PT_SELF;

	let mut boot_frame_allocator = BumpAllocator::<SIZE_4KIB>::new(
		guest_address + PAGETABLES_OFFSET,
		(PAGETABLES_END - PAGETABLES_OFFSET) / SIZE_4KIB,
	);

	// Hypercalls are MMIO reads/writes in the lowest 4KiB of address space.
	// Thus, we need to provide pagetable entries for this region.
	let pgd0_addr = boot_frame_allocator.allocate().unwrap().as_u64();
	pgt_slice[0] = pgd0_addr | PT_PT;
	let pgd0_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset((pgd0_addr - guest_address.as_u64()) as isize) as *mut u64,
			512,
		)
	};
	pgd0_slice.fill(0);
	let pud0_addr = boot_frame_allocator.allocate().unwrap().as_u64();
	pgd0_slice[0] = pud0_addr | PT_PT;

	let pud0_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset((pud0_addr - guest_address.as_u64()) as isize) as *mut u64,
			512,
		)
	};
	pud0_slice.fill(0);
	let pmd0_addr = boot_frame_allocator.allocate().unwrap().as_u64();
	pud0_slice[0] = pmd0_addr | PT_PT;

	let pmd0_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset((pmd0_addr - guest_address.as_u64()) as isize) as *mut u64,
			512,
		)
	};
	pmd0_slice.fill(0);
	// Hypercall/IO mapping
	pmd0_slice[0] = guest_address | PT_MEM_CD;

	for frame_addr in (guest_address.align_down(SIZE_4KIB).as_u64()
		..(guest_address + length).align_up(SIZE_4KIB).as_u64())
		.step_by(SIZE_4KIB as usize)
	{
		let idx_l4 = (frame_addr as usize >> 39) & (0x1FF);
		let idx_l3 = (frame_addr as usize >> 30) & (0x1FF);
		let idx_l2 = (frame_addr as usize >> 21) & (0x1FF);
		let idx_l1 = (frame_addr as usize >> 12) & (0x1FF);
		debug!("mapping frame {frame_addr:x} to pagetable {idx_l4}-{idx_l3}-{idx_l2}-{idx_l1}");

		let (pgd_addr, new) = if pgt_slice[idx_l4] == 0 {
			(boot_frame_allocator.allocate().unwrap().as_u64(), true)
		} else {
			(
				PageTableEntry::from(pgt_slice[idx_l4]).address().as_u64(),
				false,
			)
		};
		let pgd_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((pgd_addr - guest_address.as_u64()) as isize) as *mut u64,
				512,
			)
		};
		if new {
			pgd_slice.fill(0);
			pgt_slice[idx_l4] = pgd_addr | PT_PT;
		}

		let (pud_addr, new) = if pgd_slice[idx_l3] == 0 {
			(boot_frame_allocator.allocate().unwrap().as_u64(), true)
		} else {
			(
				PageTableEntry::from(pgd_slice[idx_l3]).address().as_u64(),
				false,
			)
		};
		let pud_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((pud_addr - guest_address.as_u64()) as isize) as *mut u64,
				512,
			)
		};
		if new {
			pud_slice.fill(0);
			pgd_slice[idx_l3] = pud_addr | PT_PT;
		}

		let (pmd_addr, new) = if pud_slice[idx_l2] == 0 {
			(boot_frame_allocator.allocate().unwrap().as_u64(), true)
		} else {
			(
				PageTableEntry::from(pud_slice[idx_l2]).address().as_u64(),
				false,
			)
		};
		let pmd_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((pmd_addr - guest_address.as_u64()) as isize) as *mut u64,
				512,
			)
		};
		if new {
			pmd_slice.fill(0);
			pud_slice[idx_l2] = pmd_addr | PT_PT;
		}

		if idx_l1 == 0 && idx_l2 == 0 && idx_l3 == 0 && idx_l4 == 0 {
			// Hypercall/IO mapping
			pmd_slice[idx_l1] = frame_addr | PT_MEM_CD;
		} else if idx_l1 == 0 && idx_l2 == 0 && idx_l3 == 0 && idx_l4 < 16 {
			pmd_slice[idx_l1] = frame_addr | PT_MEM;
		} else {
			// set contiguous bit only if the page is mapped contiguous
			// and each 16 * 4 KByte area have the same access property
			pmd_slice[idx_l1] = frame_addr | PT_MEM_CONTIGUOUS;
		}
	}
}
