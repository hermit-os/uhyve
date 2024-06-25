use std::mem::size_of;

use bitflags::bitflags;
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};

use crate::{
	consts::{BOOT_INFO_ADDR_OFFSET, PGT_OFFSET},
	mem::MmapMemory,
	paging::PagetableError,
};

pub const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x00);

pub const PT_DEVICE: u64 = 0x707;
pub const PT_PT: u64 = 0x713;
pub const PT_MEM: u64 = 0x713;
pub const PT_MEM_CD: u64 = 0x70F;
pub const PT_SELF: u64 = 1 << 55;

/*
 * Memory types available.
 */
#[allow(non_upper_case_globals)]
pub const MT_DEVICE_nGnRnE: u64 = 0;
#[allow(non_upper_case_globals)]
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
		GuestPhysAddr(
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
	virtual_address < GuestVirtAddr(0x1_0000_0000_0000)
}

/// Converts a virtual address in the guest to a physical address in the guest
pub fn virt_to_phys(
	addr: GuestVirtAddr,
	mem: &MmapMemory,
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
		std::mem::transmute::<&[u8], &[PageTableEntry]>(
			mem.slice_at(mem.guest_address, PAGE_SIZE).unwrap(),
		)
	};
	// TODO: Depending on the virtual address length and granule (defined in TCR register by TG and TxSZ), we could reduce the number of pagetable walks. Hermit doesn't do this at the moment.
	for level in 0..3 {
		let table_index =
			(addr.as_u64() >> PAGE_BITS >> ((3 - level) * PAGE_MAP_BITS) & PAGE_MAP_MASK) as usize;
		let pte = PageTableEntry::from(pagetable[table_index]);
		// TODO: We could stop here if we have a "Block Entry" (ARM equivalent to huge page). Currently not supported.

		pagetable = unsafe {
			std::mem::transmute::<&[u8], &[PageTableEntry]>(
				mem.slice_at(pte.address(), PAGE_SIZE).unwrap(),
			)
		};
	}
	let table_index = (addr.as_u64() >> PAGE_BITS & PAGE_MAP_MASK) as usize;
	let pte = PageTableEntry::from(pagetable[table_index]);

	Ok(pte.address())
}

pub fn init_guest_mem(mem: &mut [u8], _guest_address: u64) {
	let mem_addr = std::ptr::addr_of_mut!(mem[0]);

	assert!(mem.len() >= PGT_OFFSET as usize + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(mem_addr.offset(PGT_OFFSET as isize) as *mut u64, 512)
	};
	pgt_slice.fill(0);
	pgt_slice[0] = PGT_OFFSET + 0x1000 + PT_PT;
	pgt_slice[511] = PGT_OFFSET + PT_PT + PT_SELF;

	assert!(mem.len() >= PGT_OFFSET as usize + 0x1000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(PGT_OFFSET as isize + 0x1000) as *mut u64,
			512,
		)
	};
	pgt_slice.fill(0);
	pgt_slice[0] = PGT_OFFSET + 0x2000 + PT_PT;

	assert!(mem.len() >= PGT_OFFSET as usize + 0x2000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(PGT_OFFSET as isize + 0x2000) as *mut u64,
			512,
		)
	};
	pgt_slice.fill(0);
	pgt_slice[0] = PGT_OFFSET + 0x3000 + PT_PT;
	pgt_slice[1] = PGT_OFFSET + 0x4000 + PT_PT;
	pgt_slice[2] = PGT_OFFSET + 0x5000 + PT_PT;

	assert!(mem.len() >= PGT_OFFSET as usize + 0x3000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(PGT_OFFSET as isize + 0x3000) as *mut u64,
			512,
		)
	};
	pgt_slice.fill(0);
	// map Uhyve ports into the virtual address space
	pgt_slice[0] = PT_MEM_CD;
	// map BootInfo into the virtual address space
	pgt_slice[BOOT_INFO_ADDR_OFFSET as usize / PAGE_SIZE] = BOOT_INFO_ADDR_OFFSET + PT_MEM;

	assert!(mem.len() >= PGT_OFFSET as usize + 0x4000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(PGT_OFFSET as isize + 0x4000) as *mut u64,
			512,
		)
	};
	for (idx, i) in pgt_slice.iter_mut().enumerate() {
		*i = 0x200000u64 + (idx * PAGE_SIZE) as u64 + PT_MEM;
	}

	assert!(mem.len() >= PGT_OFFSET as usize + 0x5000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(PGT_OFFSET as isize + 0x5000) as *mut u64,
			512,
		)
	};
	for (idx, i) in pgt_slice.iter_mut().enumerate() {
		*i = 0x400000u64 + (idx * PAGE_SIZE) as u64 + PT_MEM;
	}
}
