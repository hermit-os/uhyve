mod paging;
pub(crate) mod registers;

use align_address::Align;
use hermit_entry::UhyveIfVersion;
use paging::initialize_pagetables;
use rand::Rng;
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};
use x86_64::structures::paging::{
	PageTable, PageTableIndex,
	page_table::{FrameError, PageTableEntry},
};

use crate::{consts::KERNEL_OFFSET, mem::MmapMemory, paging::PagetableError};

pub const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x00);

/// Generates a random guest address for Uhyve's virtualized memory.
/// This function gets invoked when a new UhyveVM gets created, provided that the object file is relocatable.
pub(crate) fn generate_address(object_mem_size: usize) -> GuestPhysAddr {
	let mut rng = rand::rng();
	// TODO: Also allow mappings beyond the 32 Bit gap
	let start_address_upper_bound: u64 =
		0x0000_0000_CFF0_0000 - object_mem_size as u64 - KERNEL_OFFSET;

	GuestPhysAddr::new(
		rng.random_range(0x0..start_address_upper_bound)
			.align_down(0x20_0000),
	)
}

/// Converts a virtual address in the guest to a physical address in the guest
pub fn virt_to_phys(
	addr: GuestVirtAddr,
	mem: &MmapMemory,
	pml4: GuestPhysAddr,
) -> Result<GuestPhysAddr, PagetableError> {
	/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
	pub const PAGE_BITS: u64 = 12;

	/// Number of bits of the index in each table (PML4, PDPT, PDT, PGT).
	pub const PAGE_MAP_BITS: usize = 9;

	let mut page_table =
		unsafe { (mem.host_address(pml4).unwrap() as *mut PageTable).as_mut() }.unwrap();
	let mut page_bits = 39;
	let mut entry = PageTableEntry::new();

	for _i in 0..4 {
		let index =
			PageTableIndex::new(((addr.as_u64() >> page_bits) & ((1 << PAGE_MAP_BITS) - 1)) as u16);
		entry = page_table[index].clone();

		match entry.frame() {
			Ok(frame) => {
				page_table = unsafe {
					(mem.host_address(frame.start_address().into()).unwrap() as *mut PageTable)
						.as_mut()
				}
				.unwrap();
				page_bits -= PAGE_MAP_BITS;
			}
			Err(FrameError::FrameNotPresent) => return Err(PagetableError::InvalidAddress),
			Err(FrameError::HugeFrame) => {
				return Ok((entry.addr() + (addr.as_u64() & !((!0_u64) << page_bits))).into());
			}
		}
	}

	Ok((entry.addr() + (addr.as_u64() & !((!0u64) << PAGE_BITS))).into())
}

pub fn init_guest_mem(
	mem: &mut [u8],
	guest_address: GuestPhysAddr,
	length: u64,
	legacy_mapping: bool,
	uhyve_interface_version: Option<UhyveIfVersion>,
) {
	// TODO: we should maybe return an error on failure (e.g., the memory is too small)
	initialize_pagetables(
		mem,
		guest_address,
		length,
		legacy_mapping,
		uhyve_interface_version,
	);
}

#[cfg(test)]
mod tests {
	use x86_64::structures::paging::PageTableFlags;

	use super::*;
	use crate::consts::{MIN_PHYSMEM_SIZE, PAGETABLES_END, PAGETABLES_OFFSET, PML4_OFFSET};

	#[test]
	fn test_virt_to_phys() {
		let _ = env_logger::builder()
			.filter(None, log::LevelFilter::Trace)
			.is_test(true)
			.try_init();

		let guest_address = GuestPhysAddr::new(0x11111000);

		let mem = MmapMemory::new(0, MIN_PHYSMEM_SIZE * 2, guest_address, true, true);
		println!("mmap memory created {mem:x?}");

		init_guest_mem(
			unsafe { mem.as_slice_mut() },
			guest_address,
			MIN_PHYSMEM_SIZE as u64 * 2,
			false,
			Some(UhyveIfVersion(1)),
		);

		// Get the address of the first entry in PML4 (the address of the PML4 itself)
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000);
		let p_addr = virt_to_phys(virt_addr, &mem, guest_address + PML4_OFFSET).unwrap();
		assert_eq!(p_addr, guest_address + PML4_OFFSET);

		// The last entry on the PML4 is the address of the PML4 with flags
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000 | (4096 - 8));
		let p_addr = virt_to_phys(virt_addr, &mem, guest_address + PML4_OFFSET).unwrap();
		assert_eq!(
			mem.read::<u64>(p_addr).unwrap(),
			(guest_address + PML4_OFFSET).as_u64()
				| (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);

		// the first entry on the 3rd level entry in the pagetables is the address of the boot pdpte
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFE00000);
		let p_addr = virt_to_phys(virt_addr, &mem, guest_address + PML4_OFFSET).unwrap();
		assert!(p_addr.as_u64() - guest_address.as_u64() >= PAGETABLES_OFFSET);
		assert!(p_addr.as_u64() - guest_address.as_u64() <= PAGETABLES_END);

		// the idx2 entry on the 2rd level entry in the pagetables is the address of the boot pde
		let idx2 = GuestVirtAddr::new(guest_address.as_u64()).p2_index();
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFC0000000)
			+ u64::from(idx2) * size_of::<PageTableEntry>() as u64;
		let p_addr = virt_to_phys(virt_addr, &mem, guest_address + PML4_OFFSET).unwrap();
		assert!(p_addr.as_u64() - guest_address.as_u64() >= PAGETABLES_OFFSET);
		assert!(p_addr.as_u64() - guest_address.as_u64() <= PAGETABLES_END);
		// That address points to a huge page
		assert!(
			PageTableFlags::from_bits_truncate(mem.read::<u64>(p_addr).unwrap()).contains(
				PageTableFlags::HUGE_PAGE | PageTableFlags::PRESENT | PageTableFlags::WRITABLE
			)
		);
	}
}
