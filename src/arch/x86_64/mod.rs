mod paging;
pub(crate) mod registers;

use paging::initialize_pagetables;
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};
use x86_64::structures::paging::{
	page_table::{FrameError, PageTableEntry},
	PageTable, PageTableIndex,
};

use crate::{mem::MmapMemory, paging::PagetableError};

pub const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x00);

/// Converts a virtual address in the guest to a physical address in the guest
pub fn virt_to_phys(
	addr: GuestVirtAddr,
	mem: &MmapMemory,
	pagetable_l0: GuestPhysAddr,
) -> Result<GuestPhysAddr, PagetableError> {
	/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
	pub const PAGE_BITS: u64 = 12;

	/// Number of bits of the index in each table (PML4, PDPT, PDT, PGT).
	pub const PAGE_MAP_BITS: usize = 9;

	let mut page_table =
		unsafe { (mem.host_address(pagetable_l0).unwrap() as *mut PageTable).as_mut() }.unwrap();
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

pub fn init_guest_mem(mem: &mut [u8]) {
	// TODO: we should maybe return an error on failure (e.g., the memory is too small)
	initialize_pagetables(mem);
}

#[cfg(test)]
mod tests {
	use x86_64::structures::paging::PageTableFlags;

	use super::*;
	use crate::consts::{BOOT_PDE, BOOT_PDPTE, BOOT_PML4};

	#[test]
	fn test_virt_to_phys() {
		let _ = env_logger::builder()
			.filter(None, log::LevelFilter::Trace)
			.is_test(true)
			.try_init();

		let mem = MmapMemory::new(
			0,
			align_up!(paging::MIN_PHYSMEM_SIZE * 2, 0x20_0000),
			GuestPhysAddr::zero(),
			true,
			true,
		);
		println!("mmap memory created {mem:?}");
		initialize_pagetables(unsafe { mem.as_slice_mut() }.try_into().unwrap());

		// Get the address of the first entry in PML4 (the address of the PML4 itself)
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000);
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(p_addr, BOOT_PML4);

		// The last entry on the PML4 is the address of the PML4 with flags
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000 | (4096 - 8));
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(
			mem.read::<u64>(p_addr).unwrap(),
			BOOT_PML4.as_u64() | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);

		// the first entry on the 3rd level entry in the pagetables is the address of the boot pdpte
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFE00000);
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(p_addr, BOOT_PDPTE);

		// the first entry on the 2rd level entry in the pagetables is the address of the boot pde
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFC0000000);
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(p_addr, BOOT_PDE);
		// That address points to a huge page
		assert!(
			PageTableFlags::from_bits_truncate(mem.read::<u64>(p_addr).unwrap()).contains(
				PageTableFlags::HUGE_PAGE | PageTableFlags::PRESENT | PageTableFlags::WRITABLE
			)
		);
	}
}
