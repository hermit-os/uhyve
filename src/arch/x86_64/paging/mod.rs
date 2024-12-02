use x86_64::{
	structures::paging::{Page, PageTable, PageTableFlags, Size2MiB},
	PhysAddr,
};

use crate::consts::*;

// Constructor for a conventional segment GDT (or LDT) entry
pub fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
	((base & 0xff000000u64) << (56 - 24))
		| ((flags & 0x0000f0ffu64) << 40)
		| ((limit & 0x000f0000u64) << (48 - 16))
		| ((base & 0x00ffffffu64) << 16)
		| (limit & 0x0000ffffu64)
}

pub const MIN_PHYSMEM_SIZE: usize = BOOT_PDE.as_u64() as usize + 0x1000;

/// Creates the pagetables and the GDT in the guest memory space.
///
/// The memory slice must be larger than [`MIN_PHYSMEM_SIZE`].
/// Also, the memory `mem` needs to be zeroed for [`PAGE_SIZE`] bytes at the
/// offsets [`BOOT_PML4`] and [`BOOT_PDPTE`], otherwise the integrity of the
/// pagetables and thus the integrity of the guest's memory is not ensured
pub fn initialize_pagetables(mem: &mut [u8]) {
	assert!(mem.len() >= MIN_PHYSMEM_SIZE);
	let mem_addr = std::ptr::addr_of_mut!(mem[0]);

	let (gdt_entry, pml4, pdpte, pde);
	// Safety:
	// We only operate in `mem`, which is plain bytes and we have ownership of
	// these and it is asserted to be large enough.
	unsafe {
		gdt_entry = mem_addr
			.add(BOOT_GDT.as_u64() as usize)
			.cast::<[u64; 3]>()
			.as_mut()
			.unwrap();

		pml4 = mem_addr
			.add(BOOT_PML4.as_u64() as usize)
			.cast::<PageTable>()
			.as_mut()
			.unwrap();
		pdpte = mem_addr
			.add(BOOT_PDPTE.as_u64() as usize)
			.cast::<PageTable>()
			.as_mut()
			.unwrap();
		pde = mem_addr
			.add(BOOT_PDE.as_u64() as usize)
			.cast::<PageTable>()
			.as_mut()
			.unwrap();

		/* For simplicity we currently use 2MB pages and only a single
		PML4/PDPTE/PDE. */

		// per default is the memory zeroed, which we allocate by the system
		// call mmap, so the following is not necessary:
		/*libc::memset(pml4 as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
		libc::memset(pdpte as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
		libc::memset(pde as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);*/
	}
	// initialize GDT
	gdt_entry[BOOT_GDT_NULL] = 0;
	gdt_entry[BOOT_GDT_CODE] = create_gdt_entry(0xA09B, 0, 0xFFFFF);
	gdt_entry[BOOT_GDT_DATA] = create_gdt_entry(0xC093, 0, 0xFFFFF);

	pml4[0].set_addr(
		BOOT_PDPTE.into(),
		PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
	);
	pml4[511].set_addr(
		BOOT_PML4.into(),
		PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
	);
	pdpte[0].set_addr(
		BOOT_PDE.into(),
		PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
	);

	for i in 0..512 {
		let addr = PhysAddr::new(i as u64 * Page::<Size2MiB>::SIZE);
		pde[i].set_addr(
			addr,
			PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
		);
	}
}

#[allow(dead_code)]
/// Helper fn for debugging pagetables
fn pretty_print_pagetable(pt: &PageTable) {
	println!("Idx       Address          Idx       Address          Idx       Address          Idx       Address      ");
	println!("--------------------------------------------------------------------------------------------------------");
	for i in (0..512).step_by(4) {
		println!(
			"{:3}: {:#18x},   {:3}: {:#18x},   {:3}: {:#18x},   {:3}: {:#18x}",
			i,
			pt[i].addr(),
			i + 1,
			pt[i + 1].addr(),
			i + 2,
			pt[i + 2].addr(),
			i + 3,
			pt[i + 3].addr()
		);
	}
	println!("--------------------------------------------------------------------------------------------------------");
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pagetable_initialization() {
		let _ = env_logger::builder()
			.filter(None, log::LevelFilter::Debug)
			.is_test(true)
			.try_init();

		let mut mem: Vec<u8> = vec![0; MIN_PHYSMEM_SIZE];
		initialize_pagetables((&mut mem[0..MIN_PHYSMEM_SIZE]).try_into().unwrap());

		// Test pagetable setup
		let addr_pdpte = u64::from_le_bytes(
			mem[(BOOT_PML4.as_u64() as usize)..(BOOT_PML4.as_u64() as usize + 8)]
				.try_into()
				.unwrap(),
		);
		assert_eq!(
			addr_pdpte,
			BOOT_PDPTE.as_u64() | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);
		let addr_pde = u64::from_le_bytes(
			mem[(BOOT_PDPTE.as_u64() as usize)..(BOOT_PDPTE.as_u64() as usize + 8)]
				.try_into()
				.unwrap(),
		);
		assert_eq!(
			addr_pde,
			BOOT_PDE.as_u64() | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);

		for i in (0..4096).step_by(8) {
			let addr = BOOT_PDE.as_u64() as usize + i;
			let entry = u64::from_le_bytes(mem[addr..(addr + 8)].try_into().unwrap());
			assert!(
				PageTableFlags::from_bits_truncate(entry)
					.difference(
						PageTableFlags::PRESENT
							| PageTableFlags::WRITABLE
							| PageTableFlags::HUGE_PAGE
					)
					.is_empty(),
				"Pagetable bits at {addr:#x} are incorrect"
			)
		}

		// Test GDT
		let gdt_results = [0x0, 0xAF9B000000FFFF, 0xCF93000000FFFF];
		for (i, res) in gdt_results.iter().enumerate() {
			let gdt_addr = BOOT_GDT.as_u64() as usize + i * 8;
			let gdt_entry = u64::from_le_bytes(mem[gdt_addr..gdt_addr + 8].try_into().unwrap());
			assert_eq!(*res, gdt_entry);
		}
	}
}
