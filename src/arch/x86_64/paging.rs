use uhyve_interface::GuestPhysAddr;
use x86_64::{
	VirtAddr,
	structures::paging::{
		FrameAllocator, MappedPageTable, Mapper, Page, PageSize, PageTable, PageTableFlags,
		PageTableIndex, PhysFrame, Size2MiB, Size4KiB, mapper::PageTableFrameMapping,
	},
};

use crate::{
	mem::MmapMemory, mem_layout::MemoryLayout, paging::BumpAllocator, x86_64::X86_64MemoryLayout,
};

const BOOT_GDT_NULL: usize = 0;
const BOOT_GDT_CODE: usize = 1;
const BOOT_GDT_DATA: usize = 2;
pub(crate) const BOOT_GDT_MAX: usize = 3;

// Constructor for a conventional segment GDT (or LDT) entry
pub fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
	((base & 0xff000000u64) << (56 - 24))
		| ((flags & 0x0000f0ffu64) << 40)
		| ((limit & 0x000f0000u64) << (48 - 16))
		| ((base & 0x00ffffffu64) << 16)
		| (limit & 0x0000ffffu64)
}

unsafe impl FrameAllocator<Size4KiB> for BumpAllocator<{ Size4KiB::SIZE }> {
	fn allocate_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame<Size4KiB>> {
		self.allocate()
			// Safety: pa is aligned and from a host perspective the Frame is just a number without UB.
			.map(|pa| unsafe { PhysFrame::from_start_address_unchecked(pa.into()) })
	}
}

/// A mapper, that does not require to be run inside the system to be mapped.
/// Attention: This must be used in an empty or correctly mapped system with
/// `mem` of sufficient size and `guest_address` beeing the correct guest-
/// physical-address of `mem`. Otherwise this will corrup memory and lead to UB.
struct UhyvePageTableFrameMapper<'a> {
	mem: &'a mut [u8],
	guest_address: GuestPhysAddr,
}
unsafe impl PageTableFrameMapping for UhyvePageTableFrameMapper<'_> {
	fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
		let rel_addr = frame.start_address().as_u64() - self.guest_address.as_u64();
		unsafe { self.mem.as_ptr().add(rel_addr as usize) as *mut PageTable }
	}
}

/// Creates the pagetables and the GDT in the guest memory space.
///
/// The memory slice must be larger than [`MIN_PHYSMEM_SIZE`].
/// Also, the memory `mem` needs to be zeroed for [`PAGE_SIZE`] bytes at the
/// offsets [`BOOT_PML4`] and [`BOOT_PDPTE`], otherwise the integrity of the
/// pagetables and thus the integrity of the guest's memory is not ensured
/// `mem` and `GuestPhysAddr` must be 2MiB page aligned.
/// length is the size of the identity mapped region in bytes.
pub fn initialize_pagetables(
	mem: &mut MmapMemory,
	layout: &X86_64MemoryLayout,
	length: u64,
	// TODO: deprecate the legacy_mapping option once hermit pre 0.10.0 isn't a thing anymore.
	legacy_mapping: bool,
) {
	let pagetable_layout = layout.pagetables().0;
	assert!(
		layout.pagetables().0.end() <= mem.guest_addr() + mem.size(),
		"Insufficient memory for pagetable mapping"
	);

	// Safety: we have ownership of mem and during the lifetime of this slice we don't create other references into the memory.
	let gdt_entry = unsafe { mem.get_ref_mut::<[u64; 3]>(layout.gdt_address()).unwrap() };
	// initialize GDT
	gdt_entry[BOOT_GDT_NULL] = 0;
	gdt_entry[BOOT_GDT_CODE] = create_gdt_entry(0xA09B, 0, 0xFFFFF);
	gdt_entry[BOOT_GDT_DATA] = create_gdt_entry(0xC093, 0, 0xFFFFF);

	let pml4 = unsafe { mem.get_ref_mut::<PageTable>(layout.pml4_address()).unwrap() };
	// recursive pagetable setup
	pml4[511].set_addr(
		layout.pml4_address().into(),
		PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
	);

	let mut boot_frame_allocator = BumpAllocator::new(
		layout.pagetables().0.start(),
		pagetable_layout.length as u64 / Size4KiB::SIZE,
	);
	let page_mapper = UhyvePageTableFrameMapper {
		// Safety: we have ownership of mem and during the lifetime of this slice we don't create other references into the memory.
		mem: unsafe {
			mem.slice_at_mut(pagetable_layout.addr, pagetable_layout.length)
				.unwrap()
		},
		guest_address: pagetable_layout.addr,
	};
	// Safety: pml4 is zero initialized and page_mapper operates in a correct environment
	let mut pagetable_mapping = unsafe { MappedPageTable::new(pml4, page_mapper) };

	let mapping_range = if legacy_mapping {
		debug!("Legacy mapping of the initial memory");
		let start_page = layout.guest_address();
		let kernel_start = VirtAddr::new(layout.kernel().0.addr.as_u64());
		let end_page = Page::from_page_table_indices_2mib(
			kernel_start.p4_index(),
			kernel_start.p3_index(),
			PageTableIndex::new(511),
		);
		let end = u64::max(
			end_page.start_address().as_u64(),
			layout.guest_address().as_u64() + length,
		);
		start_page.as_u64()..=end
	} else {
		layout.guest_address().as_u64()..=layout.guest_address().as_u64() + length
	};

	// Map the kernel
	debug!(
		"identity mapping from {:?} to {:?}",
		layout.guest_address(),
		layout.guest_address() + length
	);
	for addr in mapping_range.step_by(Size2MiB::SIZE as usize) {
		let ga = GuestPhysAddr::new(addr);
		let _ = unsafe {
			pagetable_mapping
				.identity_map(
					PhysFrame::<Size2MiB>::from_start_address_unchecked(ga.into()),
					PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
					&mut boot_frame_allocator,
				)
				.unwrap()
		};
	}
}

/// Helper fn for debugging pagetables
#[allow(dead_code, reason = "Useful for debugging purposes.")]
fn pretty_print_pagetable(pt: &PageTable) {
	println!(
		"Idx       Address          Idx       Address          Idx       Address          Idx       Address      "
	);
	println!(
		"--------------------------------------------------------------------------------------------------------"
	);
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
	println!(
		"--------------------------------------------------------------------------------------------------------"
	);
}

#[cfg(test)]
mod tests {
	use uhyve_interface::GuestVirtAddr;

	use super::*;
	use crate::mem::MmapMemory;

	#[test]
	fn test_pagetable_initialization() {
		let _ = env_logger::builder()
			.filter(None, log::LevelFilter::Debug)
			.is_test(true)
			.try_init();

		let gaddrs = [
			GuestPhysAddr::new(0x0),
			GuestPhysAddr::new(0x11120000),
			GuestPhysAddr::new(0x111ff000),
			GuestPhysAddr::new(0xe1120000),
		];

		for &guest_address in gaddrs.iter() {
			println!("\n\n---------------------------------------");
			println!("testing guest address {guest_address:?}");
			let mut mem = MmapMemory::new(
				X86_64MemoryLayout::MIN_PHYSMEM_SIZE * 2,
				guest_address,
				true,
				true,
			);
			let layout = X86_64MemoryLayout::simple_layout(guest_address);
			initialize_pagetables(&mut mem, &layout, 0x20_0000 * 4, false);

			/// Checks if `address` is in the pagetables.
			fn check_and_print(
				address: GuestVirtAddr,
				mem: &MmapMemory,
				layout: &X86_64MemoryLayout,
			) {
				let idx4 = address.p4_index();
				let idx3 = address.p3_index();
				let idx2 = address.p2_index();
				debug!(
					"address: {address:#x}: {}-{}-{}",
					u16::from(idx4),
					u16::from(idx3),
					u16::from(idx2)
				);
				let pml4 = unsafe { mem.get_ref(layout.pml4_address()).unwrap() };
				pretty_print_pagetable(pml4);

				// Check PDPTE address
				let addr_pdpte = &pml4[idx4];
				debug!("addr_ptpde: {addr_pdpte:?}");
				assert!(addr_pdpte.addr().as_u64() >= layout.pagetables().0.start().as_u64());
				assert!(addr_pdpte.addr().as_u64() <= layout.pagetables().0.end().as_u64());
				assert!(
					addr_pdpte
						.flags()
						.contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
				);

				let pdpte = unsafe { mem.get_ref(addr_pdpte.addr().into()).unwrap() };
				pretty_print_pagetable(pdpte);
				let addr_pde = &pdpte[idx3];
				assert!(addr_pde.addr().as_u64() >= layout.pagetables().0.start().as_u64());
				assert!(addr_pde.addr().as_u64() <= layout.pagetables().0.end().as_u64());
				assert!(
					addr_pde
						.flags()
						.contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
				);

				let pde = unsafe { mem.get_ref(addr_pde.addr().into()).unwrap() };
				pretty_print_pagetable(pde);
				assert_eq!(pde[idx2].addr().as_u64(), address.as_u64());
			}

			check_and_print(GuestVirtAddr::new(guest_address.as_u64()), &mem, &layout);
			check_and_print(
				GuestVirtAddr::new(guest_address.as_u64() + 3 * 0x20_0000),
				&mem,
				&layout,
			);

			// Test GDT
			let gdt_results = [0x0, 0xAF9B000000FFFF, 0xCF93000000FFFF];
			for (i, res) in gdt_results.iter().enumerate() {
				let gdt_addr = layout.gdt_address() + i * 8;
				let gdt_entry = u64::from_le_bytes(unsafe {
					mem.slice_at(gdt_addr, 8).unwrap().try_into().unwrap()
				});
				assert_eq!(*res, gdt_entry);
			}
		}
	}
}
