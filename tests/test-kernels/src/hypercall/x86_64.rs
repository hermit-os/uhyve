use uhyve_interface::{
	GuestPhysAddr, GuestVirtAddr,
	v3::{Hypercall, HypercallAddress},
};
use x86_64::{
	VirtAddr,
	structures::paging::{PageTable, RecursivePageTable},
};

use super::hypercall_data;

unsafe fn get_page_table() -> RecursivePageTable<'static> {
	let level_4_table_addr: u64 = 0xFFFF_FFFF_FFFF_F000;
	unsafe {
		let level_4_table = &mut *(level_4_table_addr as *mut PageTable);
		RecursivePageTable::new(level_4_table).unwrap()
	}
}

/// Translate a guest virtual address to a physical one (recursive map).
pub fn virtual_to_physical(virtual_address: GuestVirtAddr) -> Option<GuestPhysAddr> {
	use x86_64::structures::paging::mapper::Translate;

	let page_table = unsafe { get_page_table() };
	page_table
		.translate_addr(VirtAddr::new(virtual_address.as_u64()))
		.map(|addr| GuestPhysAddr::new(addr.as_u64()))
}

/// Perform a hypercall to the uhyve hypervisor.
#[inline]
pub fn uhyve_hypercall(hypercall: Hypercall<'_>) {
	let ptr = HypercallAddress::from(&hypercall) as u16;
	let data = hypercall_data(&hypercall);
	unsafe {
		use core::arch::asm;
		asm!(
			"out dx, eax",
			in("dx") ptr,
			in("eax") 0x1234u32,
			in("rdi") data,
			options(nostack, preserves_flags)
		);
	}
}
