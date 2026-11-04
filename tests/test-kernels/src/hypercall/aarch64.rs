use core::arch::asm;

use uhyve_interface::{
	GuestPhysAddr, GuestVirtAddr,
	v2::{Hypercall, HypercallAddress},
};

use super::hypercall_data;

/// Translate a guest virtual address to a physical one using the current EL1 stage 1 translation.
pub fn virtual_to_physical(virtual_address: GuestVirtAddr) -> Option<GuestPhysAddr> {
	let va = virtual_address.as_u64();
	let par: u64;
	unsafe {
		asm!(
			"at s1e1r, {va}",
			"isb",
			"mrs {par}, par_el1",
			va = in(reg) va,
			par = out(reg) par,
			options(nostack, preserves_flags)
		);
	}
	// PAR_EL1.F signals a failed translation.
	if par & 1 != 0 {
		return None;
	}
	let page = par & 0x0000_FFFF_FFFF_F000;
	Some(GuestPhysAddr::new(page | (va & 0xFFF)))
}

/// Perform a hypercall to the uhyve hypervisor.
#[inline]
pub fn uhyve_hypercall(hypercall: Hypercall<'_>) {
	let ptr = HypercallAddress::from(&hypercall) as u64;
	let data = hypercall_data(&hypercall);
	unsafe {
		asm!(
			"str x8, [{ptr}]",
			ptr = in(reg) ptr,
			in("x8") data,
			options(nostack)
		);
	}
}
