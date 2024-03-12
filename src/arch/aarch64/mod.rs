use crate::consts::{BOOT_INFO_ADDR, BOOT_PGT, PAGE_SIZE};
use bitflags::bitflags;
use std::mem::size_of;
use uhyve_interface::GuestPhysAddr;

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

pub fn init_guest_mem(mem: &mut [u8]) {
	let mem_addr = std::ptr::addr_of_mut!(mem[0]);

	assert!(mem.len() >= BOOT_PGT.as_u64() as usize + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(mem_addr.offset(BOOT_PGT.as_u64() as isize) as *mut u64, 512)
	};
	pgt_slice.fill(0);
	pgt_slice[0] = BOOT_PGT.as_u64() + 0x1000 + PT_PT;
	pgt_slice[511] = BOOT_PGT.as_u64() + PT_PT + PT_SELF;

	assert!(mem.len() >= BOOT_PGT.as_u64() as usize + 0x1000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(BOOT_PGT.as_u64() as isize + 0x1000) as *mut u64,
			512,
		)
	};
	pgt_slice.fill(0);
	pgt_slice[0] = BOOT_PGT.as_u64() + 0x2000 + PT_PT;

	assert!(mem.len() >= BOOT_PGT.as_u64() as usize + 0x2000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(BOOT_PGT.as_u64() as isize + 0x2000) as *mut u64,
			512,
		)
	};
	pgt_slice.fill(0);
	pgt_slice[0] = BOOT_PGT.as_u64() + 0x3000 + PT_PT;
	pgt_slice[1] = BOOT_PGT.as_u64() + 0x4000 + PT_PT;
	pgt_slice[2] = BOOT_PGT.as_u64() + 0x5000 + PT_PT;

	assert!(mem.len() >= BOOT_PGT.as_u64() as usize + 0x3000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(BOOT_PGT.as_u64() as isize + 0x3000) as *mut u64,
			512,
		)
	};
	pgt_slice.fill(0);
	// map uhyve ports into the virtual address space
	pgt_slice[0] = PT_MEM_CD;
	// map BootInfo into the virtual address space
	pgt_slice[BOOT_INFO_ADDR.as_u64() as usize / PAGE_SIZE] = BOOT_INFO_ADDR.as_u64() + PT_MEM;

	assert!(mem.len() >= BOOT_PGT.as_u64() as usize + 0x4000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(BOOT_PGT.as_u64() as isize + 0x4000) as *mut u64,
			512,
		)
	};
	for (idx, i) in pgt_slice.iter_mut().enumerate() {
		*i = 0x200000u64 + (idx * PAGE_SIZE) as u64 + PT_MEM;
	}

	assert!(mem.len() >= BOOT_PGT.as_u64() as usize + 0x5000 + 512 * size_of::<u64>());
	let pgt_slice = unsafe {
		std::slice::from_raw_parts_mut(
			mem_addr.offset(BOOT_PGT.as_u64() as isize + 0x5000) as *mut u64,
			512,
		)
	};
	for (idx, i) in pgt_slice.iter_mut().enumerate() {
		*i = 0x400000u64 + (idx * PAGE_SIZE) as u64 + PT_MEM;
	}
}
