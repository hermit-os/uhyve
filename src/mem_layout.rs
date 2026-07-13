use std::{
	fmt::{Debug, Display},
	ops::Add,
};

use align_address::Align;
use hermit_entry::{UhyveIfVersion, elf::KernelObject};
use uhyve_interface::GuestPhysAddr;

use crate::{V1_ADDR_RANGE, V2_ADDR_RANGE, params::Params};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Section {
	pub addr: GuestPhysAddr,
	pub length: usize,
}
impl Section {
	pub fn start(&self) -> GuestPhysAddr {
		self.addr
	}
	// "no code using it on aarch64 (yet)"
	pub fn end(&self) -> GuestPhysAddr {
		self.addr + self.length
	}
}

pub(crate) struct FdtSection(pub Section);
pub(crate) struct BootInfoSection(pub Section);
pub(crate) struct StackSection(pub Section);
pub(crate) struct PagetableSection(pub Section);
pub(crate) struct KernelSection(pub Section);

pub trait MemoryLayout: Display + Debug {
	fn new(params: &Params, object: &KernelObject<'_>) -> Self;

	/// The location of the whole guest in the physical address space
	fn guest_address(&self) -> GuestPhysAddr;

	/// The location of the kernel image in physical memory
	fn kernel(&self) -> KernelSection;

	fn stack(&self) -> StackSection;

	fn fdt(&self) -> FdtSection;

	fn boot_info(&self) -> BootInfoSection;

	/// The Starting position of the allocatable pagetables area. This doesn't need to include the root pagetable.
	fn pagetables(&self) -> PagetableSection;
}

/// Returns a guest & start address tuple based on the object file.
///
/// Generates a tuple containing a potentially random guest address and a derived
/// start address for Uhyve's virtualized memory. The guest address will not be
/// random under the following conditions:
/// - The image is not relocatable / uses uhyve-interface v1.
/// - ASLR is disabled.
///
/// If the image is not relocatable, the start address will be equal to that
/// present in the unikernel image file's object representation.
///
/// - `interface_version`: Version of uhyve-interface.
/// - `aslr`: `bool` describing whether ASLR is enabled (`true`) or disabled (`false`).
/// - `object_mem_size`: Memory required to load the object file onto the guest's memory.
/// - `object_start_addr`: Start address embedded in the unikernel image (if applicable).
/// - `mem_size`: User-defined memory size that should be available to the VM.
pub(crate) fn generate_guest_start_address(
	interface_version: UhyveIfVersion,
	aslr: bool,
	object_mem_size: usize,
	object_start_addr: Option<u64>,
	mem_size: usize,
	kernel_offset: u64,
) -> (GuestPhysAddr, GuestPhysAddr) {
	// Using an interface-specific version's range and by using checked_sub, we
	// guarantee that the range used during the kernel's execution won't lead
	// to a boundary violation during the guest's execution.
	let (guest_address_lb, guest_address_ub): (u64, u64) = {
		let range = match interface_version.0 {
			1 => V1_ADDR_RANGE,
			2 | 3 => V2_ADDR_RANGE,
			_ => unimplemented!(),
		};
		// kernel_offset will be added again later for the start address, later.
		let mem_size = (object_mem_size + mem_size) as u64 + kernel_offset;
		(
			range.0,
			range.1.checked_sub(mem_size).unwrap_or_else(|| {
				let (lb, ub) = range;
				let hint = match interface_version.0 {
					1 => " (More than 3GiB memory is not supported for Hermit <= 0.13.2)",
					2 | 3 => "",
					_ => unimplemented!(),
				};
				panic!("Out of range [{lb:#x}, {ub:#x}) due to memory size {mem_size:#x}.{hint}")
			}),
		)
	};

	debug_assert!(guest_address_lb <= guest_address_ub);

	match (aslr, object_start_addr) {
		(true, None) => {
			let mut rng = rand::rng();
			let guest_address = GuestPhysAddr::new(
				rand::RngExt::random_range(&mut rng, guest_address_lb..=guest_address_ub)
					.align_down(0x20_0000),
			);
			(guest_address, guest_address.add(kernel_offset))
		}
		(false, None) => {
			let guest_address = GuestPhysAddr::new(guest_address_lb);
			(guest_address, guest_address.add(kernel_offset))
		}
		(_, Some(predefined_start_address)) => {
			assert!(
				(guest_address_lb..=guest_address_ub).contains(&predefined_start_address),
				"Predefined address {predefined_start_address:#x} out of range of possible
				 guest addresses: [{guest_address_lb:#x}, {guest_address_ub:#x}]."
			);
			if aslr {
				warn!("ASLR is enabled but kernel is not relocatable - disabling ASLR");
			}
			(
				GuestPhysAddr::new(guest_address_lb),
				GuestPhysAddr::new(predefined_start_address),
			)
		}
	}
}

#[cfg(test)]
mod tests {
	use std::ops::Add;

	use hermit_entry::UhyveIfVersion;

	use super::*;
	use crate::{RAM_START, V1_MAX_ADDR};

	#[test]
	fn test_generate_guest_start_address() {
		#![cfg_attr(target_arch = "aarch64", allow(unused_assignments))]
		let mem_size: usize = 0xBE20_0000; // 3042 MiB
		let if_v1 = UhyveIfVersion(1);
		let if_v2 = UhyveIfVersion(2);
		let object_mem_size: usize = 0x0009_C400;
		let object_no_start_addr: Option<u64> = None;
		#[cfg(target_arch = "x86_64")]
		let object_start_addr: u64 = 0x0002_0000;
		#[cfg(target_arch = "aarch64")]
		let object_start_addr: u64 = 0x1002_0000;
		let kernel_offset = 0x004_0000;

		/* v1 */
		// v1: No ASLR, relocatable
		let (mut guest_address, mut start_address) = generate_guest_start_address(
			if_v1,
			false,
			object_mem_size,
			object_no_start_addr,
			mem_size,
			kernel_offset,
		);
		assert!(guest_address < start_address);
		assert_eq!(guest_address, RAM_START);

		// v1: ASLR, relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v1,
			true,
			object_mem_size,
			object_no_start_addr,
			mem_size,
			kernel_offset,
		);
		assert!(guest_address < start_address);
		assert!(start_address.as_u64() <= V1_MAX_ADDR);

		// v1: ASLR, non-relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v1,
			true,
			object_mem_size,
			object_start_addr.into(),
			mem_size,
			kernel_offset,
		);
		assert!(guest_address < start_address);
		assert_eq!(guest_address, RAM_START);
		assert_eq!(start_address.as_u64(), object_start_addr);
		// Note that this is a bit brittle and implicitly relies on RAM_START.
		assert_eq!(start_address, guest_address.add(0x0002_0000usize));
		assert!(start_address.as_u64() <= V1_MAX_ADDR);

		/* v2 */

		// v2: No ASLR, relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v2,
			false,
			object_mem_size,
			object_no_start_addr,
			mem_size,
			kernel_offset,
		);
		assert_eq!(guest_address.as_u64(), 0x0001_0000_0000u64);
		#[cfg(target_arch = "x86_64")]
		assert!(start_address.as_u64() >= V1_MAX_ADDR);

		// v2: ASLR, relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v2,
			true,
			object_mem_size,
			object_no_start_addr,
			mem_size,
			kernel_offset,
		);
		#[cfg(target_arch = "x86_64")]
		assert!(start_address.as_u64() >= V1_MAX_ADDR);
		assert_ne!(guest_address.as_u64(), 0x0);

		// v2: Use entire memory available
		//
		// (This effectively renders ASLR worthless, yet it is great for testing,
		//  underlying arithmetic operations for potential regressions without
		//  exclusively relying on randomness!)
		(guest_address, start_address) = generate_guest_start_address(
			if_v2,
			true,
			object_mem_size,
			object_no_start_addr,
			// Highest address, minus everything that is subtracted from it in the function.
			0x0010_0000_0000 - object_mem_size - kernel_offset as usize - 0x0001_0000_0000,
			kernel_offset,
		);
		assert_eq!(guest_address.as_u64(), 0x0001_0000_0000);
		#[cfg(target_arch = "x86_64")]
		assert_eq!(
			start_address,
			guest_address.add(crate::arch::x86_64::X86_64MemoryLayout::KERNEL_OFFSET)
		);
		#[cfg(target_arch = "aarch64")]
		assert_eq!(
			start_address,
			guest_address.add(crate::arch::aarch64::Aarch64MemoryLayout::KERNEL_OFFSET)
		);
		#[cfg(target_arch = "x86_64")]
		assert!(start_address.as_u64() >= V1_MAX_ADDR);
	}
}
