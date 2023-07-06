use thiserror::Error;
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::{arch::virt_to_phys, consts::BOOT_PML4};

#[derive(Error, Debug)]
pub enum MemoryError {
	#[error("Memory bounds exceeded")]
	BoundsViolation,
	#[error("The desired guest location is not part of this memory")]
	WrongMemoryError,
	#[error("Accessing memory with an invalid virtual address")]
	InvalidAddress,
}

/// Helper function to access memory in a `GuestMemoryMap` via a `GuestPhysAddr` as a slice.
///
/// # Safety:
/// This is only safe, if the memory is not modified during the lifetime of the slice. Another part
/// of the hypervisor or the virtual machine modifying the memory results in undefined behaviour.
pub(crate) unsafe fn mem_as_slice(
	mem: &GuestMemoryMmap,
	start: GuestPhysAddr,
	len: usize,
) -> Result<&mut [u8], MemoryError> {
	let guest_addr = GuestAddress(start.as_u64());
	if mem.check_range(guest_addr, len) {
		Ok(std::slice::from_raw_parts_mut(
			mem.get_host_address(guest_addr).unwrap(),
			len,
		))
	} else {
		Err(MemoryError::BoundsViolation)
	}
}

/// Helper function to access memory in a `GuestMemoryMap` via a `GuestVirtAddr` as a slice.
///
/// # Safety:
/// This is only safe, if the memory is not modified during the lifetime of the slice. Another part
/// of the hypervisor or the virtual machine modifying the memory results in undefined behaviour.
pub(crate) unsafe fn mem_as_slice_virt(
	mem: &GuestMemoryMmap,
	start: GuestVirtAddr,
	len: usize,
) -> Result<&mut [u8], MemoryError> {
	let guest_addr =
		virt_to_phys(start, mem, BOOT_PML4).map_err(|_err| MemoryError::WrongMemoryError)?;
	mem_as_slice(mem, guest_addr, len)
}

/// Helper function to access an element in a `GuestMemoryMap`.
///
/// # Safety:
/// - This is only safe, if the memory is not modified during the lifetime of the slice. Another
///   part of the hypervisor or the virtual machine modifying the memory results in undefined
///   behaviour.
/// - `addr` must follow the alignment rules for `T`.
pub(crate) unsafe fn mem_get_ref_mut<T>(
	mem: &GuestMemoryMmap,
	addr: GuestPhysAddr,
) -> Result<&mut T, MemoryError> {
	let guest_addr = GuestAddress(addr.as_u64());
	if mem.check_range(guest_addr, std::mem::size_of::<T>()) {
		Ok(unsafe {
			&mut *(mem
				.get_host_address(guest_addr)
				.map_err(|_| MemoryError::InvalidAddress)? as *mut T)
		})
	} else {
		Err(MemoryError::BoundsViolation)
	}
}
