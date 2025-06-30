use std::{mem::MaybeUninit, ops::Index, os::raw::c_void, ptr::NonNull};

use nix::sys::mman::*;
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;

#[derive(Error, Debug)]
pub enum MemoryError {
	#[error("Memory bounds exceeded")]
	BoundsViolation,
	#[error("The desired guest location is not part of this memory")]
	WrongMemoryError,
}

/// A general purpose VM memory section that can exploit some Linux Kernel features.
#[derive(Debug)]
pub struct MmapMemory {
	// TODO: make private
	pub flags: u32,
	pub memory_size: usize,
	pub guest_address: GuestPhysAddr,
	pub host_address: *mut u8,
}

impl MmapMemory {
	pub fn new(
		flags: u32,
		memory_size: usize,
		guest_address: GuestPhysAddr,
		huge_pages: bool,
		mergeable: bool,
	) -> MmapMemory {
		let host_address = unsafe {
			mmap_anonymous(
				None,
				memory_size.try_into().unwrap(),
				ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
				MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
			)
			.expect("mmap failed")
		};

		if mergeable {
			#[cfg(target_os = "linux")]
			{
				debug!("Enable kernel feature to merge same pages");
				unsafe {
					madvise(host_address, memory_size, MmapAdvise::MADV_MERGEABLE).unwrap();
				}
			}
			#[cfg(not(target_os = "linux"))]
			{
				error!("OS does not support same page merging");
			}
		}

		if huge_pages {
			#[cfg(target_os = "linux")]
			{
				debug!("Uhyve uses huge pages");
				unsafe {
					madvise(host_address, memory_size, MmapAdvise::MADV_HUGEPAGE).unwrap();
				}
			}
			#[cfg(not(target_os = "linux"))]
			{
				error!("OS does not support huge pages");
			}
		}

		MmapMemory {
			flags,
			memory_size,
			guest_address,
			host_address: host_address.as_ptr() as *mut u8,
		}
	}

	/// This can create multiple aliasing. During the lifetime of the returned slice, the memory must not be altered, dropped or simmilar.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
		unsafe { std::slice::from_raw_parts_mut(self.host_address, self.memory_size) }
	}

	/// Same as [`as_slice_mut`], but for `MaybeUninit<u8>`. Actually the memory is initialized, as Mmap zero initializes it, but some fns like [`hermit_entry::elf::load_kernel`] require [`MaybeUninit`]s.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn as_slice_uninit_mut(&self) -> &mut [MaybeUninit<u8>] {
		unsafe {
			std::slice::from_raw_parts_mut(
				self.host_address as *mut MaybeUninit<u8>,
				self.memory_size,
			)
		}
	}

	/// Read a section of the memory.
	///
	/// # Safety
	///
	/// This is unsafe, as can create multiple aliasing. During the lifetime of
	/// the returned slice, the memory must not be altered to prevent undfined
	/// behaviour.
	pub unsafe fn slice_at(&self, addr: GuestPhysAddr, len: usize) -> Result<&[u8], MemoryError> {
		if addr.as_u64() as usize + len >= self.memory_size + self.guest_address.as_u64() as usize {
			Err(MemoryError::BoundsViolation)
		} else {
			Ok(unsafe { std::slice::from_raw_parts(self.host_address(addr)?, len) })
		}
	}

	/// Writeable access to a section of the memory.
	///
	/// # Safety
	///
	/// This is unsafe, as it can create multiple aliasing. During the lifetime of
	/// the returned slice, the memory must not be altered to prevent undfined
	/// behavior.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn slice_at_mut(
		&self,
		addr: GuestPhysAddr,
		len: usize,
	) -> Result<&mut [u8], MemoryError> {
		if addr.as_u64() as usize + len > self.memory_size + self.guest_address.as_u64() as usize {
			Err(MemoryError::BoundsViolation)
		} else {
			Ok(unsafe { std::slice::from_raw_parts_mut(self.host_address(addr)? as *mut u8, len) })
		}
	}

	/// Returns the host address of the given internal physical address in the
	/// memory, if the address is valid.
	pub fn host_address(&self, addr: GuestPhysAddr) -> Result<*const u8, MemoryError> {
		if addr < self.guest_address
			|| addr.as_u64() as usize > self.guest_address.as_u64() as usize + self.memory_size
		{
			return Err(MemoryError::WrongMemoryError);
		}
		Ok(
			// Safety:
			// - The new ptr is checked to be within the mmap'd memory region above
			// - to overflow an isize, the guest memory needs to be larger than 2^63 (which is rather unlikely anytime soon).
			unsafe { self.host_address.add((addr - self.guest_address) as usize) as usize }
				as *const u8,
		)
	}

	/// Read the value in the memory at the given address
	pub fn read<T>(&self, addr: GuestPhysAddr) -> Result<T, MemoryError> {
		Ok(unsafe { self.host_address(addr)?.cast::<T>().read_unaligned() })
	}

	/// Get a reference to the type at the given address in the memory.
	pub unsafe fn get_ref<T>(&self, addr: GuestPhysAddr) -> Result<&T, MemoryError> {
		Ok(unsafe { &*(self.host_address(addr)? as *const T) })
	}

	/// Get a mutable reference to the type at the given address in the memory.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn get_ref_mut<T>(&self, addr: GuestPhysAddr) -> Result<&mut T, MemoryError> {
		Ok(unsafe { &mut *(self.host_address(addr)? as *mut T) })
	}
}

impl Drop for MmapMemory {
	fn drop(&mut self) {
		if self.memory_size > 0 {
			let host_addr = NonNull::new(self.host_address as *mut c_void).unwrap();
			unsafe {
				munmap(host_addr, self.memory_size).unwrap();
			}
		}
	}
}

impl Index<usize> for MmapMemory {
	type Output = u8;

	#[inline(always)]
	fn index(&self, index: usize) -> &Self::Output {
		assert!(index < self.memory_size);

		// Safety:
		// - The new ptr is checked to be within the mmap'd memory region above
		// - to overflow an isize, the guest memory needs to be larger than 2^63 (which is rather unlikely anytime soon).
		unsafe { &*self.host_address.add(index) }
	}
}

/// Wrapper aroud a memory allocation that is aligned to x86 HugePages
/// (`0x20_0000`). Intended for testing purposes only
#[cfg(test)]
#[expect(dead_code)]
pub(crate) struct HugePageAlignedMem<'a, const SIZE: usize> {
	ptr: *mut u8,
	pub mem: &'a mut [u8],
}
#[cfg(test)]
#[expect(dead_code)]
impl<const SIZE: usize> HugePageAlignedMem<'_, SIZE> {
	pub fn new() -> Self {
		use std::alloc::{Layout, alloc_zeroed};
		// TODO: Make this generic to arbitrary alignments.
		let layout = Layout::from_size_align(SIZE, 0x20_0000).unwrap();
		unsafe {
			let ptr = alloc_zeroed(layout);
			if ptr.is_null() {
				panic!("Allocation failed");
			}
			Self {
				ptr,
				mem: std::slice::from_raw_parts_mut(ptr, SIZE),
			}
		}
	}
}
#[cfg(test)]
impl<const SIZE: usize> Drop for HugePageAlignedMem<'_, SIZE> {
	fn drop(&mut self) {
		use std::alloc::{Layout, dealloc};
		let layout = Layout::from_size_align(SIZE, 0x20_0000).unwrap();
		unsafe {
			dealloc(self.ptr, layout);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::consts::PAGE_SIZE;

	#[test]
	fn test_mmap_memory_readwrite() {
		let phys_mem_start_addresses = vec![
			0x1000,                // "normal" address offset
			0x2221,                // odd address
			0x13000,               // something we'd actually use (minimal size for the physical memory)
			0x000F_FFFF_FFFF_0000, // "physical addresses: no bits in the range 52 to 64 set"
		];

		for address in phys_mem_start_addresses {
			let mem = MmapMemory::new(0, 40 * PAGE_SIZE, GuestPhysAddr::new(address), true, true);
			unsafe {
				mem.as_slice_mut()[0xfe] = 0xaa;
				mem.as_slice_mut()[0xff] = 0xbb;
				mem.as_slice_mut()[0x100] = 0x78;
				mem.as_slice_mut()[0x101] = 0x56;
				mem.as_slice_mut()[0x102] = 0x34;
				mem.as_slice_mut()[0x103] = 0x12;
			}
			assert_eq!(
				mem.read::<u64>(GuestPhysAddr::new(address + 0x100))
					.unwrap(),
				0x12345678
			);
			// unaligned read
			assert_eq!(
				mem.read::<u64>(GuestPhysAddr::new(address + 0xfe)).unwrap(),
				0x12345678bbaa
			);
		}
	}
}
