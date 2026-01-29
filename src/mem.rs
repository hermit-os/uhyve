use std::{mem::MaybeUninit, ops::Range};
#[cfg(target_os = "linux")]
use std::{os::raw::c_void, ptr::NonNull};

#[cfg(target_os = "linux")]
use nix::sys::mman::{MmapAdvise, madvise};
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;
use vm_memory::{
	Address, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
	MemoryRegionAddress, mmap::MmapRegionBuilder,
};

#[derive(Error, Debug)]
pub enum MemoryError {
	#[error("Memory bounds exceeded")]
	BoundsViolation,
}

/// A general purpose VM memory section that can exploit some Linux Kernel features.
/// Uses `GuestMemoryMmap` under the hood.
#[derive(Debug)]
pub(crate) struct MmapMemory {
	mem: GuestMemoryMmap,
}
impl MmapMemory {
	pub fn new(
		memory_size: usize,
		guest_address: GuestPhysAddr,
		huge_pages: bool,
		mergeable: bool,
	) -> Self {
		let mm_region = MmapRegionBuilder::new_with_bitmap(memory_size, ())
			.with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
			.with_mmap_flags(libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE)
			.build()
			.unwrap();

		if mergeable {
			#[cfg(target_os = "linux")]
			{
				debug!("Enable kernel feature to merge same pages");

				unsafe {
					madvise(
						NonNull::new(mm_region.as_ptr() as *mut c_void).unwrap(),
						memory_size,
						MmapAdvise::MADV_MERGEABLE,
					)
					.unwrap();
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
					madvise(
						NonNull::new(mm_region.as_ptr() as *mut c_void).unwrap(),
						memory_size,
						MmapAdvise::MADV_HUGEPAGE,
					)
					.unwrap();
				}
			}
			#[cfg(not(target_os = "linux"))]
			{
				error!("OS does not support huge pages");
			}
		}

		Self {
			mem: GuestMemoryMmap::from_regions(vec![
				GuestRegionMmap::<()>::new(mm_region, GuestAddress(guest_address.as_u64()))
					.unwrap(),
			])
			.unwrap(),
		}
	}

	/// Helper function to access the only Mmap region in our struct
	fn region_mmap(&self) -> &GuestRegionMmap {
		self.mem.iter().next().unwrap()
	}

	/// Returns the size of the memory in bytes
	pub fn size(&self) -> usize {
		self.region_mmap().size()
	}

	/// Returns the first valid physical address from the gutest perspective.
	pub fn guest_addr(&self) -> GuestPhysAddr {
		GuestPhysAddr::new(self.mem.iter().next().unwrap().start_addr().0)
	}

	/// Returns a pointer to the beginning of the memory on the host.
	pub fn host_start(&self) -> *mut u8 {
		let start_addr = self.region_mmap().start_addr();
		let region_addr = self.region_mmap().to_region_addr(start_addr).unwrap();
		self.region_mmap().get_host_address(region_addr).unwrap()
	}

	/// # Safety
	///
	/// This can create multiple aliasing. During the lifetime of the returned slice, the memory must not be altered, dropped or simmilar.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
		unsafe { std::slice::from_raw_parts_mut(self.host_start(), self.size()) }
	}

	/// # Safety
	///
	/// Same as [`as_slice_mut`], but for `MaybeUninit<u8>`. Actually the memory is initialized, as Mmap zero initializes it, but some fns like [`hermit_entry::elf::load_kernel`] require [`MaybeUninit`]s.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn as_slice_uninit_mut(&self) -> &mut [MaybeUninit<u8>] {
		unsafe {
			std::slice::from_raw_parts_mut(self.host_start() as *mut MaybeUninit<u8>, self.size())
		}
	}

	/// Converts `addr` to a `MemoryRegionAddress` that is relative to the internally used memory.
	fn addr_to_mem_region_addr(
		&self,
		addr: GuestPhysAddr,
	) -> Result<MemoryRegionAddress, MemoryError> {
		Ok(MemoryRegionAddress(
			addr.as_u64()
				.checked_sub(self.mem.iter().next().unwrap().start_addr().0)
				.ok_or(MemoryError::BoundsViolation)?,
		))
	}

	/// Checks if the range described by `addr` + `len` is part of this memory region
	fn check_range(&self, addr: MemoryRegionAddress, len: usize) -> Result<bool, MemoryError> {
		Ok(self.region_mmap().address_in_range(addr)
			&& self.region_mmap().address_in_range(
				addr.checked_add(if len > 0 { len as u64 - 1 } else { 0 })
					.ok_or(MemoryError::BoundsViolation)?,
			))
	}

	/// Read a section of the memory.
	///
	/// # Safety
	///
	/// This is unsafe, as can create multiple aliasing. During the lifetime of
	/// the returned slice, the memory must not be altered to prevent undfined
	/// behaviour.
	pub unsafe fn slice_at(&self, addr: GuestPhysAddr, len: usize) -> Result<&[u8], MemoryError> {
		let guest_addr = self.addr_to_mem_region_addr(addr)?;
		if self.check_range(guest_addr, len)? {
			Ok(unsafe {
				std::slice::from_raw_parts_mut(
					self.region_mmap().get_host_address(guest_addr).unwrap(),
					len,
				)
			})
		} else {
			Err(MemoryError::BoundsViolation)
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
		let guest_addr = self.addr_to_mem_region_addr(addr)?;
		if self.check_range(guest_addr, len)? {
			Ok(unsafe {
				std::slice::from_raw_parts_mut(
					self.region_mmap().get_host_address(guest_addr).unwrap(),
					len,
				)
			})
		} else {
			Err(MemoryError::BoundsViolation)
		}
	}

	/// Returns the host address of the given internal physical address in the
	/// memory, if the address is valid.
	pub fn host_address(&self, addr: GuestPhysAddr) -> Result<*const u8, MemoryError> {
		let ptr = self
			.region_mmap()
			.get_host_address(
				self.region_mmap()
					.to_region_addr(GuestAddress(addr.as_u64()))
					.unwrap(),
			)
			.unwrap();
		Ok(ptr as *const u8)
	}

	/// Read the value in the memory at the given address
	#[cfg(test)]
	pub fn read<T>(&self, addr: GuestPhysAddr) -> Result<T, MemoryError> {
		Ok(unsafe { self.host_address(addr)?.cast::<T>().read_unaligned() })
	}

	unsafe fn get_ptr_internal(&self, addr: MemoryRegionAddress) -> Result<*mut u8, MemoryError> {
		self.region_mmap()
			.get_host_address(addr)
			.map_err(|_| MemoryError::BoundsViolation)
	}

	/// # Safety
	///
	/// Get a reference to the type at the given address in the memory.
	#[allow(dead_code)] // currently not used on every architecture and OS
	pub unsafe fn get_ref<T>(&self, addr: GuestPhysAddr) -> Result<&T, MemoryError> {
		let guest_addr = self.addr_to_mem_region_addr(addr)?;
		if self.check_range(guest_addr, std::mem::size_of::<T>())? {
			Ok(unsafe { &*(self.get_ptr_internal(guest_addr)? as *const T) })
		} else {
			Err(MemoryError::BoundsViolation)
		}
	}

	/// # Safety
	///
	/// Get a mutable reference to the type at the given address in the memory.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn get_ref_mut<T>(&self, addr: GuestPhysAddr) -> Result<&mut T, MemoryError> {
		let guest_addr = self.addr_to_mem_region_addr(addr)?;
		if self.check_range(guest_addr, std::mem::size_of::<T>())? {
			Ok(unsafe { &mut *(self.get_ptr_internal(guest_addr)? as *mut T) })
		} else {
			Err(MemoryError::BoundsViolation)
		}
	}

	/// Produces a (exclusive) range of all valid addresses in this memory.
	pub fn address_range(&self) -> Range<GuestPhysAddr> {
		self.guest_addr()..self.guest_addr() + self.size() as u64
	}

	/// Same as [`address_range`] but with `u64` as range type.
	// TODO: Eliminate usages in favor of `address_range`
	pub fn address_range_u64(&self) -> Range<u64> {
		self.guest_addr().as_u64()..self.guest_addr().as_u64() + self.size() as u64
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
			let mem = MmapMemory::new(40 * PAGE_SIZE, GuestPhysAddr::new(address), true, true);
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
