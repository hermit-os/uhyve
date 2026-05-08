#[cfg(unix)]
use std::{fs::File, sync::Arc};
use std::{
	io::{self, Write},
	ops::Range,
};
#[cfg(target_os = "linux")]
use std::{os::raw::c_void, ptr::NonNull};
#[cfg(not(unix))]
use std::{ptr, thread};

#[cfg(target_os = "linux")]
use nix::sys::mman::{MmapAdvise, madvise};
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;
use vm_memory::{
	Address, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
	MemoryRegionAddress, guest_memory::FileOffset, mmap::MmapRegionBuilder,
};

use crate::mem_layout::Section;

#[derive(Error, Debug)]
pub enum MemoryError {
	#[error("Memory bounds exceeded")]
	BoundsViolation,
}
#[cfg(target_os = "linux")]
fn linux_guest_mmap_advise(ptr: *mut u8, len: usize, mergeable: bool, huge_pages: bool) {
	let ptr = NonNull::new(ptr as *mut c_void).unwrap();
	if mergeable {
		debug!("Enable kernel feature to merge same pages");
		unsafe {
			madvise(ptr, len, MmapAdvise::MADV_MERGEABLE).unwrap();
		}
	}
	if huge_pages {
		debug!("Uhyve uses huge pages");
		unsafe {
			madvise(ptr, len, MmapAdvise::MADV_HUGEPAGE).unwrap();
		}
	}
}

#[cfg(not(target_os = "linux"))]
fn linux_guest_mmap_advise(_ptr: *mut u8, _len: usize, mergeable: bool, huge_pages: bool) {
	if mergeable {
		error!("OS does not support same page merging");
	}
	if huge_pages {
		error!("OS does not support huge pages");
	}
}

/// Guest RAM image prepared outside the hot restore path: writable backing fd filled once,
/// then [`MmapMemory::from_prepared_ram_private`] maps it `MAP_PRIVATE` for lazy, CoW-backed pages.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub(crate) struct GuestRamFile {
	pub(crate) file: Arc<File>,
	pub(crate) len: usize,
}

#[cfg(unix)]
impl GuestRamFile {
	pub(crate) fn prepare_from_ram(ram: &[u8]) -> io::Result<Self> {
		let mut file = guest_ram_backing_file()?;
		file.write_all(ram)?;
		file.sync_data()?;
		Ok(Self {
			file: Arc::new(file),
			len: ram.len(),
		})
	}
}

#[cfg(all(unix, target_os = "linux"))]
fn guest_ram_backing_file() -> io::Result<File> {
	use std::os::fd::FromRawFd;

	let fd = unsafe {
		libc::memfd_create(
			c"uhyve-guest-ram".as_ptr().cast::<libc::c_char>(),
			libc::MFD_CLOEXEC,
		)
	};
	if fd >= 0 {
		return Ok(unsafe { File::from_raw_fd(fd) });
	}
	Err(io::Error::last_os_error())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn guest_ram_backing_file() -> io::Result<File> {
	Err(io::Error::new(
		io::ErrorKind::Unsupported,
		"guest RAM snapshot backing uses Linux memfd_create only (RAM-copy fallback not implemented)",
	))
}

/// A general purpose VM memory section that can exploit some Linux Kernel features.
/// Uses `GuestMemoryMmap` under the hood.
#[derive(Debug)]
pub(crate) struct MmapMemory {
	pub(crate) mem: GuestMemoryMmap,
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

		linux_guest_mmap_advise(mm_region.as_ptr(), memory_size, mergeable, huge_pages);

		Self {
			mem: GuestMemoryMmap::from_regions(vec![
				GuestRegionMmap::<()>::new(mm_region, GuestAddress(guest_address.as_u64()))
					.unwrap(),
			])
			.unwrap(),
		}
	}

	/// Map [`PreparedGuestRam`] with `MAP_PRIVATE` (CoW vs backing fd). Does not copy guest RAM;
	/// pages populate on fault when the guest touches them.
	#[cfg(unix)]
	pub(crate) fn from_ram_file(
		prepared: &GuestRamFile,
		guest_address: GuestPhysAddr,
		huge_pages: bool,
		mergeable: bool,
	) -> io::Result<Self> {
		let mmap_region = MmapRegionBuilder::new_with_bitmap(prepared.len, ())
			.with_file_offset(FileOffset::from_arc(Arc::clone(&prepared.file), 0))
			.with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
			.with_mmap_flags(libc::MAP_NORESERVE | libc::MAP_PRIVATE)
			.build()
			.map_err(io::Error::other)?;
		let guest_base = GuestAddress(guest_address.as_u64());
		let region = GuestRegionMmap::<()>::new(mmap_region, guest_base).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidInput,
				"guest address and RAM size overflow guest physical space",
			)
		})?;

		linux_guest_mmap_advise(region.as_ptr(), prepared.len, mergeable, huge_pages);

		let mem = GuestMemoryMmap::from_regions(vec![region])
			.map_err(|e| io::Error::other(e.to_string()))?;
		Ok(Self { mem })
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
	/// - This can create multiple aliasing. During the lifetime of the returned slice, the memory must
	///   not be altered to prevent undfined behaviour.
	/// - `addr` must have proper alignment of `T`
	pub unsafe fn slice_at<T>(&self, addr: GuestPhysAddr, len: usize) -> Result<&[T], MemoryError> {
		let guest_addr = self.addr_to_mem_region_addr(addr)?;
		let len_bytes = len * size_of::<T>();
		if self.check_range(guest_addr, len_bytes)? {
			Ok(unsafe {
				std::slice::from_raw_parts_mut(
					self.region_mmap().get_host_address(guest_addr).unwrap() as *mut T,
					len_bytes,
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
	/// - This can create multiple aliasing. During the lifetime of the returned slice, the memory must
	///   not be altered to prevent undfined behaviour.
	/// - `addr` must have proper alignment of `T`
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn slice_at_mut<T>(
		&self,
		addr: GuestPhysAddr,
		len: usize,
	) -> Result<&mut [T], MemoryError> {
		let guest_addr = self.addr_to_mem_region_addr(addr)?;
		let len_bytes = len * size_of::<T>();
		if self.check_range(guest_addr, len_bytes)? {
			Ok(unsafe {
				std::slice::from_raw_parts_mut(
					self.region_mmap().get_host_address(guest_addr).unwrap() as *mut T,
					len_bytes,
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

	/// Convenience wrapper around [`slice_at`] to work directly on [`Section`]s. Same safety rules apply.
	#[expect(dead_code)] // not yet used.
	pub unsafe fn section_slice<T>(&self, section: Section) -> Result<&[T], MemoryError> {
		assert_eq!(section.length % size_of::<T>(), 0);
		unsafe { self.slice_at(section.start(), section.length / size_of::<T>()) }
	}

	/// Convenience wrapper around [`slice_at_mut`] to work directly on [`Section`]s. Same safety rules apply.
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn section_slice_mut<T>(&self, section: Section) -> Result<&mut [T], MemoryError> {
		assert_eq!(section.length % size_of::<T>(), 0);
		unsafe { self.slice_at_mut(section.start(), section.length / size_of::<T>()) }
	}
}

#[cfg(not(unix))]
/// Copies deserialized snapshot RAM into a fresh mmap.
///
/// Large regions use parallelised `memcpy`s.
pub(crate) fn parallel_copy(dst: &mut [u8], src: &[u8]) {
	assert_eq!(
		dst.len(),
		src.len(),
		"guest RAM and snapshot payload length mismatch"
	);
	let len = dst.len();
	const MIN_CHUNK: usize = 2 * 1024 * 1024;
	const PARALLEL_THRESHOLD: usize = 2 * MIN_CHUNK;

	let parallelism = thread::available_parallelism()
		.map(|n| n.get())
		.unwrap_or(1)
		.max(1);

	if parallelism == 1 || len < PARALLEL_THRESHOLD {
		dst.copy_from_slice(src);
		return;
	}

	let ideal_chunk = len.div_ceil(parallelism);
	let chunk = ideal_chunk.max(MIN_CHUNK);

	thread::scope(|scope| {
		let dst_base = dst.as_mut_ptr() as usize;
		let src_base = src.as_ptr() as usize;
		let mut off = 0usize;
		while off < len {
			let len_this = chunk.min(len - off);
			let chunk_off = off;
			off += len_this;
			scope.spawn(move || unsafe {
				let dst = (dst_base + chunk_off) as *mut u8;
				let src = (src_base + chunk_off) as *const u8;
				ptr::copy_nonoverlapping(src, dst, len_this);
			});
		}
	});
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::arch::PAGE_SIZE;

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
