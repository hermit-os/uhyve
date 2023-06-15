use std::{mem::MaybeUninit, os::raw::c_void};

use log::debug;
use nix::sys::mman::*;

/// A general purpose VM memory section that can exploit some Linux Kernel features.
#[derive(Debug)]
pub struct MmapMemory {
	// TODO: make private
	pub flags: u32,
	pub memory_size: usize,
	pub guest_address: usize,
	pub host_address: usize,
}

impl MmapMemory {
	pub fn new(
		flags: u32,
		memory_size: usize,
		guest_address: u64,
		huge_pages: bool,
		mergeable: bool,
	) -> MmapMemory {
		let host_address = unsafe {
			mmap::<std::fs::File>(
				None,
				memory_size.try_into().unwrap(),
				ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
				MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_NORESERVE,
				None,
				0,
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
			guest_address: guest_address as usize,
			host_address: host_address as usize,
		}
	}

	/// This can create multiple aliasing. During the lifetime of the returned slice, the memory must not be altered, dropped or simmilar.
	#[allow(clippy::mut_from_ref)]
	pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
		std::slice::from_raw_parts_mut(self.host_address as *mut u8, self.memory_size)
	}

	/// Same as [`as_slice_mut`], but for `MaybeUninit<u8>`. Actually the memory is initialized, as Mmap zero initializes it, but some fns like [`hermit_entry::elf::load_kernel`] require [`MaybeUninit`]s.
	#[allow(clippy::mut_from_ref)]
	pub unsafe fn as_slice_uninit_mut(&self) -> &mut [MaybeUninit<u8>] {
		std::slice::from_raw_parts_mut(self.host_address as *mut MaybeUninit<u8>, self.memory_size)
	}
}

impl Drop for MmapMemory {
	fn drop(&mut self) {
		if self.memory_size > 0 {
			unsafe {
				munmap(self.host_address as *mut c_void, self.memory_size).unwrap();
			}
		}
	}
}
