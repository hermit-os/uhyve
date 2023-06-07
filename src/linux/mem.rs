use std::{mem, os::raw::c_void, ptr::NonNull};

use log::debug;
use nix::sys::mman::*;
use x86_64::{
	structures::paging::{Page, PageTable, PageTableFlags, Size2MiB},
	PhysAddr,
};

use crate::{consts::*, vm::VmGuestMemory, x86_64::create_gdt_entry};

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
			mmap_anonymous(
				None,
				memory_size.try_into().unwrap(),
				ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
				MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
			)
			.expect("mmap failed")
		};

		if mergeable {
			debug!("Enable kernel feature to merge same pages");
			unsafe {
				madvise(host_address, memory_size, MmapAdvise::MADV_MERGEABLE).unwrap();
			}
		}

		if huge_pages {
			debug!("Uhyve uses huge pages");
			unsafe {
				madvise(host_address, memory_size, MmapAdvise::MADV_HUGEPAGE).unwrap();
			}
		}

		MmapMemory {
			flags,
			memory_size,
			guest_address: guest_address as usize,
			host_address: host_address.as_ptr() as usize,
		}
	}

	#[allow(dead_code)]
	fn as_slice_mut(&mut self) -> &mut [u8] {
		unsafe { std::slice::from_raw_parts_mut(self.host_address as *mut u8, self.memory_size) }
	}
}
impl VmGuestMemory for MmapMemory {
	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.host_address as *mut u8, self.memory_size)
	}

	/// Initialize the page tables for the guest
	fn init_guest_mem(&mut self) {
		// TODO: Move to x86_64
		debug!("Initialize guest memory");

		let (mem_addr, _) = self.guest_mem();

		unsafe {
			let pml4 = &mut *((mem_addr as u64 + BOOT_PML4.as_u64()) as *mut PageTable);
			let pdpte = &mut *((mem_addr as u64 + BOOT_PDPTE.as_u64()) as *mut PageTable);
			let pde = &mut *((mem_addr as u64 + BOOT_PDE.as_u64()) as *mut PageTable);
			let gdt_entry: u64 = mem_addr as u64 + BOOT_GDT.as_u64();

			// initialize GDT
			*((gdt_entry) as *mut u64) = create_gdt_entry(0, 0, 0);
			*((gdt_entry + mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xA09B, 0, 0xFFFFF); /* code */
			*((gdt_entry + 2 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xC093, 0, 0xFFFFF); /* data */

			/* For simplicity we currently use 2MB pages and only a single
			PML4/PDPTE/PDE. */

			// per default is the memory zeroed, which we allocate by the system call mmap
			/*libc::memset(pml4 as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
			libc::memset(pdpte as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
			libc::memset(pde as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);*/

			pml4[0].set_addr(
				BOOT_PDPTE,
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);
			pml4[511].set_addr(
				BOOT_PML4,
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);
			pdpte[0].set_addr(BOOT_PDE, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

			for i in 0..512 {
				let addr = PhysAddr::new(i as u64 * Page::<Size2MiB>::SIZE);
				pde[i].set_addr(
					addr,
					PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
				);
			}
		}
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
