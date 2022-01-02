use crate::aarch64::BootInfo;
use crate::macos::aarch64::vcpu::*;
use crate::macos::aarch64::HYPERVISOR_PAGE_SIZE;
use crate::params::Params;
use crate::vm::HypervisorResult;
use crate::vm::Vm;
use libc;
use libc::c_void;
use log::debug;
use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::ptr::read_volatile;
use xhypervisor::{create_vm, map_mem, unmap_mem, MemPerm};

pub struct Uhyve {
	offset: u64,
	entry_point: u64,
	mem_size: usize,
	guest_mem: *mut c_void,
	num_cpus: u32,
	path: PathBuf,
	boot_info: *const BootInfo,
	verbose: bool,
}

impl std::fmt::Debug for Uhyve {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Uhyve")
			.field("entry_point", &self.entry_point)
			.field("mem_size", &self.mem_size)
			.field("guest_mem", &self.guest_mem)
			.field("num_cpus", &self.num_cpus)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("verbose", &self.verbose)
			.finish()
	}
}

impl Uhyve {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<Uhyve> {
		let memory_size = params.memory_size.get();

		assert!(HYPERVISOR_PAGE_SIZE < memory_size);

		let mem = unsafe {
			libc::mmap(
				std::ptr::null_mut(),
				memory_size,
				libc::PROT_READ | libc::PROT_WRITE,
				libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
				-1,
				0,
			)
		};

		assert_ne!(libc::MAP_FAILED, mem, "mmap failed");

		debug!("Allocate memory for the guest at 0x{:x}", mem as usize);

		debug!("Create VM...");
		create_vm()?;

		debug!("Map guest memory...");
		unsafe {
			map_mem(
				std::slice::from_raw_parts(mem as *mut u8, HYPERVISOR_PAGE_SIZE),
				0,
				MemPerm::Read,
			)?;

			map_mem(
				std::slice::from_raw_parts_mut(
					(mem as *mut u8).offset(HYPERVISOR_PAGE_SIZE.try_into().unwrap()),
					memory_size - HYPERVISOR_PAGE_SIZE,
				),
				HYPERVISOR_PAGE_SIZE.try_into().unwrap(),
				MemPerm::ExecAndWrite,
			)?;
		}

		let hyve = Uhyve {
			offset: 0,
			entry_point: 0,
			mem_size: memory_size,
			guest_mem: mem,
			num_cpus: params.cpu_count.get(),
			path: kernel_path,
			boot_info: ptr::null(),
			verbose: params.verbose,
		};

		hyve.init_guest_mem();

		Ok(hyve)
	}
}

impl Vm for Uhyve {
	fn verbose(&self) -> bool {
		self.verbose
	}

	fn set_offset(&mut self, offset: u64) {
		self.offset = offset;
	}

	fn get_offset(&self) -> u64 {
		self.offset
	}

	fn set_entry_point(&mut self, entry: u64) {
		self.entry_point = entry;
	}

	fn get_entry_point(&self) -> u64 {
		self.entry_point
	}

	fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.guest_mem as *mut u8, self.mem_size)
	}

	fn kernel_path(&self) -> &Path {
		self.path.as_path()
	}

	fn create_cpu(&self, id: u32) -> HypervisorResult<UhyveCPU> {
		Ok(UhyveCPU::new(
			id,
			self.path.clone(),
			self.guest_mem as usize,
		))
	}

	fn get_ip(&self) -> Option<Ipv4Addr> {
		None
	}

	fn get_gateway(&self) -> Option<Ipv4Addr> {
		None
	}

	fn get_mask(&self) -> Option<Ipv4Addr> {
		None
	}

	fn set_boot_info(&mut self, header: *const BootInfo) {
		self.boot_info = header;
	}

	fn cpu_online(&self) -> u32 {
		if self.boot_info.is_null() {
			0
		} else {
			unsafe { read_volatile(&(*self.boot_info).cpu_online) }
		}
	}

	fn init_guest_mem(&self) {
		debug!("Initialize guest memory");

		// TODO: initialization if missing
		//let (mem_addr, _) = self.guest_mem();
	}
}

impl Drop for Uhyve {
	fn drop(&mut self) {
		debug!("Drop virtual machine");

		unmap_mem(0, self.mem_size).unwrap();

		unsafe {
			libc::munmap(self.guest_mem, self.mem_size);
		}
	}
}

unsafe impl Send for Uhyve {}
unsafe impl Sync for Uhyve {}
