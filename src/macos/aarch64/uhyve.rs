use std::{
	ffi::OsString,
	path::{Path, PathBuf},
	ptr,
};

use hermit_entry::boot_info::RawBootInfo;
use libc::{self, c_void};
use log::debug;
use xhypervisor::{create_vm, map_mem, unmap_mem, MemPerm};

use crate::{
	aarch64::{PT_MEM, PT_MEM_CD, PT_PT, PT_SELF},
	consts::{BOOT_INFO_ADDR, BOOT_PGT, PAGE_SIZE},
	macos::aarch64::{vcpu::*, HYPERVISOR_PAGE_SIZE},
	params::Params,
	vm::{HypervisorResult, Vm},
};

pub struct Uhyve {
	offset: u64,
	entry_point: u64,
	stack_address: u64,
	mem_size: usize,
	guest_mem: *mut c_void,
	num_cpus: u32,
	path: PathBuf,
	args: Vec<OsString>,
	boot_info: *const RawBootInfo,
	verbose: bool,
}

impl std::fmt::Debug for Uhyve {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Uhyve")
			.field("entry_point", &self.entry_point)
			.field("stack_address", &self.stack_address)
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
			stack_address: 0,
			mem_size: memory_size,
			guest_mem: mem,
			num_cpus: params.cpu_count.get(),
			path: kernel_path,
			args: params.kernel_args,
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

	fn set_stack_address(&mut self, stack_address: u64) {
		self.stack_address = stack_address;
	}

	fn stack_address(&self) -> u64 {
		self.stack_address
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

	fn create_cpu(&self, id: u32) -> HypervisorResult<XhyveCpu> {
		Ok(XhyveCpu::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.guest_mem as usize,
		))
	}

	fn set_boot_info(&mut self, header: *const RawBootInfo) {
		self.boot_info = header;
	}
}

impl Drop for Uhyve {
	fn drop(&mut self) {
		unmap_mem(0, self.mem_size).unwrap();

		unsafe {
			libc::munmap(self.guest_mem, self.mem_size);
		}
	}
}

unsafe impl Send for Uhyve {}
unsafe impl Sync for Uhyve {}
