use crate::aarch64::{PT_MEM, PT_MEM_CD, PT_PT, PT_SELF};
use crate::consts::{BOOT_INFO_ADDR, BOOT_PGT, PAGE_SIZE};
use crate::macos::aarch64::vcpu::*;
use crate::macos::aarch64::HYPERVISOR_PAGE_SIZE;
use crate::params::Params;
use crate::vm::HypervisorResult;
use crate::vm::Vm;
use hermit_entry::boot_info::RawBootInfo;
use libc;
use libc::c_void;
use log::debug;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use xhypervisor::{create_vm, map_mem, unmap_mem, MemPerm};

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

	fn create_cpu(&self, id: u32) -> HypervisorResult<UhyveCPU> {
		Ok(UhyveCPU::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.guest_mem as usize,
		))
	}

	fn set_boot_info(&mut self, header: *const RawBootInfo) {
		self.boot_info = header;
	}

	fn init_guest_mem(&self) {
		debug!("Initialize guest memory");

		let (mem_addr, _) = self.guest_mem();

		let pgt_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset(BOOT_PGT.try_into().unwrap()) as *mut u64,
				512,
			)
		};
		for i in pgt_slice.iter_mut() {
			*i = 0;
		}
		pgt_slice[0] = BOOT_PGT + 0x1000 + PT_PT;
		pgt_slice[511] = BOOT_PGT + PT_PT + PT_SELF;

		let pgt_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((BOOT_PGT + 0x1000).try_into().unwrap()) as *mut u64,
				512,
			)
		};
		for i in pgt_slice.iter_mut() {
			*i = 0;
		}
		pgt_slice[0] = BOOT_PGT + 0x2000 + PT_PT;

		let pgt_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((BOOT_PGT + 0x2000).try_into().unwrap()) as *mut u64,
				512,
			)
		};
		for i in pgt_slice.iter_mut() {
			*i = 0;
		}
		pgt_slice[0] = BOOT_PGT + 0x3000 + PT_PT;
		pgt_slice[1] = BOOT_PGT + 0x4000 + PT_PT;
		pgt_slice[2] = BOOT_PGT + 0x5000 + PT_PT;

		let pgt_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((BOOT_PGT + 0x3000).try_into().unwrap()) as *mut u64,
				512,
			)
		};
		for i in pgt_slice.iter_mut() {
			*i = 0;
		}
		// map uhyve ports into the virtual address space
		pgt_slice[0] = PT_MEM_CD;
		// map BootInfo into the virtual address space
		pgt_slice[BOOT_INFO_ADDR as usize / PAGE_SIZE] = BOOT_INFO_ADDR + PT_MEM;

		let pgt_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((BOOT_PGT + 0x4000).try_into().unwrap()) as *mut u64,
				512,
			)
		};
		for (idx, i) in pgt_slice.iter_mut().enumerate() {
			*i = 0x200000u64 + (idx * PAGE_SIZE) as u64 + PT_MEM;
		}

		let pgt_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mem_addr.offset((BOOT_PGT + 0x5000).try_into().unwrap()) as *mut u64,
				512,
			)
		};
		for (idx, i) in pgt_slice.iter_mut().enumerate() {
			*i = 0x400000u64 + (idx * PAGE_SIZE) as u64 + PT_MEM;
		}
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
