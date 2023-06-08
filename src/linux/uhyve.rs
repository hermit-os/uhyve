//! This file contains the entry point to the Hypervisor. The Uhyve utilizes KVM to
//! create a Virtual Machine and load the kernel.

use std::{
	ffi::OsString,
	fmt,
	path::{Path, PathBuf},
	ptr,
	sync::{Arc, Mutex},
};

use hermit_entry::boot_info::RawBootInfo;

use crate::{
	linux::x86_64::kvm_cpu::{initialize_kvm, KvmCpu},
	mem::MmapMemory,
	params::Params,
	virtio::*,
	vm::{Vm, VmGuestMemory},
	HypervisorResult,
};

pub struct Uhyve {
	offset: u64,
	entry_point: u64,
	stack_address: u64,
	mem: MmapMemory,
	num_cpus: u32,
	path: PathBuf,
	args: Vec<OsString>,
	boot_info: *const RawBootInfo,
	verbose: bool,
	virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
	pub(super) gdb_port: Option<u16>,
}

impl fmt::Debug for Uhyve {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Uhyve")
			.field("entry_point", &self.entry_point)
			.field("stack_address", &self.stack_address)
			.field("mem", &self.mem)
			.field("num_cpus", &self.num_cpus)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("verbose", &self.verbose)
			.field("virtio_device", &self.virtio_device)
			.finish()
	}
}

impl Uhyve {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<Uhyve> {
		let memory_size = params.memory_size.get();

		let mem = MmapMemory::new(0, memory_size, 0, params.thp, params.ksm);

		// create virtio interface
		// TODO: Remove allow once fixed:
		// https://github.com/rust-lang/rust-clippy/issues/11382
		#[allow(clippy::arc_with_non_send_sync)]
		let virtio_device = Arc::new(Mutex::new(VirtioNetPciDevice::new()));

		initialize_kvm(&mem, params.pit)?;

		let cpu_count = params.cpu_count.get();

		assert!(
			params.gdb_port.is_none() || cpu_count == 1,
			"gdbstub is only supported with one CPU"
		);

		let mut hyve = Uhyve {
			offset: 0,
			entry_point: 0,
			stack_address: 0,
			mem,
			num_cpus: cpu_count,
			path: kernel_path,
			args: params.kernel_args,
			boot_info: ptr::null(),
			verbose: params.verbose,
			virtio_device,
			gdb_port: params.gdb_port,
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

	fn set_stack_address(&mut self, stack_addresss: u64) {
		self.stack_address = stack_addresss;
	}

	fn stack_address(&self) -> u64 {
		self.stack_address
	}

	fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.mem.host_address as *mut u8, self.mem.memory_size)
	}

	fn kernel_path(&self) -> &Path {
		self.path.as_path()
	}

	fn create_cpu(&self, id: u32) -> HypervisorResult<KvmCpu> {
		KvmCpu::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.mem.host_address,
			self.virtio_device.clone(),
		)
	}

	fn set_boot_info(&mut self, header: *const RawBootInfo) {
		self.boot_info = header;
	}

	/// Initialize the page tables for the guest
	fn init_guest_mem(&mut self) {
		self.mem.init_guest_mem();
	}
}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Uhyve {}
unsafe impl Sync for Uhyve {}
