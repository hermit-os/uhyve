//! This file contains the entry point to the Hypervisor. The ehyve utilizes KVM to
//! create a Virtual Machine and load the kernel.

use error::*;
use kvm_bindings::*;
use kvm_ioctls::VmFd;
use libc;
use std;
use std::convert::TryInto;
use vm::{VirtualCPU, Vm};
use x86_64::vcpu::*;
use x86_64::{MemorySlot, KVM};

pub struct Ehyve {
	vm: VmFd,
	entry_point: u64,
	mem: MmapMemorySlot,
	num_cpus: u32,
	path: String,
}

impl Ehyve {
	pub fn new(kernel_path: String, mem_size: usize, num_cpus: u32) -> Result<Ehyve> {
		let vm = KVM.create_vm().unwrap();

		let mut cap: kvm_enable_cap = Default::default();
		cap.cap = KVM_CAP_SET_TSS_ADDR;
		if vm.enable_cap(&cap).is_ok() {
			debug!("Setting TSS address");
			vm.set_tss_address(0xfffbd000).unwrap();
		}

		let mem = MmapMemorySlot::new(0, 0, mem_size, 0);
		unsafe {
			vm.set_user_memory_region(mem.mem_region).unwrap();
		}

		let mut hyve = Ehyve {
			vm: vm,
			entry_point: 0,
			mem: mem,
			num_cpus: num_cpus,
			path: kernel_path,
		};

		hyve.init()?;

		Ok(hyve)
	}

	fn init(&mut self) -> Result<()> {
		self.init_guest_mem();

		debug!("Initialize interrupt controller");

		match self.vm.create_irq_chip() {
			Err(_) => return Err(Error::KVMUnableToCreateIrqChip),
			_ => {}
		};

		let pit_config = kvm_pit_config::default();
		match self.vm.create_pit2(pit_config) {
			Err(_) => return Err(Error::KVMUnableToCreatePit2),
			_ => {}
		};

		Ok(())
	}
}

impl Vm for Ehyve {
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
		(self.mem.host_address() as *mut u8, self.mem.memory_size())
	}

	fn kernel_path(&self) -> &str {
		&self.path
	}

	fn create_cpu(&self, id: u32) -> Result<Box<dyn VirtualCPU>> {
		let vm_start = self.mem.host_address() as usize;
		Ok(Box::new(EhyveCPU::new(
			id,
			self.path.clone(),
			self.vm.create_vcpu(id.try_into().unwrap()).unwrap(),
			vm_start,
		)))
	}
}

impl Drop for Ehyve {
	fn drop(&mut self) {
		debug!("Drop virtual machine");
	}
}

unsafe impl Send for Ehyve {}
unsafe impl Sync for Ehyve {}

#[derive(Debug)]
struct MmapMemorySlot {
	pub mem_region: kvm_userspace_memory_region,
}

impl MmapMemorySlot {
	pub fn new(id: u32, flags: u32, memory_size: usize, guest_address: u64) -> MmapMemorySlot {
		let host_address = unsafe {
			libc::mmap(
				std::ptr::null_mut(),
				memory_size,
				libc::PROT_READ | libc::PROT_WRITE,
				libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
				-1,
				0,
			)
		};

		if host_address == libc::MAP_FAILED {
			panic!("mmap failed with: {}", unsafe { *libc::__errno_location() });
		}

		MmapMemorySlot {
			mem_region: kvm_userspace_memory_region {
				slot: id,
				flags: flags,
				memory_size: memory_size as u64,
				guest_phys_addr: guest_address,
				userspace_addr: host_address as u64,
			},
		}
	}

	#[allow(dead_code)]
	fn as_slice_mut(&mut self) -> &mut [u8] {
		unsafe {
			std::slice::from_raw_parts_mut(
				self.mem_region.userspace_addr as *mut u8,
				self.mem_region.memory_size as usize,
			)
		}
	}
}

impl MemorySlot for MmapMemorySlot {
	fn slot_id(&self) -> u32 {
		self.mem_region.slot
	}

	fn flags(&self) -> u32 {
		self.mem_region.flags
	}

	fn memory_size(&self) -> usize {
		self.mem_region.memory_size as usize
	}

	fn guest_address(&self) -> u64 {
		self.mem_region.guest_phys_addr as u64
	}

	fn host_address(&self) -> u64 {
		self.mem_region.userspace_addr as u64
	}
}

impl Drop for MmapMemorySlot {
	fn drop(&mut self) {
		if self.memory_size() > 0 {
			let result = unsafe {
				libc::munmap(self.host_address() as *mut libc::c_void, self.memory_size())
			};
			if result != 0 {
				panic!("munmap failed with: {}", unsafe {
					*libc::__errno_location()
				});
			}
		}
	}
}
