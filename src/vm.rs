use std::{fs, io, mem::MaybeUninit, num::NonZeroU32, path::Path, slice, time::SystemTime};

use hermit_entry::{
	boot_info::{BootInfo, HardwareInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use log::{error, warn};
use thiserror::Error;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{
	detect_freq_from_cpuid, detect_freq_from_cpuid_hypervisor_info, get_cpu_frequency_from_os,
};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use crate::linux::x86_64::kvm_cpu::KvmCpu;
use crate::{arch, consts::*, os::HypervisorError};

pub type HypervisorResult<T> = Result<T, HypervisorError>;
#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
use crate::macos::x86_64::vcpu::XhyveCpu;

#[derive(Error, Debug)]
pub enum LoadKernelError {
	#[error(transparent)]
	Io(#[from] io::Error),
	#[error("{0}")]
	ParseKernelError(ParseKernelError),
	#[error("guest memory size is not large enough")]
	InsufficientMemory,
}

pub type LoadKernelResult<T> = Result<T, LoadKernelError>;

pub trait Vm {
	/// Returns the number of cores for the vm.
	fn num_cpus(&self) -> u32;
	/// Returns a pointer to the address of the guest memory and the size of the memory in bytes.
	fn guest_mem(&self) -> (*mut u8, usize);
	#[doc(hidden)]
	fn set_offset(&mut self, offset: u64);
	/// Returns the section offsets relative to their base addresses
	fn get_offset(&self) -> u64;
	/// Sets the elf entry point.
	fn set_entry_point(&mut self, entry: u64);
	fn get_entry_point(&self) -> u64;
	fn set_stack_address(&mut self, stack_addresss: u64);
	fn stack_address(&self) -> u64;
	fn kernel_path(&self) -> &Path;
	fn create_cpu(&self, id: u32) -> HypervisorResult<KvmCpu>;
	fn set_boot_info(&mut self, header: *const RawBootInfo);
	fn verbose(&self) -> bool;
	fn init_guest_mem(&mut self);

	unsafe fn load_kernel(&mut self) -> LoadKernelResult<()> {
		let elf = fs::read(self.kernel_path())?;
		let object = KernelObject::parse(&elf).map_err(LoadKernelError::ParseKernelError)?;

		// TODO: should be a random start address, if we have a relocatable executable
		let start_address = object.start_addr().unwrap_or(0x400000);
		self.set_offset(start_address);

		let (vm_mem, vm_mem_len) = self.guest_mem();
		if start_address as usize + object.mem_size() > vm_mem_len {
			return Err(LoadKernelError::InsufficientMemory);
		}

		let vm_slice = {
			let vm_slice = slice::from_raw_parts_mut(vm_mem as *mut MaybeUninit<u8>, vm_mem_len);
			&mut vm_slice[start_address as usize..][..object.mem_size()]
		};

		let LoadedKernel {
			load_info,
			entry_point,
		} = object.load_kernel(vm_slice, start_address);
		self.set_entry_point(entry_point);

		let boot_info = BootInfo {
			hardware_info: HardwareInfo {
				phys_addr_range: arch::RAM_START..arch::RAM_START + vm_mem_len as u64,
				serial_port_base: self.verbose().then(|| {
					SerialPortBase::new((uhyve_interface::HypercallAddress::Uart as u16).into())
						.unwrap()
				}),
				device_tree: None,
			},
			load_info,
			platform_info: PlatformInfo::Uhyve {
				has_pci: cfg!(target_os = "linux"),
				num_cpus: u64::from(self.num_cpus()).try_into().unwrap(),
				cpu_freq: NonZeroU32::new(detect_cpu_freq() * 1000),
				boot_time: SystemTime::now().into(),
			},
		};
		let raw_boot_info_ptr = vm_mem.add(BOOT_INFO_ADDR.as_u64() as usize) as *mut RawBootInfo;
		*raw_boot_info_ptr = RawBootInfo::from(boot_info);
		self.set_boot_info(raw_boot_info_ptr);
		self.set_stack_address(start_address.checked_sub(KERNEL_STACK_SIZE).expect(
			"there should be enough space for the boot stack before the kernel start address",
		));

		Ok(())
	}
}

fn detect_cpu_freq() -> u32 {
	#[cfg(target_arch = "aarch64")]
	let mhz: u32 = 0;
	#[cfg(target_arch = "x86_64")]
	let mhz = {
		let cpuid = raw_cpuid::CpuId::new();
		let mhz: u32 = detect_freq_from_cpuid(&cpuid).unwrap_or_else(|_| {
			debug!("Failed to detect from cpuid");
			detect_freq_from_cpuid_hypervisor_info(&cpuid).unwrap_or_else(|_| {
				debug!("Failed to detect from hypervisor_info");
				get_cpu_frequency_from_os().unwrap_or(0)
			})
		});
		debug!("detected a cpu frequency of {} Mhz", mhz);

		mhz
	};
	if mhz == 0 {
		warn!("Unable to determine processor frequency");
	}
	mhz
}

/// A section of memory that is reserved for the VM guest.
pub trait VmGuestMemory {
	/// returns a pointer to the address of the guest memory and the size of the memory in bytes.
	// TODO: replace with slice
	// TODO: rename to memory
	fn guest_mem(&self) -> (*mut u8, usize);

	/// Initialize the memory
	fn init_guest_mem(&mut self);
}
