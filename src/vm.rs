use std::{
	fmt, fs, io,
	marker::PhantomData,
	num::NonZeroU32,
	path::PathBuf,
	ptr,
	sync::{Arc, Mutex},
	time::SystemTime,
};

use hermit_entry::{
	boot_info::{BootInfo, HardwareInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use log::{error, warn};
use sysinfo::System;
use thiserror::Error;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{
	detect_freq_from_cpuid, detect_freq_from_cpuid_hypervisor_info, get_cpu_frequency_from_os,
};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use crate::linux::x86_64::kvm_cpu::initialize_kvm;
use crate::{
	arch, arch::FrequencyDetectionFailed, consts::*, mem::MmapMemory, os::HypervisorError,
	params::Params, vcpu::VirtualCPU, virtio::*,
};

pub type HypervisorResult<T> = Result<T, HypervisorError>;

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

pub fn detect_freq_from_sysinfo() -> std::result::Result<u32, FrequencyDetectionFailed> {
	debug!("Trying to detect CPU frequency using sysinfo");

	let mut system = System::new();
	system.refresh_cpu_frequency();

	let frequency = system.cpus().first().unwrap().frequency();
	println!("frequencies: {frequency:?}");

	if !system.cpus().iter().all(|cpu| cpu.frequency() == frequency) {
		// Even if the CPU frequencies are not all equal, the
		// frequency of the "first" CPU is treated as "authoritative".
		eprintln!("CPU frequencies are not all equal");
	}

	if frequency > 0 {
		Ok(frequency.try_into().unwrap())
	} else {
		Err(FrequencyDetectionFailed)
	}
}

// TODO: move to architecture specific section
fn detect_cpu_freq() -> u32 {
	#[cfg(target_arch = "aarch64")]
	let mhz: u32 = detect_freq_from_sysinfo().unwrap_or_else(|_| {
		debug!("Failed to detect using sysinfo");
		0
	});
	#[cfg(target_arch = "x86_64")]
	let mhz = {
		let mhz: u32 = detect_freq_from_sysinfo().unwrap_or_else(|_| {
			debug!("Failed to detect using sysinfo");
			let cpuid = raw_cpuid::CpuId::new();
			detect_freq_from_cpuid(&cpuid).unwrap_or_else(|_| {
				debug!("Failed to detect from cpuid");
				detect_freq_from_cpuid_hypervisor_info(&cpuid).unwrap_or_else(|_| {
					debug!("Failed to detect from hypervisor_info");
					get_cpu_frequency_from_os().unwrap_or(0)
				})
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

#[cfg(target_os = "linux")]
pub type VcpuDefault = crate::linux::x86_64::kvm_cpu::KvmCpu;
#[cfg(target_os = "macos")]
pub type VcpuDefault = crate::macos::XhyveCpu;

pub struct UhyveVm<VCpuType: VirtualCPU = VcpuDefault> {
	/// The starting position of the image in physical memory
	offset: u64,
	entry_point: u64,
	stack_address: u64,
	pub mem: Arc<MmapMemory>,
	pub params: Params,
	memory_size: usize,
	num_cpus: u32,
	path: PathBuf,
	boot_info: *const RawBootInfo,
	pub virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
	#[allow(dead_code)] // gdb is not supported on macos
	pub(super) gdb_port: Option<u16>,
	_vcpu_type: PhantomData<VCpuType>,
}
impl<VCpuType: VirtualCPU> UhyveVm<VCpuType> {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<UhyveVm<VCpuType>> {
		// We expose the params struct, but use some extra variables for the
		// gdb_port (because of pub(super)) and memory_size (later, num_cpus)
		// which require a get() to reduce overhead, and, most importantly,
		// increase flexibility.
		let memory_size = params.memory_size.get();
		let gdb_port = params.gdb_port;

		#[cfg(target_os = "linux")]
		let mem = MmapMemory::new(0, memory_size, arch::RAM_START, params.thp, params.ksm);
		#[cfg(not(target_os = "linux"))]
		let mem = MmapMemory::new(0, memory_size, arch::RAM_START, false, false);

		// create virtio interface
		// TODO: Remove allow once fixed:
		// https://github.com/rust-lang/rust-clippy/issues/11382
		#[allow(clippy::arc_with_non_send_sync)]
		let virtio_device = Arc::new(Mutex::new(VirtioNetPciDevice::new()));

		#[cfg(target_os = "linux")]
		initialize_kvm(&mem, params.pit)?;

		let num_cpus = params.cpu_count.get();

		assert!(
			gdb_port.is_none() || cfg!(target_os = "linux"),
			"gdb is only supported on linux (yet)"
		);
		assert!(
			gdb_port.is_none() || num_cpus == 1,
			"gdbstub is only supported with one CPU"
		);

		let mut vm = Self {
			offset: 0,
			entry_point: 0,
			stack_address: 0,
			mem: mem.into(),
			params,
			memory_size,
			num_cpus,
			path: kernel_path,
			boot_info: ptr::null(),
			virtio_device,
			gdb_port,
			_vcpu_type: PhantomData,
		};

		vm.init_guest_mem();

		Ok(vm)
	}

	/// Returns the section offsets relative to their base addresses
	pub fn get_offset(&self) -> u64 {
		self.offset
	}

	pub fn get_entry_point(&self) -> u64 {
		self.entry_point
	}

	pub fn stack_address(&self) -> u64 {
		self.stack_address
	}

	// Returns the struct containing all parameters.
	pub fn params(&self) -> &Params {
		&self.params
	}

	// Returns the total memory size made available.
	pub fn memory_size(&self) -> usize {
		self.memory_size
	}

	// Returns number of cores for the VM.
	pub fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	pub fn kernel_path(&self) -> &PathBuf {
		&self.path
	}

	/// Initialize the page tables for the guest
	fn init_guest_mem(&mut self) {
		debug!("Initialize guest memory");
		crate::arch::init_guest_mem(
			unsafe { self.mem.as_slice_mut() } // slice only lives during this fn call
				.try_into()
				.expect("Guest memory is not large enough for pagetables"),
		);
	}

	pub fn load_kernel(&mut self) -> LoadKernelResult<()> {
		let elf = fs::read(self.kernel_path())?;
		let object = KernelObject::parse(&elf).map_err(LoadKernelError::ParseKernelError)?;

		// TODO: should be a random start address, if we have a relocatable executable
		let kernel_start_address = object.start_addr().unwrap_or(0x400000) as usize;
		let kernel_end_address = kernel_start_address + object.mem_size();
		self.offset = kernel_start_address as u64;

		if kernel_end_address > self.mem.memory_size - self.mem.guest_address.as_u64() as usize {
			return Err(LoadKernelError::InsufficientMemory);
		}

		let LoadedKernel {
			load_info,
			entry_point,
		} = object.load_kernel(
			// Safety: Slice only lives during this fn call, so no aliasing happens
			&mut unsafe { self.mem.as_slice_uninit_mut() }
				[kernel_start_address..kernel_end_address],
			kernel_start_address as u64,
		);
		self.entry_point = entry_point;

		let boot_info = BootInfo {
			hardware_info: HardwareInfo {
				phys_addr_range: self.mem.guest_address.as_u64()
					..self.mem.guest_address.as_u64() + self.mem.memory_size as u64,
				serial_port_base: self.params.verbose.then(|| {
					SerialPortBase::new((uhyve_interface::HypercallAddress::Uart as u16).into())
						.unwrap()
				}),
				device_tree: None,
			},
			load_info,
			platform_info: PlatformInfo::Uhyve {
				has_pci: cfg!(target_os = "linux"),
				num_cpus: u64::from(self.num_cpus).try_into().unwrap(),
				cpu_freq: NonZeroU32::new(detect_cpu_freq() * 1000),
				boot_time: SystemTime::now().into(),
			},
		};
		unsafe {
			let raw_boot_info_ptr =
				self.mem.host_address.add(BOOT_INFO_ADDR.as_u64() as usize) as *mut RawBootInfo;
			*raw_boot_info_ptr = RawBootInfo::from(boot_info);
			self.boot_info = raw_boot_info_ptr;
		}

		self.stack_address = (kernel_start_address as u64)
			.checked_sub(KERNEL_STACK_SIZE)
			.expect(
				"there should be enough space for the boot stack before the kernel start address",
			);

		Ok(())
	}
}

impl<VCpuType: VirtualCPU> fmt::Debug for UhyveVm<VCpuType> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("UhyveVm")
			.field("entry_point", &self.entry_point)
			.field("stack_address", &self.stack_address)
			.field("mem", &self.mem)
			.field("params", &self.params)
			.field("memory_size", &self.memory_size)
			.field("num_cpus", &self.num_cpus)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("virtio_device", &self.virtio_device)
			.finish()
	}
}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<VCpuType: VirtualCPU> Send for UhyveVm<VCpuType> {}
unsafe impl<VCpuType: VirtualCPU> Sync for UhyveVm<VCpuType> {}

#[cfg(test)]
mod tests {
	#[test]
	// derived from test_get_cpu_frequency_from_os() in src/arch/x86_64/mod.rs
	fn test_detect_freq_from_sysinfo() {
		let freq_res = crate::vm::detect_freq_from_sysinfo();

		#[cfg(target_os = "macos")]
		// The CI always returns 0 as freq and thus a None in the MacOS CI
		if option_env!("CI").is_some() {
			return;
		}

		assert!(freq_res.is_ok());
		let freq = freq_res.unwrap();
		// The unit of the value for the first core must be in MHz.
		// We presume that more than 10 GHz is incorrect.
		assert!(freq > 0);
		assert!(freq < 10000);
	}
}
