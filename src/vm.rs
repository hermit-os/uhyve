use std::{
	env, fmt, fs, io,
	mem::MaybeUninit,
	num::NonZeroU32,
	path::PathBuf,
	sync::{Arc, Mutex},
	time::SystemTime,
};

use hermit_entry::{
	boot_info::{BootInfo, HardwareInfo, LoadInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use internal::VirtualizationBackendInternal;
use log::{error, warn};
use sysinfo::System;
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{
	detect_freq_from_cpuid, detect_freq_from_cpuid_hypervisor_info, get_cpu_frequency_from_os,
};
use crate::{
	arch::{self, FrequencyDetectionFailed},
	consts::*,
	fdt::Fdt,
	isolation::filemap::UhyveFileMap,
	mem::MmapMemory,
	params::Params,
	serial::UhyveSerial,
	stats::VmStats,
	virtio::*,
	HypervisorError,
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
pub type DefaultBackend = crate::linux::x86_64::kvm_cpu::KvmVm;
#[cfg(target_os = "macos")]
pub type DefaultBackend = crate::macos::XhyveVm;

pub(crate) mod internal {
	use std::sync::Arc;

	use crate::{
		vcpu::VirtualCPU,
		vm::{KernelInfo, Params, VmPeripherals},
		HypervisorResult,
	};

	/// Trait marking a interface for creating (accelerated) VMs.
	pub trait VirtualizationBackendInternal: Sized {
		type VCPU: 'static + VirtualCPU;
		const NAME: &str;

		/// Create a new CPU object
		fn new_cpu(
			&self,
			id: u32,
			kernel_info: Arc<KernelInfo>,
			enable_stats: bool,
		) -> HypervisorResult<Self::VCPU>;

		fn new(peripherals: Arc<VmPeripherals>, params: &Params) -> HypervisorResult<Self>;
	}
}

pub trait VirtualizationBackend {
	type BACKEND: internal::VirtualizationBackendInternal;
}

#[derive(Debug, Clone)]
pub struct VmResult {
	pub code: i32,
	pub output: Option<String>,
	pub stats: Option<VmStats>,
}

/// mutable devices that a vCPU interacts with
pub(crate) struct VmPeripherals {
	pub file_mapping: Mutex<UhyveFileMap>,
	pub mem: MmapMemory,
	pub(crate) serial: UhyveSerial,
	pub virtio_device: Mutex<VirtioNetPciDevice>,
}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
unsafe impl Send for VmPeripherals {}
unsafe impl Sync for VmPeripherals {}

/// static information that does not change during execution
#[derive(Debug)]
pub(crate) struct KernelInfo {
	pub entry_point: GuestPhysAddr,
	/// The starting position of the image in physical memory
	#[cfg_attr(target_os = "macos", allow(dead_code))] // currently only needed in gdb
	pub kernel_address: GuestPhysAddr,
	pub params: Params,
	pub path: PathBuf,
	pub stack_address: GuestPhysAddr,
}

pub struct UhyveVm<VirtBackend: VirtualizationBackend> {
	pub(crate) vcpus: Vec<<VirtBackend::BACKEND as VirtualizationBackendInternal>::VCPU>,
	pub(crate) peripherals: Arc<VmPeripherals>,
	pub(crate) kernel_info: Arc<KernelInfo>,
}
impl<VirtBackend: VirtualizationBackend> UhyveVm<VirtBackend> {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<UhyveVm<VirtBackend>> {
		let memory_size = params.memory_size.get();

		#[cfg(target_os = "linux")]
		let mem = MmapMemory::new(0, memory_size, arch::RAM_START, params.thp, params.ksm);
		#[cfg(not(target_os = "linux"))]
		let mem = MmapMemory::new(0, memory_size, arch::RAM_START, false, false);

		let (
			LoadedKernel {
				load_info,
				entry_point,
			},
			kernel_address,
		) = load_kernel_to_mem(&kernel_path, unsafe { mem.as_slice_uninit_mut() })
			.expect("Unable to load Kernel {kernel_path}");

		let stack_address = GuestPhysAddr::new(
			kernel_address
				.as_u64()
				.checked_sub(KERNEL_STACK_SIZE)
				.expect(
				"there should be enough space for the boot stack before the kernel start address",
			),
		);

		let kernel_info = Arc::new(KernelInfo {
			entry_point: entry_point.into(),
			kernel_address,
			path: kernel_path,
			params,
			stack_address,
		});

		// create virtio interface
		// TODO: Remove allow once fixed:
		// https://github.com/rust-lang/rust-clippy/issues/11382
		#[allow(clippy::arc_with_non_send_sync)]
		let virtio_device = Mutex::new(VirtioNetPciDevice::new());

		let file_mapping = Mutex::new(UhyveFileMap::new(
			&kernel_info.params.file_mapping,
			&kernel_info.params.tempdir,
		));

		let serial = UhyveSerial::from_params(&kernel_info.params.output)?;

		let peripherals = Arc::new(VmPeripherals {
			mem,
			virtio_device,
			file_mapping,
			serial,
		});

		let virt_backend = VirtBackend::BACKEND::new(peripherals.clone(), &kernel_info.params)?;

		let cpu_count = kernel_info.params.cpu_count.get();

		assert!(
			kernel_info.params.gdb_port.is_none() || cfg!(target_os = "linux"),
			"gdb is only supported on linux (yet)"
		);
		assert!(
			kernel_info.params.gdb_port.is_none() || cpu_count == 1,
			"gdbstub is only supported with one CPU"
		);

		let mut vcpus = Vec::with_capacity(cpu_count as usize);
		for cpu_id in 0..cpu_count {
			vcpus.push(
				virt_backend
					.new_cpu(cpu_id, kernel_info.clone(), kernel_info.params.stats)
					.unwrap(),
			)
		}

		// TODO: Get frequency

		write_fdt_into_mem(&peripherals.mem, &kernel_info.params);
		write_boot_info_to_mem(&peripherals.mem, load_info, cpu_count as u64);
		init_guest_mem(
			unsafe { peripherals.mem.as_slice_mut() }, // slice only lives during this fn call
		);
		debug!("VM initialization complete");

		Ok(Self {
			peripherals,
			kernel_info,
			vcpus,
		})
	}
}

impl<VirtIf: VirtualizationBackend> fmt::Debug for UhyveVm<VirtIf> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct(&format!("UhyveVm<{}>", VirtIf::BACKEND::NAME))
			.field("entry_point", &self.kernel_info.entry_point)
			.field("stack_address", &self.kernel_info.stack_address)
			.field("mem", &self.peripherals.mem)
			.field("path", &self.kernel_info.path)
			.field("virtio_device", &self.peripherals.virtio_device)
			.field("params", &self.kernel_info.params)
			.field("file_mapping", &self.peripherals.file_mapping)
			.finish()
	}
}

/// Initialize the page tables for the guest
fn init_guest_mem(mem: &mut [u8]) {
	debug!("Initialize guest memory");
	crate::arch::init_guest_mem(
		mem.try_into()
			.expect("Guest memory is not large enough for pagetables"),
	);
}

fn write_fdt_into_mem(mem: &MmapMemory, params: &Params) {
	debug!("Writing FDT in memory");
	let tsc_khz = detect_cpu_freq() * 1000;

	let sep = params
		.kernel_args
		.iter()
		.enumerate()
		.find(|(_i, arg)| *arg == "--")
		.map(|(i, _arg)| i)
		.unwrap_or_else(|| params.kernel_args.len());

	let fdt = Fdt::new()
		.unwrap()
		.tsc_khz(tsc_khz)
		.unwrap()
		.memory(mem.guest_address..mem.guest_address + mem.memory_size as u64)
		.unwrap()
		.kernel_args(&params.kernel_args[..sep])
		.app_args(params.kernel_args.get(sep + 1..).unwrap_or_default())
		.envs(env::vars())
		.finish()
		.unwrap();

	debug!("fdt.len() = {}", fdt.len());
	assert!(fdt.len() < (BOOT_INFO_ADDR - FDT_ADDR) as usize);
	unsafe {
		let fdt_ptr = mem.host_address.add(FDT_ADDR.as_u64() as usize);
		fdt_ptr.copy_from_nonoverlapping(fdt.as_ptr(), fdt.len());
	}
}

fn write_boot_info_to_mem(mem: &MmapMemory, load_info: LoadInfo, num_cpus: u64) {
	debug!("Writing BootInfo to memory");
	let boot_info = BootInfo {
		hardware_info: HardwareInfo {
			phys_addr_range: mem.guest_address.as_u64()
				..mem.guest_address.as_u64() + mem.memory_size as u64,
			serial_port_base: SerialPortBase::new(
				(uhyve_interface::HypercallAddress::Uart as u16).into(),
			),
			device_tree: Some(FDT_ADDR.as_u64().try_into().unwrap()),
		},
		load_info,
		platform_info: PlatformInfo::Uhyve {
			has_pci: cfg!(target_os = "linux"),
			num_cpus: num_cpus.try_into().unwrap(),
			cpu_freq: NonZeroU32::new(detect_cpu_freq() * 1000),
			boot_time: SystemTime::now().into(),
		},
	};
	unsafe {
		let raw_boot_info_ptr =
			mem.host_address.add(BOOT_INFO_ADDR.as_u64() as usize) as *mut RawBootInfo;
		*raw_boot_info_ptr = RawBootInfo::from(boot_info);
	}
}

/// loads the kernel image into `mem`. `offset` is the start address of `mem`.
fn load_kernel_to_mem(
	kernel_path: &PathBuf,
	mem: &mut [MaybeUninit<u8>],
) -> LoadKernelResult<(LoadedKernel, GuestPhysAddr)> {
	let elf = fs::read(kernel_path)?;
	let object = KernelObject::parse(&elf).map_err(LoadKernelError::ParseKernelError)?;

	// TODO: should be a random start address, if we have a relocatable executable
	let kernel_address = GuestPhysAddr::new(object.start_addr().unwrap_or(0x400000));
	let kernel_end_address = kernel_address + object.mem_size();

	if kernel_end_address.as_u64() > mem.len() as u64 - arch::RAM_START.as_u64() {
		return Err(LoadKernelError::InsufficientMemory);
	}

	Ok((
		object.load_kernel(
			// Safety: Slice only lives during this fn call, so no aliasing happens
			&mut mem[kernel_address.as_u64() as usize..kernel_end_address.as_u64() as usize],
			kernel_address.as_u64(),
		),
		kernel_address,
	))
}

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
