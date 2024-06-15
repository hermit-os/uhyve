use std::{
	ffi::OsString,
	fmt, fs, io,
	marker::PhantomData,
	num::NonZeroU32,
	path::PathBuf,
	ptr,
	sync::{Arc, Mutex},
	time::SystemTime,
};

use rand::Rng;

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
use crate::linux::x86_64::kvm_cpu::initialize_kvm;
use crate::{
	arch, consts::*, mem::MmapMemory, os::HypervisorError, params::Params, vcpu::VirtualCPU,
	virtio::*,
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

// TODO: move to architecture specific section
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
	num_cpus: u32,
	path: PathBuf,
	args: Vec<OsString>,
	boot_info: *const RawBootInfo,
	verbose: bool,
	pub virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
	#[allow(dead_code)] // gdb is not supported on macos
	pub(super) gdb_port: Option<u16>,
	_vcpu_type: PhantomData<VCpuType>,
}
impl<VCpuType: VirtualCPU> UhyveVm<VCpuType> {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<UhyveVm<VCpuType>> {
		let memory_size = params.memory_size.get();

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

		let cpu_count = params.cpu_count.get();

		assert!(
			params.gdb_port.is_none() || cfg!(target_os = "linux"),
			"gdb is only supported on linux (yet)"
		);
		assert!(
			params.gdb_port.is_none() || cpu_count == 1,
			"gdbstub is only supported with one CPU"
		);

		let mut vm = Self {
			offset: 0,
			entry_point: 0,
			stack_address: 0,
			mem: mem.into(),
			num_cpus: cpu_count,
			path: kernel_path,
			args: params.kernel_args,
			boot_info: ptr::null(),
			verbose: params.verbose,
			virtio_device,
			gdb_port: params.gdb_port,
			_vcpu_type: PhantomData,
		};

		vm.init_guest_mem();

		Ok(vm)
	}

	fn verbose(&self) -> bool {
		self.verbose
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

	/// Returns the number of cores for the vm.
	pub fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	pub fn kernel_path(&self) -> &PathBuf {
		&self.path
	}

	pub fn args(&self) -> &Vec<OsString> {
		&self.args
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

		// TODO: If rand::Rng should not be used, use `0x400000` instead.
		// TODO: Is the value generated properly? Are we using rand properly?
		let mut rng = rand::thread_rng();
		// 0xFFFFF0 maintains the generated address, minus the last 4 bits, which are required for paging.
		// TODO: Find the upper boundary, and decuce it from the max possible address. Remove 0x891230.
		// TODO: What if we don't have enough space?
		// TODO: Uhyve should be informed if the value returned by `start_addr()` is equal to zero.
		let kernel_random_address: u64 = rng.gen_range(START_ADDRESS_OFFSET..0x891230) & 0xFFFFF0;
		let kernel_start_address = object.start_addr().unwrap_or(kernel_random_address) as usize;
		let kernel_end_address = kernel_start_address + object.mem_size();
		self.offset = kernel_start_address as u64;

		println!("{}", self.mem.guest_address.as_u64());
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
				phys_addr_range: arch::RAM_START.as_u64()
					..arch::RAM_START.as_u64() + self.mem.memory_size as u64,
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
			.field("num_cpus", &self.num_cpus)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("verbose", &self.verbose)
			.field("virtio_device", &self.virtio_device)
			.finish()
	}
}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<VCpuType: VirtualCPU> Send for UhyveVm<VCpuType> {}
unsafe impl<VCpuType: VirtualCPU> Sync for UhyveVm<VCpuType> {}
