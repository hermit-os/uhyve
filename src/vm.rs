use std::{
	ffi::OsString,
	fmt, fs, io,
	marker::PhantomData,
	mem::MaybeUninit,
	num::NonZeroU32,
	path::{Path, PathBuf},
	ptr, slice,
	sync::{Arc, Mutex},
	time::SystemTime,
};

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
use crate::linux::x86_64::kvm_cpu::{initialize_kvm, KvmCpu};
#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
use crate::macos::x86_64::vcpu::XhyveCpu;
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

/// A section of memory that is reserved for the VM guest.
pub trait VmGuestMemory {
	/// returns a pointer to the address of the guest memory and the size of the memory in bytes.
	// TODO: replace with slice
	// TODO: rename to memory
	fn guest_mem(&self) -> (*mut u8, usize);

	/// Initialize the memory
	fn init_guest_mem(&mut self);

	// TODO Guest physical to virtual here
}

#[cfg(target_os = "linux")]
pub type VcpuDefault = crate::linux::x86_64::kvm_cpu::KvmCpu;
#[cfg(target_os = "macos")]
pub type VcpuDefault = crate::macos::x86_64::vcpu::XhyveCpu;

pub struct UhyveVm<VCpuType: VirtualCPU = VcpuDefault> {
	/// The starting position of the image in physical memory
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
	#[allow(dead_code)] // gdb is not supported on macos
	pub(super) gdb_port: Option<u16>,
	_vcpu_type: PhantomData<VCpuType>,
}
impl<VCpuType: VirtualCPU> UhyveVm<VCpuType> {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<UhyveVm<VCpuType>> {
		let memory_size = params.memory_size.get();

		#[cfg(target_os = "linux")]
		let mem = MmapMemory::new(0, memory_size, 0, params.thp, params.ksm);
		#[cfg(not(target_os = "linux"))]
		let mem = MmapMemory::new(0, memory_size, 0, false, false);

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
			mem,
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

	fn set_offset(&mut self, offset: u64) {
		self.offset = offset;
	}

	/// Returns the section offsets relative to their base addresses
	pub fn get_offset(&self) -> u64 {
		self.offset
	}

	/// Sets the elf entry point.
	fn set_entry_point(&mut self, entry: u64) {
		self.entry_point = entry;
	}

	pub fn get_entry_point(&self) -> u64 {
		self.entry_point
	}

	fn set_stack_address(&mut self, stack_addresss: u64) {
		self.stack_address = stack_addresss;
	}

	pub fn stack_address(&self) -> u64 {
		self.stack_address
	}

	/// Returns the number of cores for the vm.
	pub fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.mem.host_address as *mut u8, self.mem.memory_size)
	}

	fn kernel_path(&self) -> &Path {
		self.path.as_path()
	}

	fn set_boot_info(&mut self, header: *const RawBootInfo) {
		self.boot_info = header;
	}

	/// Initialize the page tables for the guest
	fn init_guest_mem(&mut self) {
		self.mem.init_guest_mem();
	}

	pub unsafe fn load_kernel(&mut self) -> LoadKernelResult<()> {
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

#[cfg(target_os = "linux")]
impl UhyveVm<KvmCpu> {
	pub fn create_cpu(&self, id: u32) -> HypervisorResult<KvmCpu> {
		KvmCpu::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.mem.host_address,
			self.virtio_device.clone(),
		)
	}
}

#[cfg(target_os = "macos")]
impl UhyveVm<XhyveCpu> {
	pub fn create_cpu(&self, id: u32) -> HypervisorResult<XhyveCpu> {
		Ok(XhyveCpu::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.mem.host_address,
		))
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
