use std::{
	env, fmt,
	fs::{self, File, OpenOptions},
	io::{self, Write},
	num::NonZeroU32,
	path::PathBuf,
	ptr, str,
	sync::{Arc, Mutex},
	time::SystemTime,
};

use hermit_entry::{
	boot_info::{BootInfo, HardwareInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use log::{error, warn};
use sysinfo::System;
use tempfile::TempDir;
use thiserror::Error;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{
	detect_freq_from_cpuid, detect_freq_from_cpuid_hypervisor_info, get_cpu_frequency_from_os,
};
use crate::{
	arch::{self, FrequencyDetectionFailed},
	consts::*,
	fdt::Fdt,
	isolation::{filemap::UhyveFileMap, tempdir::create_temp_dir},
	mem::MmapMemory,
	os::HypervisorError,
	params::{self, Params},
	stats::VmStats,
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

/// Trait marking a interface for creating (accelerated) VMs.
pub trait VirtualizationBackend: Sized {
	type VCPU;
	const NAME: &str;

	/// Create a new CPU object
	fn new_cpu(
		&self,
		id: u32,
		parent_vm: Arc<UhyveVm<Self>>,
		enable_stats: bool,
	) -> HypervisorResult<Self::VCPU>;

	fn new(memory: &MmapMemory, params: &Params) -> HypervisorResult<Self>;
}

#[derive(Debug, Clone)]
pub struct VmResult {
	pub code: i32,
	pub output: Option<String>,
	pub stats: Option<VmStats>,
}

#[derive(Debug)]
pub enum Output {
	StdIo,
	File(Arc<Mutex<File>>),
	Buffer(Arc<Mutex<String>>),
	None,
}
impl Default for Output {
	fn default() -> Self {
		Self::StdIo
	}
}

pub struct UhyveVm<VirtBackend: VirtualizationBackend> {
	/// The starting position of the image in physical memory
	offset: u64,
	entry_point: u64,
	stack_address: u64,
	pub mem: Arc<MmapMemory>,
	path: PathBuf,
	boot_info: *const RawBootInfo,
	pub virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
	#[allow(dead_code)] // gdb is not supported on macos
	pub(super) gdb_port: Option<u16>,
	pub(crate) file_mapping: Mutex<UhyveFileMap>,
	pub(crate) virt_backend: VirtBackend,
	params: Params,
	pub output: Output,
	pub(crate) tempdir: TempDir,
}
impl<VirtBackend: VirtualizationBackend> UhyveVm<VirtBackend> {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<UhyveVm<VirtBackend>> {
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

		let virt_backend = VirtBackend::new(&mem, &params)?;

		let cpu_count = params.cpu_count.get();

		assert!(
			params.gdb_port.is_none() || cfg!(target_os = "linux"),
			"gdb is only supported on linux (yet)"
		);
		assert!(
			params.gdb_port.is_none() || cpu_count == 1,
			"gdbstub is only supported with one CPU"
		);

		let tempdir = create_temp_dir();
		let file_mapping = Mutex::new(UhyveFileMap::new(&params.file_mapping, "/root"));

		let output = match params.output {
			params::Output::None => Output::None,
			params::Output::StdIo => Output::StdIo,
			params::Output::Buffer => {
				Output::Buffer(Arc::new(Mutex::new(String::with_capacity(8096))))
			}
			params::Output::File(ref path) => {
				let f = OpenOptions::new()
					.read(false)
					.write(true)
					.create_new(true)
					.open(path)
					.map_err(|e| {
						error!("Cant create kernel output file: {e}");
						// TODO: proper error handling
						#[cfg(target_os = "macos")]
						panic!();
						#[cfg(not(target_os = "macos"))]
						e
					})?;
				Output::File(Arc::new(Mutex::new(f)))
			}
		};

		let mut vm = Self {
			offset: 0,
			entry_point: 0,
			stack_address: 0,
			mem: mem.into(),
			path: kernel_path,
			boot_info: ptr::null(),
			virtio_device,
			gdb_port: params.gdb_port,
			file_mapping,
			virt_backend,
			params,
			output,
			tempdir,
		};

		vm.init_guest_mem();

		Ok(vm)
	}

	pub fn serial_output(&self, buf: &[u8]) -> io::Result<()> {
		match &self.output {
			Output::StdIo => io::stdout().write_all(buf),
			Output::None => Ok(()),
			Output::Buffer(b) => {
				b.lock().unwrap().push_str(str::from_utf8(buf).map_err(|e| {
					io::Error::new(
						io::ErrorKind::InvalidData,
						format!("invalid UTF-8 bytes in output: {e:?}"),
					)
				})?);
				Ok(())
			}
			Output::File(f) => f.lock().unwrap().write_all(buf),
		}
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
		self.params.cpu_count.get()
	}

	pub fn kernel_path(&self) -> &PathBuf {
		&self.path
	}

	pub fn args(&self) -> &Vec<String> {
		&self.params.kernel_args
	}

	pub fn get_params(&self) -> &Params {
		&self.params
	}

	pub fn get_tempdir(&self) -> &TempDir {
		&self.tempdir
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

		let sep = self
			.args()
			.iter()
			.enumerate()
			.find(|(_i, arg)| *arg == "--")
			.map(|(i, _arg)| i)
			.unwrap_or_else(|| self.args().len());

		let fdt = Fdt::new()
			.unwrap()
			.memory(self.mem.guest_address..self.mem.guest_address + self.mem.memory_size as u64)
			.unwrap()
			.kernel_args(&self.args()[..sep])
			.app_args(self.args().get(sep + 1..).unwrap_or_default())
			.envs(env::vars())
			.finish()
			.unwrap();

		debug!("fdt.len() = {}", fdt.len());
		assert!(fdt.len() < (BOOT_INFO_ADDR - FDT_ADDR) as usize);
		unsafe {
			let fdt_ptr = self.mem.host_address.add(FDT_ADDR.as_u64() as usize);
			fdt_ptr.copy_from_nonoverlapping(fdt.as_ptr(), fdt.len());
		}

		let boot_info = BootInfo {
			hardware_info: HardwareInfo {
				phys_addr_range: self.mem.guest_address.as_u64()
					..self.mem.guest_address.as_u64() + self.mem.memory_size as u64,
				serial_port_base: SerialPortBase::new(
					(uhyve_interface::HypercallAddress::Uart as u16).into(),
				),
				device_tree: Some(FDT_ADDR.as_u64().try_into().unwrap()),
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

impl<VirtIf: VirtualizationBackend> fmt::Debug for UhyveVm<VirtIf> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct(&format!("UhyveVm<{}>", VirtIf::NAME))
			.field("entry_point", &self.entry_point)
			.field("stack_address", &self.stack_address)
			.field("mem", &self.mem)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("virtio_device", &self.virtio_device)
			.field("params", &self.params)
			.field("file_mapping", &self.file_mapping)
			.field("tempdir", &self.tempdir)
			.finish()
	}
}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<VirtIf: VirtualizationBackend> Send for UhyveVm<VirtIf> {}
unsafe impl<VirtIf: VirtualizationBackend> Sync for UhyveVm<VirtIf> {}

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
