use std::{
	env, fmt, fs, io,
	num::NonZeroU32,
	os::unix::prelude::JoinHandleExt,
	path::PathBuf,
	sync::{Arc, Barrier, Mutex},
	thread,
	time::SystemTime,
};

use core_affinity::CoreId;
use hermit_entry::{
	HermitVersion,
	boot_info::{BootInfo, HardwareInfo, LoadInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use internal::VirtualizationBackendInternal;
use log::error;
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;

use crate::{
	HypervisorError, arch,
	consts::*,
	fdt::Fdt,
	generate_address,
	isolation::filemap::UhyveFileMap,
	mem::MmapMemory,
	os::KickSignal,
	params::{EnvVars, Params},
	serial::{Destination, UhyveSerial},
	stats::{CpuStats, VmStats},
	vcpu::VirtualCPU,
	virtio::*,
};
#[cfg(target_os = "linux")]
use crate::{isolation::landlock::initialize, params::FileSandboxMode};

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

type LoadKernelResult<T> = Result<T, LoadKernelError>;

#[cfg(target_os = "linux")]
pub type DefaultBackend = crate::linux::x86_64::kvm_cpu::KvmVm;
#[cfg(target_os = "macos")]
pub type DefaultBackend = crate::macos::XhyveVm;

pub(crate) mod internal {
	use std::sync::Arc;

	use uhyve_interface::GuestPhysAddr;

	use crate::{
		HypervisorResult,
		vcpu::VirtualCPU,
		vm::{KernelInfo, Params, VmPeripherals},
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

		fn new(
			peripherals: Arc<VmPeripherals>,
			params: &Params,
			guest_addr: GuestPhysAddr,
		) -> HypervisorResult<Self>;
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
#[derive(Debug)]
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
	/// The first instruction after boot
	pub entry_point: GuestPhysAddr,
	/// The starting position of the image in physical memory
	#[cfg_attr(target_os = "macos", expect(dead_code))] // currently only needed in gdb
	pub kernel_address: GuestPhysAddr,
	pub params: Params,
	pub path: PathBuf,
	pub stack_address: GuestPhysAddr,
	/// The location of the whole guest in the physical address space
	pub guest_address: GuestPhysAddr,
}

pub struct UhyveVm<VirtBackend: VirtualizationBackend> {
	pub(crate) vcpus: Vec<<VirtBackend::BACKEND as VirtualizationBackendInternal>::VCPU>,
	pub(crate) peripherals: Arc<VmPeripherals>,
	pub(crate) kernel_info: Arc<KernelInfo>,
}
impl<VirtBackend: VirtualizationBackend> UhyveVm<VirtBackend> {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<UhyveVm<VirtBackend>> {
		let memory_size = params.memory_size.get();

		let elf = fs::read(&kernel_path)
			.map_err(|_e| HypervisorError::InvalidKernelPath(kernel_path.clone()))?;
		let object: KernelObject<'_> =
			KernelObject::parse(&elf).map_err(LoadKernelError::ParseKernelError)?;

		let hermit_version = object.hermit_version();
		if let Some(version) = hermit_version {
			info!("Loading a Hermit v{version} kernel");
		} else {
			info!("Loading a pre Hermit v0.10.0 kernel");
		}

		// The memory layout of uhyve looks as follows:
		//
		//     0x0000_0000 ┌───────────────────┐
		//                 │ Hypercalls        │
		//                 ├───────────────────┤
		//                 │ not present       │
		//                 │                   │
		//    guest_address├───────────────────┤ ▲ ▲ ▲ ▲
		//                 │                   │ │ │ │ │BOOT_INFO_OFFSET
		//                 ├───────────────────┤ │ │ │ ▼
		//                 │ Boot Info         │ │ │ │FDT_OFFSET
		//                 ├───────────────────┤ │ │ ▼
		//                 │ Device Tree (FDT) │ │ │
		//                 ├───────────────────┤ │ │
		//                 │                   │ │ │PAGETABLE_OFFSET
		//                 ├───────────────────┤ │ ▼
		//                 │ Pagetables        │ │
		//    stack_address├───────────────────┤ │
		//                 │ Stack             │ │KERNEL_OFFSET
		//   kernel_address├───────────────────┤ ▼
		//                 │ Kernel            │
		//   entry_point──►│                   │
		//                 │                   │
		//                 ├───────────────────┤
		//                 │ Kernel Memory     │
		//                 │                   │
		//                 └───────────────────┘

		let (guest_address, kernel_address) = if let Some(start_addr) = object.start_addr() {
			if params.aslr {
				warn!("ASLR is enabled but kernel is not relocatable - disabling ASLR");
			}
			(arch::RAM_START, GuestPhysAddr::from(start_addr))
		} else {
			let guest_address = if params.aslr {
				generate_address(object.mem_size())
			} else {
				arch::RAM_START
			};
			(guest_address, (guest_address + KERNEL_OFFSET))
		};

		debug!("Guest starts at {guest_address:#x}");
		debug!("Kernel gets loaded to {kernel_address:#x}");

		#[cfg(target_os = "linux")]
		let mut mem = MmapMemory::new(0, memory_size, guest_address, params.thp, params.ksm);

		#[cfg(not(target_os = "linux"))]
		let mut mem = MmapMemory::new(0, memory_size, guest_address, false, false);

		// TODO: file_mapping not in kernel_info
		let file_mapping = Mutex::new(UhyveFileMap::new(&params.file_mapping, &params.tempdir));

		let serial = UhyveSerial::from_params(&params.output)?;

		// Takes place before the kernel is actually loaded.
		#[cfg(target_os = "linux")]
		Self::landlock_init(
			&params,
			&file_mapping.lock().unwrap(),
			kernel_path.to_str().unwrap(),
		);

		let (
			LoadedKernel {
				load_info,
				entry_point,
			},
			kernel_end_address,
		) = load_kernel_to_mem(&object, &mut mem, kernel_address - guest_address)
			.expect("Unable to load Kernel {kernel_path}");

		assert!(
			kernel_address.as_u64() > KERNEL_STACK_SIZE,
			"there should be enough space for the boot stack before the kernel start address",
		);
		let stack_address = kernel_address - KERNEL_STACK_SIZE;
		debug!("Stack starts at {stack_address:#x}");

		let kernel_info = Arc::new(KernelInfo {
			entry_point: entry_point.into(),
			kernel_address,
			guest_address: mem.guest_address,
			path: kernel_path,
			params,
			stack_address,
		});

		// create virtio interface
		let virtio_device = Mutex::new(VirtioNetPciDevice::new());

		let peripherals = Arc::new(VmPeripherals {
			mem,
			virtio_device,
			file_mapping,
			serial,
		});

		let virt_backend =
			VirtBackend::BACKEND::new(peripherals.clone(), &kernel_info.params, guest_address)?;

		let cpu_count = kernel_info.params.cpu_count.get();

		assert!(
			kernel_info.params.gdb_port.is_none() || cfg!(target_os = "linux"),
			"gdb is only supported on linux (yet)"
		);
		assert!(
			kernel_info.params.gdb_port.is_none() || cpu_count == 1,
			"gdbstub is only supported with one CPU"
		);

		let vcpus: Vec<_> = (0..cpu_count)
			.map(|cpu_id| {
				virt_backend
					.new_cpu(cpu_id, kernel_info.clone(), kernel_info.params.stats)
					.unwrap()
			})
			.collect();

		let freq = vcpus[0].get_cpu_frequency();

		write_fdt_into_mem(&peripherals.mem, &kernel_info.params, freq);
		write_boot_info_to_mem(&peripherals.mem, load_info, cpu_count as u64, freq);

		let legacy_mapping = if let Some(version) = hermit_version {
			// actually, all versions that have the tag in the elf are valid, but an explicit check doesn't hurt
			version
				< HermitVersion {
					major: 0,
					minor: 10,
					patch: 0,
				}
		} else {
			true
		};
		init_guest_mem(
			unsafe { peripherals.mem.as_slice_mut() }, // slice only lives during this fn call
			peripherals.mem.guest_address,
			kernel_end_address - guest_address,
			legacy_mapping,
		);
		trace!("VM initialization complete");

		Ok(Self {
			peripherals,
			kernel_info,
			vcpus,
		})
	}

	#[cfg(target_os = "linux")]
	pub fn landlock_init(params: &Params, file_map: &UhyveFileMap, kernel_path: &str) {
		if params.file_isolation != FileSandboxMode::None {
			trace!("Attempting to initialize Landlock...");
			let host_paths = file_map.get_all_host_paths();
			let temp_dir = file_map.get_temp_dir().to_owned();
			let landlock = initialize(
				params.file_isolation,
				kernel_path.to_owned(),
				&params.output,
				host_paths,
				temp_dir,
			);
			landlock.apply_landlock_restrictions();
		}
	}

	pub fn run_no_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		KickSignal::register_handler().unwrap();

		// After spinning up all vCPU threads, the main thread waits for any vCPU to end execution.
		let barrier = Arc::new(Barrier::new(2));

		trace!("Starting vCPUs");
		let threads = self
			.vcpus
			.into_iter()
			.enumerate()
			.map(|(cpu_id, mut cpu)| {
				let barrier = barrier.clone();
				let local_cpu_affinity = cpu_affinity
					.as_ref()
					.and_then(|core_ids| core_ids.get(cpu_id).copied());

				thread::spawn(move || {
					trace!("Create thread for CPU {cpu_id}");
					match local_cpu_affinity {
						Some(core_id) => {
							debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
							core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
						}
						None => debug!("No affinity specified, not binding thread"),
					}

					cpu.thread_local_init().expect("Unable to initialize vCPU");

					thread::sleep(std::time::Duration::from_millis(cpu_id as u64 * 50));

					// jump into the VM and execute code of the guest
					match cpu.run() {
						Ok((code, stats)) => {
							if code.is_some() {
								// Let the main thread continue with kicking the other vCPUs
								barrier.wait();
							}
							(Ok(code), stats)
						}
						Err(err) => {
							error!("CPU {cpu_id} crashed with {err:?}");
							barrier.wait();
							(Err(err), None)
						}
					}
				})
			})
			.collect::<Vec<_>>();
		trace!("Waiting for first CPU to finish");

		// Wait for one vCPU to return with an exit code.
		barrier.wait();

		trace!("Killing all threads");
		for thread in &threads {
			KickSignal::pthread_kill(thread.as_pthread_t()).unwrap();
		}

		let cpu_results = threads
			.into_iter()
			.map(|thread| thread.join().unwrap())
			.collect::<Vec<_>>();
		let code = match cpu_results
			.iter()
			.filter_map(|(ret, _stats)| ret.as_ref().ok())
			.filter_map(|ret| *ret)
			.count()
		{
			0 => panic!("No return code from any CPU? Maybe all have been kicked?"),
			1 => cpu_results[0].0.as_ref().unwrap().unwrap(),
			_ => panic!("more than one thread finished with an exit code (code: {cpu_results:?})"),
		};

		let stats: Vec<CpuStats> = cpu_results
			.iter()
			.filter_map(|(_ret, stats)| stats.clone())
			.collect();
		let output = if let Destination::Buffer(b) = &self.peripherals.serial.destination {
			Some(String::from_utf8_lossy(&b.lock().unwrap()).into_owned())
		} else {
			None
		};

		VmResult {
			code,
			output,
			stats: Some(VmStats::new(&stats)),
		}
	}
}

impl<VirtIf: VirtualizationBackend> fmt::Debug for UhyveVm<VirtIf> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct(&format!("UhyveVm<{}>", VirtIf::BACKEND::NAME))
			.field("entry_point", &self.kernel_info.entry_point)
			.field("stack_address", &self.kernel_info.stack_address)
			.field("guest_address", &self.kernel_info.guest_address)
			.field("mem", &self.peripherals.mem)
			.field("path", &self.kernel_info.path)
			.field("virtio_device", &self.peripherals.virtio_device)
			.field("params", &self.kernel_info.params)
			.field("file_mapping", &self.peripherals.file_mapping)
			.finish()
	}
}

/// Initialize the page tables for the guest
/// `memory_size` is the length of the memory from the start of the physical
/// memory till the end of the kernel in bytes.
fn init_guest_mem(
	mem: &mut [u8],
	guest_addr: GuestPhysAddr,
	memory_size: u64,
	legacy_mapping: bool,
) {
	trace!("Initialize guest memory");
	crate::arch::init_guest_mem(mem, guest_addr, memory_size, legacy_mapping);
}

fn write_fdt_into_mem(mem: &MmapMemory, params: &Params, cpu_freq: Option<NonZeroU32>) {
	trace!("Writing FDT in memory");

	let sep = params
		.kernel_args
		.iter()
		.enumerate()
		.find(|(_i, arg)| *arg == "--")
		.map(|(i, _arg)| i)
		.unwrap_or_else(|| params.kernel_args.len());

	let mut fdt = Fdt::new()
		.unwrap()
		.memory(mem.guest_address..mem.guest_address + mem.memory_size as u64)
		.unwrap()
		.kernel_args(&params.kernel_args[..sep])
		.app_args(params.kernel_args.get(sep + 1..).unwrap_or_default());

	fdt = match &params.env {
		EnvVars::Host => fdt.envs(env::vars()),
		EnvVars::Set(map) => fdt.envs(map.iter().map(|(a, b)| (a.as_str(), b.as_str()))),
	};

	#[cfg(target_arch = "aarch64")]
	{
		fdt = fdt.gic().unwrap();
		fdt = fdt.cpus(params.cpu_count).unwrap();
		fdt = fdt.timer().unwrap();
	}

	if let Some(tsc_khz) = cpu_freq {
		fdt = fdt.tsc_khz(tsc_khz.into()).unwrap();
	}
	let fdt = fdt.finish().unwrap();

	debug!("fdt.len() = {}", fdt.len());
	assert!(fdt.len() < (BOOT_INFO_OFFSET - FDT_OFFSET) as usize);
	unsafe {
		let fdt_ptr = mem.host_address.add(FDT_OFFSET as usize);
		fdt_ptr.copy_from_nonoverlapping(fdt.as_ptr(), fdt.len());
	}
}

fn write_boot_info_to_mem(
	mem: &MmapMemory,
	load_info: LoadInfo,
	num_cpus: u64,
	cpu_freq: Option<NonZeroU32>,
) {
	debug!(
		"Writing BootInfo to {:?}",
		mem.guest_address + BOOT_INFO_OFFSET
	);
	let boot_info = BootInfo {
		hardware_info: HardwareInfo {
			phys_addr_range: mem.guest_address.as_u64()
				..mem.guest_address.as_u64() + mem.memory_size as u64,
			#[cfg_attr(
				target_arch = "x86_64",
				expect(
					clippy::useless_conversion,
					reason = "aarch64 uses 64-bit SerialPortBase, x86_64 uses 16 bit"
				)
			)]
			serial_port_base: SerialPortBase::new(
				(uhyve_interface::v1::HypercallAddress::Uart as u16).into(),
			),
			device_tree: Some(
				(mem.guest_address.as_u64() + FDT_OFFSET)
					.try_into()
					.unwrap(),
			),
		},
		load_info,
		platform_info: PlatformInfo::Uhyve {
			has_pci: cfg!(target_os = "linux"),
			num_cpus: num_cpus.try_into().unwrap(),
			cpu_freq,
			boot_time: SystemTime::now().into(),
		},
	};
	unsafe {
		let raw_boot_info_ptr = mem.host_address.add(BOOT_INFO_OFFSET as usize) as *mut RawBootInfo;
		*raw_boot_info_ptr = RawBootInfo::from(boot_info);
	}
}

/// loads the kernel `object` into `mem`. `relative_offset` is the start address the kernel relative to `mem`.
/// Returns the loaded kernel marker and the kernel's end address.
fn load_kernel_to_mem(
	object: &KernelObject<'_>,
	mem: &mut MmapMemory,
	relative_offset: u64,
) -> LoadKernelResult<(LoadedKernel, GuestPhysAddr)> {
	let kernel_end_address = mem.guest_address + relative_offset + object.mem_size();

	if kernel_end_address > mem.guest_address + mem.memory_size {
		return Err(LoadKernelError::InsufficientMemory);
	}

	Ok((
		object.load_kernel(
			// Safety: Slice only lives during this fn call, so no aliasing happens
			&mut unsafe { mem.as_slice_uninit_mut() }
				[relative_offset as usize..relative_offset as usize + object.mem_size()],
			relative_offset + mem.guest_address.as_u64(),
		),
		kernel_end_address,
	))
}
