use std::{
	env,
	fmt::{self, Debug},
	fs, io,
	mem::{drop, take},
	num::NonZero,
	ops::Add,
	path::PathBuf,
	sync::{Arc, Barrier, Mutex},
	thread,
	time::SystemTime,
};

use align_address::Align;
use core_affinity::CoreId;
use hermit_entry::{
	Format, HermitVersion, UhyveIfVersion,
	boot_info::{BootInfo, HardwareInfo, LoadInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	config, detect_format,
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use log::error;
use nix::sys::pthread::{Pthread, pthread_self};
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;

use crate::{
	HypervisorError, V1_ADDR_RANGE, V2_ADDR_RANGE,
	fdt::Fdt,
	isolation::filemap::{UhyveFileMap, UhyveMapLeaf},
	mem::MmapMemory,
	net::NetworkBackend,
	os::KickSignal,
	params::{EnvVars, NetworkMode, Params},
	parking::Parker,
	serial::{Destination, UhyveSerial},
	stats::{CpuStats, VmStats},
	vcpu::VirtualCPU,
};
#[cfg(target_os = "linux")]
use crate::{
	isolation::landlock::initialize,
	params::{FileSandboxMode, Output},
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

type LoadKernelResult<T> = Result<T, LoadKernelError>;

#[cfg(target_os = "linux")]
pub type DefaultBackend = crate::linux::x86_64::kvm_cpu::KvmVm;
#[cfg(target_os = "macos")]
pub type DefaultBackend = crate::macos::XhyveVm;

/// Trait marking a interface for creating (accelerated) VMs.
pub(crate) trait VirtualizationBackendInternal: Sized {
	type VCPU: 'static + VirtualCPU;
	type VirtioNetImpl: NetworkBackend;
	const NAME: &str;

	/// Create a new CPU object
	fn new_cpu(
		&self,
		id: usize,
		kernel_info: Arc<KernelInfo>,
		enable_stats: bool,
	) -> HypervisorResult<Self::VCPU>;

	fn new(
		peripherals: Arc<VmPeripherals<Self::VirtioNetImpl>>,
		params: &Params,
	) -> HypervisorResult<Self>;

	fn virtio_net_device(mode: NetworkMode, mmap: Arc<MmapMemory>) -> Self::VirtioNetImpl;
}

#[derive(Debug, Clone)]
pub struct VmResult {
	pub code: i32,
	pub output: Option<String>,
	pub stats: Option<VmStats>,
}

/// mutable devices that a vCPU interacts with
#[derive(Debug)]
pub(crate) struct VmPeripherals<VirtioNetImpl: NetworkBackend> {
	pub file_mapping: Mutex<UhyveFileMap>,
	pub mem: Arc<MmapMemory>,
	pub(crate) serial: UhyveSerial,
	pub virtio_device: Option<Mutex<VirtioNetImpl>>,
}

// This uses the "private sealed supertrait pattern".
#[allow(private_bounds)]
pub trait VirtualizationBackend: Sized + VirtualizationBackendInternal {}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
unsafe impl<N: NetworkBackend> Send for VmPeripherals<N> {}

unsafe impl<N: NetworkBackend> Sync for VmPeripherals<N> {}

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

// guest_address + OFFSET
pub(crate) const BOOT_INFO_OFFSET: u64 = 0x9000;
const FDT_OFFSET: u64 = 0x5000;
pub(crate) const KERNEL_OFFSET: u64 = 0x40000;

const KERNEL_STACK_SIZE: u64 = 0x8000;

/// Returns a guest & start address tuple based on the object file.
///
/// Generates a tuple containing a potentially random guest address and a derived
/// start address for Uhyve's virtualized memory. The guest address will not be
/// random under the following conditions:
/// - The image is not relocatable / uses uhyve-interface v1.
/// - ASLR is disabled.
///
/// If the image is not relocatable, the start address will be equal to that
/// present in the unikernel image file's object representation.
///
/// - `interface_version`: Version of uhyve-interface.
/// - `aslr`: `bool` describing whether ASLR is enabled (`true`) or disabled (`false`).
/// - `object_mem_size`: Memory required to load the object file onto the guest's memory.
/// - `object_start_addr`: Start address embedded in the unikernel image (if applicable).
/// - `mem_size`: User-defined memory size that should be available to the VM.
pub(crate) fn generate_guest_start_address(
	interface_version: UhyveIfVersion,
	aslr: bool,
	object_mem_size: usize,
	object_start_addr: Option<u64>,
	mem_size: usize,
) -> (GuestPhysAddr, GuestPhysAddr) {
	// Using an interface-specific version's range and by using checked_sub, we
	// guarantee that the range used during the kernel's execution won't lead
	// to a boundary violation during the guest's execution.
	let (guest_address_lb, guest_address_ub): (u64, u64) = {
		let range = match interface_version.0 {
			1 => V1_ADDR_RANGE,
			2 => V2_ADDR_RANGE,
			_ => unimplemented!(),
		};
		// KERNEL_OFFSET will be added again later for the start address, later.
		let mem_size = (object_mem_size + mem_size) as u64 + KERNEL_OFFSET;
		(
			range.0,
			range.1.checked_sub(mem_size).unwrap_or_else(|| {
				let (lb, ub) = range;
				panic!("Out of range [{lb:#x}, {ub:#x}) due to memory size {mem_size:#x}.")
			}),
		)
	};

	match (aslr, object_start_addr) {
		(true, None) => {
			let mut rng = rand::rng();
			let guest_address = GuestPhysAddr::new(
				rand::RngExt::random_range(&mut rng, guest_address_lb..=guest_address_ub)
					.align_down(0x20_0000),
			);
			(guest_address, guest_address.add(KERNEL_OFFSET))
		}
		(false, None) => {
			let guest_address = GuestPhysAddr::new(guest_address_lb);
			(guest_address, guest_address.add(KERNEL_OFFSET))
		}
		(_, Some(predefined_start_address)) => {
			assert!(
				(guest_address_lb..=guest_address_ub).contains(&predefined_start_address),
				"Predefined address {predefined_start_address:#x} out of range of possible
				 guest addresses: [{guest_address_lb:#x}, {guest_address_ub:#x}]."
			);
			if aslr {
				warn!("ASLR is enabled but kernel is not relocatable - disabling ASLR");
			}
			(
				GuestPhysAddr::new(guest_address_lb),
				GuestPhysAddr::new(predefined_start_address),
			)
		}
	}
}

pub struct UhyveVm<VirtBackend: VirtualizationBackend> {
	pub(crate) vcpus: Vec<<VirtBackend as VirtualizationBackendInternal>::VCPU>,
	pub(crate) peripherals: Arc<VmPeripherals<VirtBackend::VirtioNetImpl>>,
	pub(crate) kernel_info: Arc<KernelInfo>,
	_virt_backend: VirtBackend,
}
#[allow(private_bounds)]
impl<VirtBackend: VirtualizationBackend<VirtioNetImpl: NetworkBackend>> UhyveVm<VirtBackend> {
	pub fn new(kernel_path: PathBuf, mut params: Params) -> HypervisorResult<UhyveVm<VirtBackend>> {
		let memory_size = params.memory_size.get();

		let kernel_data = fs::read(&kernel_path)
			.map_err(|_e| HypervisorError::InvalidKernelPath(kernel_path.clone()))?;

		// TODO: file_mapping not in kernel_info
		let mut file_mapping = UhyveFileMap::new(
			&params.file_mapping,
			params.tempdir.clone(),
			#[cfg(target_os = "linux")]
			params.io_mode,
		);

		// `kernel_data` might be an Hermit image
		let elf = match detect_format(&kernel_data[..]) {
			None => return Err(HypervisorError::InvalidKernelPath(kernel_path.clone())),
			Some(Format::Elf) => kernel_data,
			Some(Format::Gzip) => {
				{
					use io::Read;

					// decompress image
					let mut buf_decompressed = Vec::new();
					flate2::bufread::GzDecoder::new(&kernel_data[..])
						.read_to_end(&mut buf_decompressed)?;
					drop(kernel_data);

					// insert Hermit image tree into file map
					file_mapping.add_hermit_image(&buf_decompressed[..])?;
				}

				let config_data = if let Some(UhyveMapLeaf::Virtual(data)) =
					file_mapping.get_host_path(&("/".to_string() + config::Config::DEFAULT_PATH))
				{
					data
				} else {
					return Err(HypervisorError::HermitImageConfigNotFound);
				};

				let config: config::Config<'_> = toml::from_slice(&config_data[..])?;

				// handle Hermit image configuration
				match config {
					config::Config::V1 {
						mut input,
						requirements,
						kernel,
					} => {
						// .input
						if params.kernel_args.is_empty() {
							params.kernel_args.append(
								&mut take(&mut input.kernel_args)
									.into_iter()
									.map(|i| i.into_owned())
									.collect(),
							);
							if !input.app_args.is_empty() {
								params.kernel_args.push("--".to_string());
								params.kernel_args.append(
									&mut take(&mut input.app_args)
										.into_iter()
										.map(|i| i.into_owned())
										.collect(),
								)
							}
						}
						debug!("Passing kernel arguments: {:?}", &params.kernel_args);

						// don't pass privileged env-var commands through
						input.env_vars.retain(|i| i.contains('='));

						if let EnvVars::Set(env) = &mut params.env {
							if let Ok(EnvVars::Set(prev_env_vars)) =
								EnvVars::try_from(&input.env_vars[..])
							{
								// env vars from params take precedence
								let new_env_vars = take(env);
								*env = prev_env_vars.into_iter().chain(new_env_vars).collect();
							} else {
								warn!("Unable to parse env vars from Hermit image configuration");
							}
						} else if input.env_vars.is_empty() {
							info!("Ignoring Hermit image env vars due to `-e host`");
						}

						// .requirements

						// TODO: what about default memory size?
						if let Some(required_memory_size) = requirements.memory
							&& params.memory_size.0 < required_memory_size
						{
							return Err(HypervisorError::InsufficientGuestMemorySize {
								got: params.memory_size.0,
								wanted: required_memory_size,
							});
						}

						if params.cpu_count.get() < requirements.cpus {
							return Err(HypervisorError::InsufficientGuestCPUs {
								got: params.cpu_count.get(),
								wanted: requirements.cpus,
							});
						}

						// .kernel
						if let Some(UhyveMapLeaf::Virtual(data)) =
							file_mapping.get_host_path(&kernel)
						{
							data.to_vec()
						} else {
							error!("Unable to find kernel in Hermit image");
							return Err(HypervisorError::InvalidKernelPath(kernel_path.clone()));
						}
					}
				}
			}
		};

		let object: KernelObject<'_> =
			KernelObject::parse(&elf).map_err(LoadKernelError::ParseKernelError)?;

		let hermit_version = object.hermit_version();
		if let Some(version) = hermit_version {
			info!("Loading a Hermit v{version} kernel");
		} else {
			info!("Loading a pre Hermit v0.10.0 kernel");
		}

		let uhyve_interface_version = object
			.uhyve_interface_version()
			.unwrap_or(UhyveIfVersion(1));

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

		let (guest_address, kernel_address) = generate_guest_start_address(
			uhyve_interface_version,
			params.aslr,
			object.mem_size(),
			object.start_addr(),
			memory_size,
		);

		debug!("Guest starts at {guest_address:#x}");
		debug!("Kernel gets loaded to {kernel_address:#x}");

		#[cfg(target_os = "linux")]
		let mut mem = MmapMemory::new(memory_size, guest_address, params.thp, params.ksm);

		#[cfg(not(target_os = "linux"))]
		let mut mem = MmapMemory::new(memory_size, guest_address, false, false);

		let mounts: Vec<_> = file_mapping.get_all_guest_dirs().collect();

		let serial = UhyveSerial::from_params(&params.output)?;

		// Takes place before the kernel is actually loaded.
		#[cfg(target_os = "linux")]
		Self::landlock_init(
			&params.file_isolation,
			&file_mapping,
			&kernel_path,
			&params.output,
			#[cfg(feature = "instrument")]
			&params.trace_dir,
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
			guest_address: mem.guest_addr(),
			path: kernel_path,
			params,
			stack_address,
		});

		// create virtio interface
		let mem = Arc::new(mem);
		if let Some(version) = hermit_version
			&& kernel_info.params.network.is_some()
			&& (version
				< HermitVersion {
					major: 0,
					minor: 13,
					patch: 2,
				}) {
			return Err(HypervisorError::FeatureMismatch(
				"Network requires Kernel 0.13.2 or newer",
			));
		}
		let virtio_device = kernel_info
			.params
			.network
			.as_ref()
			.map(|mode| Mutex::new(VirtBackend::virtio_net_device(mode.clone(), mem.clone())));

		let peripherals = Arc::new(VmPeripherals {
			mem,
			// create virtio interface
			virtio_device,
			// TODO: file_mapping not in kernel_info
			file_mapping: Mutex::new(file_mapping),
			serial,
		});

		let virt_backend = VirtBackend::new(peripherals.clone(), &kernel_info.params)?;

		let cpu_count = kernel_info.params.cpu_count.get();

		assert!(
			kernel_info.params.gdb_port.is_none() || cfg!(target_os = "linux"),
			"gdb is only supported on linux (yet)"
		);

		let vcpus: Vec<_> = (0..cpu_count as usize)
			.map(|cpu_id| {
				virt_backend
					.new_cpu(cpu_id, kernel_info.clone(), kernel_info.params.stats)
					.unwrap()
			})
			.collect();

		let freq = vcpus[0].get_cpu_frequency();

		let serial_port = SerialPortBase::new(match uhyve_interface_version.0 {
			1 => uhyve_interface::v1::HypercallAddress::Uart as _,
			2 => uhyve_interface::v2::HypercallAddress::SerialWriteBuffer as _,
			uhifv => {
				unimplemented!(
					"Kernel uses unsupported uhyve-interface version {}. Is Uhyve too old?",
					uhifv
				)
			}
		});

		write_fdt_into_mem(&peripherals.mem, &kernel_info.params, freq, mounts);
		write_boot_info_to_mem(
			&peripherals.mem,
			load_info,
			cpu_count as u64,
			freq,
			serial_port,
		);

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
			guest_address,
			kernel_end_address - guest_address,
			legacy_mapping,
		);
		trace!("VM initialization complete");

		Ok(Self {
			peripherals,
			kernel_info,
			vcpus,
			_virt_backend: virt_backend,
		})
	}

	#[cfg(target_os = "linux")]
	pub fn landlock_init(
		file_sandbox_mode: &FileSandboxMode,
		file_map: &UhyveFileMap,
		kernel_path: &std::path::Path,
		output: &Output,
		#[cfg(feature = "instrument")] trace: &Option<PathBuf>,
	) {
		if file_sandbox_mode != &FileSandboxMode::None {
			debug!("Attempting to initialize Landlock...");
			let host_paths = file_map.get_all_host_paths();
			let temp_dir = file_map.get_temp_dir().to_owned();
			let landlock = initialize(
				file_sandbox_mode,
				kernel_path.into(),
				output,
				host_paths.map(|i| i.as_os_str()),
				temp_dir,
				#[cfg(feature = "instrument")]
				trace,
			);
			landlock.apply_landlock_restrictions();
		}
	}

	pub fn run_no_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		KickSignal::register_handler().unwrap();

		// After spinning up all vCPU threads, the main thread waits for any vCPU to end execution.
		let main_parker = Parker::current();

		let num_vcpus = self.vcpus.len();

		let pthreads: Mutex<Vec<Pthread>> = Mutex::new(Vec::with_capacity(num_vcpus));
		let pthreads_published = Barrier::new(num_vcpus + 1);

		let cpu_results = thread::scope(|s| {
			trace!("Starting vCPUs");
			let cpu_handles = self
				.vcpus
				.into_iter()
				.enumerate()
				.map(|(cpu_id, mut cpu)| {
					let main_parker = main_parker.clone();
					let local_cpu_affinity = cpu_affinity
						.as_ref()
						.and_then(|core_ids| core_ids.get(cpu_id).copied());
					let pthreads = &pthreads;
					let pthreads_published = &pthreads_published;

					s.spawn(move || {
						{
							pthreads.lock().unwrap().push(pthread_self());
						}
						pthreads_published.wait();

						trace!("Create thread for CPU {cpu_id}");
						match local_cpu_affinity {
							Some(core_id) => {
								debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
								core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
							}
							None => debug!("No affinity specified, not binding thread"),
						}

						cpu.thread_local_init().expect("Unable to initialize vCPU");

						struct UnparkOnDrop(Parker);

						impl Drop for UnparkOnDrop {
							fn drop(&mut self) {
								self.0.unpark();
							}
						}

						let _unpark_on_drop = UnparkOnDrop(main_parker);

						// jump into the VM and execute code of the guest
						match cpu.run() {
							Ok((code, stats)) => (Ok(code), stats),
							Err(err) => {
								error!("CPU {cpu_id} crashed with {err:?}");
								(Err(err), None)
							}
						}
					})
				})
				.collect::<Vec<_>>();

			pthreads_published.wait();

			trace!("Waiting for first CPU to finish");
			main_parker.park();

			trace!("Killing all threads");
			for &tid in pthreads.lock().unwrap().iter() {
				// `pthread_kill` may return ESRCH if the thread already finished;
				// scoped threads aren't joined until the scope ends, so the id is
				// still valid, but the kernel may no longer know about it.
				let _ = KickSignal::pthread_kill(tid);
			}

			cpu_handles
				.into_iter()
				.map(|h| h.join().unwrap())
				.collect::<Vec<_>>()
		});

		let code = cpu_results
			.iter()
			.find_map(|(ret, _stats)| ret.as_ref().ok().copied().flatten())
			.unwrap();

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

impl<VirtIf: VirtualizationBackend + Debug> fmt::Debug for UhyveVm<VirtIf> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct(&format!("UhyveVm<{}>", VirtIf::NAME))
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

fn write_fdt_into_mem(
	mem: &MmapMemory,
	params: &Params,
	cpu_freq: Option<NonZero<u32>>,
	mounts: Vec<String>,
) {
	trace!("Writing FDT in memory");

	let sep = params
		.kernel_args
		.iter()
		.take_while(|arg| *arg != "--")
		.count();

	let mut fdt = Fdt::new()
		.unwrap()
		.memory(mem.address_range())
		.unwrap()
		.kernel_args(&params.kernel_args[..sep])
		.app_args(params.kernel_args.get(sep + 1..).unwrap_or_default());

	fdt = match &params.env {
		EnvVars::Host => fdt.envs(env::vars()),
		EnvVars::Set(map) => fdt.envs(map.iter().map(|(a, b)| (a.as_str(), b.as_str()))),
	};

	if !mounts.is_empty() {
		fdt = fdt.mounts(mounts).unwrap();
	}

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
		let fdt_ptr = mem.host_start().add(FDT_OFFSET as usize);
		fdt_ptr.copy_from_nonoverlapping(fdt.as_ptr(), fdt.len());
	}
}

fn write_boot_info_to_mem(
	mem: &MmapMemory,
	load_info: LoadInfo,
	num_cpus: u64,
	cpu_freq: Option<NonZero<u32>>,
	#[cfg(target_arch = "x86_64")] serial_port: Option<NonZero<u16>>,
	#[cfg(target_arch = "aarch64")] serial_port: Option<NonZero<u64>>,
) {
	debug!(
		"Writing BootInfo to {:?}",
		mem.guest_addr() + BOOT_INFO_OFFSET
	);
	let boot_info = BootInfo {
		hardware_info: HardwareInfo {
			phys_addr_range: mem.address_range_u64(),
			serial_port_base: serial_port,
			device_tree: Some((mem.guest_addr().as_u64() + FDT_OFFSET).try_into().unwrap()),
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
		let raw_boot_info_ptr = mem.host_start().add(BOOT_INFO_OFFSET as usize) as *mut RawBootInfo;
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
	let kernel_end_address = mem.guest_addr() + relative_offset + object.mem_size();

	if kernel_end_address > mem.guest_addr() + mem.size() {
		return Err(LoadKernelError::InsufficientMemory);
	}

	Ok((
		object.load_kernel(
			// Safety: Slice only lives during this fn call, so no aliasing happens
			&mut unsafe { mem.as_slice_uninit_mut() }
				[relative_offset as usize..relative_offset as usize + object.mem_size()],
			relative_offset + mem.guest_addr().as_u64(),
		),
		kernel_end_address,
	))
}

#[cfg(test)]
mod tests {
	use std::ops::Add;

	use hermit_entry::UhyveIfVersion;

	use crate::{
		RAM_START, V1_MAX_ADDR,
		vm::{KERNEL_OFFSET, generate_guest_start_address},
	};

	#[test]
	fn test_generate_guest_start_address() {
		let mem_size: usize = 0xBE20_0000; // 3042 MiB
		let if_v1 = UhyveIfVersion(1);
		let if_v2 = UhyveIfVersion(2);
		let object_mem_size: usize = 0x0009_C400;
		let object_no_start_addr: Option<u64> = None;
		#[cfg(target_arch = "x86_64")]
		let object_start_addr: u64 = 0x0002_0000;
		#[cfg(target_arch = "aarch64")]
		let object_start_addr: u64 = 0x1002_0000;

		/* v1 */

		// v1: No ASLR, relocatable
		let (mut guest_address, mut start_address) = generate_guest_start_address(
			if_v1,
			false,
			object_mem_size,
			object_no_start_addr,
			mem_size,
		);
		assert_eq!(guest_address, RAM_START);
		assert_eq!(start_address, guest_address.add(KERNEL_OFFSET));

		// v1: ASLR, relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v1,
			true,
			object_mem_size,
			object_no_start_addr,
			mem_size,
		);
		assert_eq!(start_address, guest_address.add(KERNEL_OFFSET));
		assert!(start_address.as_u64() <= V1_MAX_ADDR);

		// v1: ASLR, non-relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v1,
			true,
			object_mem_size,
			object_start_addr.into(),
			mem_size,
		);
		assert_eq!(guest_address, RAM_START);
		assert_eq!(start_address.as_u64(), object_start_addr);
		// Note that this is a bit brittle and implicitly relies on RAM_START.
		assert_eq!(start_address, guest_address.add(0x0002_0000usize));
		assert!(start_address.as_u64() <= V1_MAX_ADDR);

		/* v2 */

		// v2: No ASLR, relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v2,
			false,
			object_mem_size,
			object_no_start_addr,
			mem_size,
		);
		assert_eq!(guest_address.as_u64(), 0x0001_0000_0000u64);
		assert_eq!(start_address, guest_address.add(KERNEL_OFFSET));
		#[cfg(target_arch = "x86_64")]
		assert!(start_address.as_u64() >= V1_MAX_ADDR);

		// v2: ASLR, relocatable
		(guest_address, start_address) = generate_guest_start_address(
			if_v2,
			true,
			object_mem_size,
			object_no_start_addr,
			mem_size,
		);
		assert_eq!(start_address, guest_address.add(KERNEL_OFFSET));
		#[cfg(target_arch = "x86_64")]
		assert!(start_address.as_u64() >= V1_MAX_ADDR);

		// v2: Use entire memory available
		//
		// (This effectively renders ASLR worthless, yet it is great for testing,
		//  underlying arithmetic operations for potential regressions without
		//  exclusively relying on randomness!)
		(guest_address, start_address) = generate_guest_start_address(
			if_v2,
			true,
			object_mem_size,
			object_no_start_addr,
			// Highest address, minus everything that is subtracted from it in the function.
			0x0010_0000_0000 - object_mem_size - KERNEL_OFFSET as usize - 0x0001_0000_0000,
		);
		assert_eq!(guest_address.as_u64(), 0x0001_0000_0000);
		assert_eq!(start_address, guest_address.add(KERNEL_OFFSET));
		#[cfg(target_arch = "x86_64")]
		assert!(start_address.as_u64() >= V1_MAX_ADDR);
	}
}
