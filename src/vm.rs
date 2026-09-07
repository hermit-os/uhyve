//! [`UhyveVm`] implementation & related code.

use std::{
	env,
	fmt::{self, Debug},
	fs, io,
	mem::{drop, take},
	num::NonZero,
	path::PathBuf,
	sync::{Arc, Barrier, Mutex},
	thread,
	time::SystemTime,
};

use align_address::Align;
use core_affinity::CoreId;
use gdbstub::{arch::Arch, target::Target};
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
	HypervisorError, PAGE_SIZE,
	fdt::Fdt,
	gdb::GdbVcpuManager,
	isolation::filemap::{UhyveFileMap, UhyveMapLeaf},
	mem::MmapMemory,
	mem_layout::{BootInfoSection, FdtSection, KernelSection, MemoryLayout},
	net::NetworkBackend,
	params::{EnvVars, HermitImageMode, NetworkMode, Params},
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub type DefaultBackend = crate::os::x86_64::kvm_cpu::KvmVm;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub type DefaultBackend = crate::os::aarch64::kvm_cpu::KvmVm;
#[cfg(target_os = "macos")]
pub type DefaultBackend = crate::os::XhyveVm;

/// Trait marking a interface for creating (accelerated) VMs.
pub(crate) trait VirtualizationBackendInternal: Sized {
	type VCPU: 'static + VirtualCPU;
	type VirtioNetImpl: NetworkBackend;
	type MemLayout: MemoryLayout + Copy;

	const NAME: &str;

	/// Create a new CPU object
	fn new_cpu(
		&self,
		id: usize,
		kernel_info: Arc<KernelInfo<Self::MemLayout>>,
		enable_stats: bool,
	) -> HypervisorResult<Self::VCPU>;

	fn new(
		peripherals: Arc<VmPeripherals<Self::VirtioNetImpl>>,
		params: &Params,
	) -> HypervisorResult<Self>;

	/// Initialize the page tables for the guest
	/// `memory_size` is the length of the memory from the start of the physical
	/// memory till the end of the kernel in bytes.
	fn init_guest_mem(
		mem: &mut MmapMemory,
		layout: &Self::MemLayout,
		memory_size: u64,
		legacy_mapping: bool,
	);

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
pub(crate) struct KernelInfo<MemLayout: MemoryLayout> {
	/// The first instruction after boot
	pub entry_point: GuestPhysAddr,
	pub layout: MemLayout,
	/// The starting position of the image in physical memory
	// currently only needed in gdb
	pub params: Params,
	pub path: PathBuf,
}

/// The signal for kicking vCPUs out of KVM_RUN.
///
/// It is used to stop a vCPU from another thread.
pub(crate) struct KickSignal;

pub struct UhyveVm<VirtBackend: VirtualizationBackend> {
	pub(crate) vcpus: Vec<<VirtBackend as VirtualizationBackendInternal>::VCPU>,
	pub(crate) peripherals: Arc<VmPeripherals<VirtBackend::VirtioNetImpl>>,
	pub(crate) kernel_info: Arc<KernelInfo<VirtBackend::MemLayout>>,
	cpu_affinity: Vec<CoreId>,
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

		let mut hermit_image = None;

		// `kernel_data` might be an Hermit image
		let elf = match detect_format(&kernel_data[..]) {
			None => return Err(HypervisorError::InvalidKernelPath(kernel_path.clone())),
			Some(Format::Elf) => kernel_data,
			Some(Format::Gzip) => {
				let buf_decompressed = {
					use io::Read;

					// decompress image
					let mut buf_decompressed = Vec::new();
					flate2::bufread::GzDecoder::new(&kernel_data[..])
						.read_to_end(&mut buf_decompressed)?;
					drop(kernel_data);
					buf_decompressed
				};

				let keep_config_data;
				let keep_kernel_data;

				let handle = match params.hermit_image_mode {
					HermitImageMode::External => {
						// insert Hermit image tree into file map
						file_mapping.add_hermit_image(&buf_decompressed[..])?;
						drop(buf_decompressed);

						let config_data = if let Some(UhyveMapLeaf::Virtual(data)) = file_mapping
							.get_host_path(&("/".to_string() + config::Config::DEFAULT_PATH), true)
						{
							keep_config_data = data;
							&keep_config_data[..]
						} else {
							return Err(HypervisorError::HermitImageConfigNotFound);
						};

						let konfig: config::Config<'_> = toml::from_slice(config_data)?;

						// .kernel
						let inner_kernel_path = match &konfig {
							config::Config::V1 { kernel, .. } => kernel,
						};
						let raw_kernel = if let Some(UhyveMapLeaf::Virtual(data)) =
							file_mapping.get_host_path(inner_kernel_path, true)
						{
							keep_kernel_data = data;
							&keep_kernel_data[..]
						} else {
							error!("Unable to find kernel in Hermit image");
							return Err(HypervisorError::InvalidKernelPath(kernel_path.clone()));
						};

						config::ConfigHandle {
							config: konfig,
							raw_kernel,
						}
					}
					HermitImageMode::Internal => {
						match config::parse_tar(hermit_image.insert(buf_decompressed)) {
							Ok(handle) => handle,
							Err(e) => {
								error!("Error during Hermit image parsing: {e}");
								return Err(HypervisorError::InvalidKernelPath(
									kernel_path.clone(),
								));
							}
						}
					}
				};

				// handle Hermit image configuration
				match handle.config {
					config::Config::V1 {
						mut input,
						requirements,
						kernel: _,
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
						debug!("Passing kernel arguments: {:?}", params.kernel_args);

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
					}
				}

				handle.raw_kernel.to_vec()
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

		let layout = VirtBackend::MemLayout::new(&params, &object);
		debug!("{layout}");

		#[cfg(target_os = "linux")]
		let mut mem = MmapMemory::new(memory_size, layout.guest_address(), params.thp, params.ksm);

		#[cfg(not(target_os = "linux"))]
		let mut mem = MmapMemory::new(memory_size, layout.guest_address(), false, false);

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
		) = load_kernel_to_mem(&object, &mut mem, &layout.kernel())
			.expect("Unable to load Kernel {kernel_path}");

		// Allocate memory for hermit image
		let hermit_image = hermit_image.map(|hermit_image| {
			load_hermit_image_to_mem(
				&hermit_image[..],
				&mut mem,
				(kernel_end_address - layout.guest_address()).align_up(PAGE_SIZE as u64),
			)
			.expect("Unable to load Hermit image {kernel_path}")
		});

		let cpu_affinity = core::mem::take(&mut params.cpu_affinity);

		let kernel_info = Arc::new(KernelInfo {
			entry_point: entry_point.into(),
			layout,
			path: kernel_path,
			params,
		});

		let legacy_mapping = if let Some(version) = hermit_version {
			// actually, all versions that have the tag in the elf don't use legacy mapping, but an explicit check doesn't hurt
			version
				< HermitVersion {
					major: 0,
					minor: 10,
					patch: 0,
				}
		} else {
			true
		};
		trace!("Initialize guest memory");
		VirtBackend::init_guest_mem(
			&mut mem,
			&layout,
			hermit_image
				.clone()
				.map(|i| i.end)
				.unwrap_or(kernel_end_address)
				- layout.guest_address(),
			legacy_mapping,
		);

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
			2 | 3 => uhyve_interface::v2::HypercallAddress::SerialWriteBuffer as _,
			uhifv => {
				unimplemented!(
					"Kernel uses unsupported uhyve-interface version {}. Is Uhyve too old?",
					uhifv
				)
			}
		});

		write_fdt_into_mem(
			&peripherals.mem,
			layout.fdt(),
			&kernel_info.params,
			hermit_image,
			freq,
			mounts,
		);
		write_boot_info_to_mem(
			&peripherals.mem,
			layout.boot_info(),
			layout.fdt().0.addr,
			load_info,
			cpu_count as u64,
			freq,
			serial_port,
		);

		trace!("VM initialization complete");

		Ok(Self {
			peripherals,
			kernel_info,
			vcpus,
			cpu_affinity,
			_virt_backend: virt_backend,
		})
	}

	#[cfg(target_os = "linux")]
	pub(crate) fn landlock_init(
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

	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(mut self) -> VmResult
	where
		GdbVcpuManager<VirtBackend>: Target,
		<GdbVcpuManager<VirtBackend> as Target>::Error: fmt::Debug,
		<GdbVcpuManager<VirtBackend> as Target>::Arch: Arch<Usize = u64>,
	{
		KickSignal::register_handler().unwrap();

		let cpu_affinity = if self.cpu_affinity.is_empty() {
			None
		} else {
			Some(core::mem::take(&mut self.cpu_affinity))
		};

		if self.kernel_info.params.gdb_port.is_none() {
			self.run_no_gdb(cpu_affinity)
		} else {
			if cfg!(target_os = "macos") {
				warn!("This mode is experimental and doesn't yet work correctly.");
			}
			self.run_gdb(cpu_affinity)
		}
	}

	fn run_no_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
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
			KickSignal::kick_all_vcpus();

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
			.field("layout", &self.kernel_info.layout)
			.field("mem", &self.peripherals.mem)
			.field("path", &self.kernel_info.path)
			.field("virtio_device", &self.peripherals.virtio_device)
			.field("params", &self.kernel_info.params)
			.field("file_mapping", &self.peripherals.file_mapping)
			.finish()
	}
}

fn write_fdt_into_mem(
	mem: &MmapMemory,
	fdt_section: FdtSection,
	params: &Params,
	hermit_image: Option<core::ops::Range<GuestPhysAddr>>,
	cpu_freq: Option<NonZero<u32>>,
	mounts: Vec<String>,
) {
	trace!("Writing FDT in memory");

	let sep = params
		.kernel_args
		.iter()
		.take_while(|arg| *arg != "--")
		.count();

	let mut fdt = Fdt::new(hermit_image)
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

	fdt = fdt.cpus(params.cpu_count).unwrap();

	#[cfg(target_arch = "aarch64")]
	{
		fdt = fdt.gic().unwrap();
		fdt = fdt.timer().unwrap();
	}

	if let Some(tsc_khz) = cpu_freq {
		fdt = fdt.tsc_khz(tsc_khz.into()).unwrap();
	}
	let fdt = fdt.finish().unwrap();

	debug!("fdt.len() = {}", fdt.len());
	assert!(fdt.len() < fdt_section.0.length);
	let fdt_target = unsafe { &mut mem.section_slice_mut(fdt_section.0).unwrap()[0..fdt.len()] };
	fdt_target.copy_from_slice(&fdt);
}

fn write_boot_info_to_mem(
	mem: &MmapMemory,
	boot_info_section: BootInfoSection,
	fdt_addr: GuestPhysAddr,
	load_info: LoadInfo,
	num_cpus: u64,
	cpu_freq: Option<NonZero<u32>>,
	#[cfg(target_arch = "x86_64")] serial_port: Option<NonZero<u16>>,
	#[cfg(target_arch = "aarch64")] serial_port: Option<NonZero<u64>>,
) {
	debug!("Writing BootInfo to {:?}", boot_info_section.0.addr,);
	let boot_info = BootInfo {
		hardware_info: HardwareInfo {
			phys_addr_range: mem.address_range_u64(),
			serial_port_base: serial_port,
			device_tree: Some(fdt_addr.as_u64().try_into().unwrap()),
		},
		load_info,
		platform_info: PlatformInfo::Uhyve {
			has_pci: cfg!(target_os = "linux"),
			num_cpus: num_cpus.try_into().unwrap(),
			cpu_freq,
			boot_time: SystemTime::now().into(),
		},
	};
	assert!(boot_info_section.0.length >= size_of::<RawBootInfo>());
	*unsafe { mem.get_ref_mut(boot_info_section.0.addr) }.unwrap() = RawBootInfo::from(boot_info);
}

/// loads the kernel `object` into `mem`. `relative_offset` is the start address the kernel relative to `mem`.
/// Returns the loaded kernel marker and the kernel's end address.
fn load_kernel_to_mem(
	object: &KernelObject<'_>,
	mem: &mut MmapMemory,
	kernel_section: &KernelSection,
) -> LoadKernelResult<(LoadedKernel, GuestPhysAddr)> {
	let kernel_end_address = kernel_section.0.end();

	if kernel_end_address > mem.guest_addr() + mem.size() {
		return Err(LoadKernelError::InsufficientMemory);
	}

	Ok((
		object.load_kernel(
			// Safety: Slice only lives during this fn call, so no aliasing happens.
			unsafe { mem.section_slice_mut(kernel_section.0).unwrap() },
			kernel_section.0.addr.as_u64(),
		),
		kernel_end_address,
	))
}

/// Loads the `hermit_image` into `mem`. `relative_offset` is the start address the image relative to `mem`.
/// Returns the memory range of the image in terms of guest addresses.
fn load_hermit_image_to_mem(
	hermit_image: &[u8],
	mem: &mut MmapMemory,
	relative_offset: u64,
) -> Option<core::ops::Range<GuestPhysAddr>> {
	assert!(!hermit_image.is_empty());

	let aligned_image_len = hermit_image.len().align_up(PAGE_SIZE);
	let image_start_address = mem.guest_addr() + relative_offset;
	let image_actual_end_address = image_start_address + hermit_image.len() as u64;
	let image_end_address = image_start_address + aligned_image_len as u64;

	if image_end_address > mem.guest_addr() + mem.size() {
		return None;
	}

	// TODO: mark that memory in the memory handling as read-only, such that
	// the hypervisor can more-or-less gracefully shutdown/error in case of
	// errornous write access to a read-only section.

	// Safety: Slice only lives during the rest of this function invocation, so no aliasing happens
	let mem_slice =
		unsafe { &mut mem.as_slice_mut()[relative_offset as usize..][..aligned_image_len] };
	mem_slice[..hermit_image.len()].copy_from_slice(hermit_image);
	mem_slice[hermit_image.len()..].fill(0);
	debug!(
		"Hermit image: start={relative_offset:#x}, length={:#x}",
		hermit_image.len()
	);
	// Safety: the length supplied matches `mem_slice.len()` and the length is aligned to the page size.
	if unsafe {
		libc::mprotect(
			&mut mem_slice[0] as *mut u8 as *mut libc::c_void,
			aligned_image_len,
			libc::PROT_READ | libc::PROT_EXEC,
		)
	} == -1
	{
		let e = std::io::Error::last_os_error();
		warn!("Hermit image mprotect(2) failed: {e}");
	}

	Some(image_start_address..image_actual_end_address)
}
