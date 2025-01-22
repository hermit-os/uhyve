use std::{
	env, fmt, fs, io,
	mem::MaybeUninit,
	num::NonZeroU32,
	os::unix::prelude::JoinHandleExt,
	path::PathBuf,
	sync::{Arc, Barrier, Mutex},
	thread,
	time::SystemTime,
};

use core_affinity::CoreId;
use hermit_entry::{
	boot_info::{BootInfo, HardwareInfo, LoadInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use internal::VirtualizationBackendInternal;
use log::error;
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;

use crate::{
	arch,
	consts::*,
	fdt::Fdt,
	isolation::filemap::UhyveFileMap,
	mem::MmapMemory,
	os::KickSignal,
	params::Params,
	serial::{Destination, UhyveSerial},
	stats::{CpuStats, VmStats},
	vcpu::VirtualCPU,
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

		let freq = vcpus[0].get_cpu_frequency();

		write_fdt_into_mem(&peripherals.mem, &kernel_info.params, freq);
		write_boot_info_to_mem(&peripherals.mem, load_info, cpu_count as u64, freq);

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

	pub fn run_no_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		KickSignal::register_handler().unwrap();

		// After spinning up all vCPU threads, the main thread waits for any vCPU to end execution.
		let barrier = Arc::new(Barrier::new(2));

		debug!("Starting vCPUs");
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
					debug!("Create thread for CPU {}", cpu_id);
					match local_cpu_affinity {
						Some(core_id) => {
							debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
							core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
						}
						None => debug!("No affinity specified, not binding thread"),
					}

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
							error!("CPU {} crashed with {:?}", cpu_id, err);
							barrier.wait();
							(Err(err), None)
						}
					}
				})
			})
			.collect::<Vec<_>>();
		debug!("Waiting for first CPU to finish");

		// Wait for one vCPU to return with an exit code.
		barrier.wait();

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
			0 => panic!(
				"No return code from any CPU? Maybe all have been kick
d?"
			),
			1 => cpu_results[0].0.as_ref().unwrap().unwrap(),
			_ => panic!(
				"more than one thread finished with an exit code (code
: {cpu_results:?})"
			),
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

fn write_fdt_into_mem(mem: &MmapMemory, params: &Params, cpu_freq: Option<NonZeroU32>) {
	debug!("Writing FDT in memory");

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
		.app_args(params.kernel_args.get(sep + 1..).unwrap_or_default())
		.envs(env::vars());
	if let Some(tsc_khz) = cpu_freq {
		fdt = fdt.tsc_khz(tsc_khz.into()).unwrap();
	}
	let fdt = fdt.finish().unwrap();

	debug!("fdt.len() = {}", fdt.len());
	assert!(fdt.len() < (BOOT_INFO_ADDR - FDT_ADDR) as usize);
	unsafe {
		let fdt_ptr = mem.host_address.add(FDT_ADDR.as_u64() as usize);
		fdt_ptr.copy_from_nonoverlapping(fdt.as_ptr(), fdt.len());
	}
}

fn write_boot_info_to_mem(
	mem: &MmapMemory,
	load_info: LoadInfo,
	num_cpus: u64,
	cpu_freq: Option<NonZeroU32>,
) {
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
			cpu_freq,
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
