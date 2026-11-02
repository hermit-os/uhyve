use std::{
	io,
	num::NonZero,
	os::fd::AsRawFd,
	sync::{Arc, LazyLock},
};

use kvm_bindings::*;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use uhyve_interface::GuestPhysAddr;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::kvm as arch;
use crate::{
	HypervisorError, HypervisorResult,
	gdb::resume::ResumeMode,
	mem::MmapMemory,
	os::KickSignal,
	params::{NetworkMode, Params},
	pci::{IOBASE_U64, IOEND_U64, PciConfigurationAddress, PciDevice},
	stats::{CpuStats, VmExit},
	vcpu::{VcpuStopReason, VirtualCPU},
	virtio::net::VirtioNetPciDevice,
	vm::{KernelInfo, VirtualizationBackend, VirtualizationBackendInternal, VmPeripherals},
};

mod virtio_device;
use virtio_device::KvmVirtioNetDevice;

pub(crate) static KVM: LazyLock<Kvm> = LazyLock::new(|| Kvm::new().unwrap());

/// Tells KVM to unblock all signals during `KVM_RUN` for the given vCPU.
fn unblock_all_signals_for_kvm(vcpu: &VcpuFd) -> nix::Result<()> {
	// `_IOW(KVMIO=0xAE, 0x8b, kvm_signal_mask)`.
	const KVM_SET_SIGNAL_MASK: libc::Ioctl = 0x4004_ae8b_u32 as libc::Ioctl;

	// `kvm_bindings::kvm_signal_mask` has a `__IncompleteArrayField` for `sigset`
	// (FAM); the trailing bytes have to be allocated by the caller. We embed an
	// 8-byte zeroed sigset right after the header.
	#[repr(C)]
	struct KvmSignalMaskWithSigset {
		header: kvm_signal_mask,
		sigset: [u8; 8],
	}

	let mut payload = KvmSignalMaskWithSigset {
		header: kvm_signal_mask::default(),
		sigset: [0; 8],
	};
	payload.header.len = 8;

	// SAFETY: `payload` lays out a valid `kvm_signal_mask` followed by its `len`
	// trailing sigset bytes; the fd outlives this call.
	let res = unsafe {
		libc::ioctl(
			vcpu.as_raw_fd(),
			KVM_SET_SIGNAL_MASK,
			&payload as *const _ as *const libc::c_void,
		)
	};
	nix::errno::Errno::result(res).map(drop)
}

#[derive(Debug)]
pub struct KvmVm {
	pub(crate) vm_fd: VmFd,
	pub(crate) peripherals:
		Arc<VmPeripherals<<Self as VirtualizationBackendInternal>::VirtioNetImpl>>,
}
impl VirtualizationBackend for KvmVm {}

pub struct KvmCpu {
	pub id: usize,
	pub vcpu: VcpuFd,
	// TODO: Remove once the getenv/getargs hypercalls are removed
	pub kernel_info: Arc<KernelInfo<<KvmVm as VirtualizationBackendInternal>::MemLayout>>,
	pub peripherals: Arc<VmPeripherals<<KvmVm as VirtualizationBackendInternal>::VirtioNetImpl>>,
	pub pci_addr: Option<u32>,
	pub stats: Option<CpuStats>,
}

impl VirtualizationBackendInternal for KvmVm {
	type VCPU = KvmCpu;
	type VirtioNetImpl = KvmVirtioNetDevice;
	type MemLayout = arch::MemLayout;
	const NAME: &str = "KvmVm";

	fn new_cpu(
		&self,
		id: usize,
		kernel_info: Arc<KernelInfo<Self::MemLayout>>,
		enable_stats: bool,
	) -> HypervisorResult<KvmCpu> {
		let vcpu = self.vm_fd.create_vcpu(id as u64)?;
		let mut kvcpu = KvmCpu {
			id,
			vcpu,
			peripherals: self.peripherals.clone(),
			kernel_info,
			pci_addr: None,
			stats: if enable_stats {
				Some(CpuStats::new(id))
			} else {
				None
			},
		};
		kvcpu.init()?;

		Ok(kvcpu)
	}

	fn new(
		peripherals: Arc<VmPeripherals<Self::VirtioNetImpl>>,
		params: &Params,
	) -> HypervisorResult<Self> {
		Self::new_internal(peripherals, params)
	}

	fn init_guest_mem(
		mem: &mut MmapMemory,
		layout: &Self::MemLayout,
		memory_size: u64,
		legacy_mapping: bool,
	) {
		Self::init_guest_mem_internal(mem, layout, memory_size, legacy_mapping);
	}

	fn virtio_net_device(mode: NetworkMode, memory: Arc<MmapMemory>) -> Self::VirtioNetImpl {
		KvmVirtioNetDevice::new(VirtioNetPciDevice::new(mode, memory))
	}
}

impl KvmCpu {
	pub(crate) fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}
}
impl VirtualCPU for KvmCpu {
	fn thread_local_init(&mut self) -> HypervisorResult<()> {
		// Block the kick signal in this vCPU thread (KVM will unblock it during `KVM_RUN`).
		KickSignal::block_in_current_thread().map_err(io::Error::from)?;
		unblock_all_signals_for_kvm(&self.vcpu).map_err(io::Error::from)?;
		Ok(())
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			self.vcpu.set_sync_valid_reg(kvm_ioctls::SyncReg::Register);
			match self.vcpu.run() {
				Ok(vcpu_stop_reason) => match vcpu_stop_reason {
					VcpuExit::Hlt => {
						// Ignore `VcpuExit::Hlt`
						debug!("{:?}", VcpuExit::Hlt);

						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::Hlt)
						}
					}
					VcpuExit::Shutdown => {
						debug!("{:?}", VcpuExit::Shutdown);
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::Shutdown)
						}
						return Ok(VcpuStopReason::Exit(0));
					}
					#[cfg(target_arch = "x86_64")]
					VcpuExit::IoIn(port, addr) => {
						arch::handle_port_io_read(
							&self.peripherals,
							self.pci_addr,
							self.stats.as_mut(),
							port,
							addr,
						);
					}
					#[cfg(target_arch = "x86_64")]
					VcpuExit::IoOut(port, addr) => {
						// The use of a mut ref would later render the non-mut ref
						// needed for getting the hypercall data adddress impossible.
						let addr = addr.to_owned();
						if let Some(value) = self.handle_port_io_write(port, &addr) {
							return value;
						}
					}
					VcpuExit::MmioRead(addr, data) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::MMIORead)
						}
						match addr {
							_ if Self::handle_mmio_read(addr) => {} // arch specific MMIO reads
							IOBASE_U64..IOEND_U64 => self
								.peripherals
								.virtio_device()
								.unwrap()
								.virtio
								.handle_read(PciConfigurationAddress(addr as u32), data),
							_ => {
								let l = data.len();
								self.print_registers();
								panic!(
									"undefined mmio read of {l} bytes to {addr:#x?} (ConfigAddress {:x?})",
									PciConfigurationAddress::from_guest_address(addr.into())
								);
							}
						}
					}
					VcpuExit::MmioWrite(addr, data) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::MMIOWrite)
						}
						match addr {
							IOBASE_U64..IOEND_U64 => self
								.peripherals
								.virtio_device()
								.unwrap()
								.virtio
								.handle_write(PciConfigurationAddress(addr as u32), data),
							_ => {
								let l = data.len();
								self.print_registers();
								panic!("undefined mmio write of {l} bytes to {addr:#x?}");
							}
						}
					}
					VcpuExit::Debug(debug) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::Debug)
						}
						trace!("Caught debug interrupt: {debug:#?}");
						return Ok(VcpuStopReason::Debug(debug));
					}
					VcpuExit::InternalError => {
						self.print_registers();
						panic!("{:?}", VcpuExit::InternalError)
					}
					VcpuExit::FailEntry(hardware_entry_failure_reason, cpu) => {
						#[expect(dead_code)]
						#[derive(Debug)]
						struct VcpuExitFailEntry {
							hardware_entry_failure_reason: u64,
							cpu: u32,
						}

						let debug = VcpuExitFailEntry {
							hardware_entry_failure_reason,
							cpu,
						};

						let err = io::Error::other(format!("{debug:?}"));
						return Err(err.into());
					}
					vcpu_exit => {
						let err = io::Error::other(format!("not implemented: {vcpu_exit:?}"));
						return Err(err.into());
					}
				},
				Err(err) => match err.errno() {
					libc::EINTR => {
						debug!("Kick upon interrupt");
						KickSignal::drain_pending_in_current_thread();
						return Ok(VcpuStopReason::Kick);
					}
					_ => return Err(err.into()),
				},
			}
		}
	}

	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)> {
		if let Some(stats) = self.stats.as_mut() {
			stats.start_time_measurement();
		}
		let res = match self.r#continue()? {
			VcpuStopReason::Debug(_) => {
				unreachable!("reached debug exit without running in debugging mode")
			}
			VcpuStopReason::Exit(code) => Some(code),
			VcpuStopReason::Kick => None,
		};
		if let Some(stats) = self.stats.as_mut() {
			stats.stop_time_measurement();
		}
		trace!("run exited with {:?}, {:?}", res, self.stats);
		Ok((res, self.stats.take()))
	}

	fn apply_current_guest_debug(
		&mut self,
		breakpoints: &crate::os::gdb::breakpoints::AllBreakpoints,
		resume_mode: ResumeMode,
	) -> HypervisorResult<()> {
		let debugreg = breakpoints.hard.registers();
		let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP;
		// SAFETY: we trust the value of `self.resume.mode`.
		if resume_mode == ResumeMode::Step {
			control |= KVM_GUESTDBG_SINGLESTEP;
		}
		let debug_struct = kvm_guest_debug {
			control,
			pad: 0,
			arch: kvm_guest_debug_arch { debugreg },
		};

		self.vcpu
			.set_guest_debug(&debug_struct)
			.map_err(HypervisorError::from)
	}

	fn print_registers(&self) {
		self.print_registers_internal();
	}

	fn get_cpu_frequency(&self) -> Option<NonZero<u32>> {
		self.get_cpu_frequency_internal()
	}

	fn get_root_pagetable(&self) -> GuestPhysAddr {
		self.get_root_pagetable_internal()
	}

	fn get_vcpu_id(&self) -> usize {
		self.id
	}
}
