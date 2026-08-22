use std::{
	io,
	num::NonZero,
	os::fd::AsRawFd,
	sync::{Arc, LazyLock},
};

use kvm_bindings::*;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use nix::sys::pthread::pthread_self;
use uhyve_interface::GuestPhysAddr;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::kvm::{self as arch, PortWrite};
use crate::{
	HypervisorResult,
	gdb::{PthreadWrapper, resume::ResumeMode},
	hypercall::{self, GuestHypercall, HypercallAction},
	mem::MmapMemory,
	os::KickSignal,
	params::{NetworkMode, Params},
	pci::{IOBASE_U64, IOEND_U64, PciConfigurationAddress, PciDevice},
	stats::{CpuStats, VmExit},
	vcpu::{KickHandle, VcpuStopReason, VirtualCPU},
	virtio::net::VirtioNetPciDevice,
	vm::{KernelInfo, VirtualizationBackend, VirtualizationBackendInternal, VmPeripherals},
};

pub(crate) mod breakpoints;
use breakpoints::AllBreakpoints;

mod virtio_device;
use virtio_device::KvmVirtioNetDevice;

pub(crate) static KVM: LazyLock<Kvm> = LazyLock::new(|| Kvm::new().unwrap());

/// Kicks a [`KvmCpu`] out of `KVM_RUN` by signalling its thread.
#[derive(Clone, Copy, Debug)]
pub struct KvmKickHandle(PthreadWrapper);

impl KickHandle for KvmKickHandle {
	fn kick(&self) -> nix::Result<()> {
		KickSignal::pthread_kill(self.0.0)
	}
}

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
	vm_fd: VmFd,
	peripherals: Arc<VmPeripherals<<Self as VirtualizationBackendInternal>::VirtioNetImpl>>,
}
impl VirtualizationBackend for KvmVm {}

pub struct KvmCpu {
	id: usize,
	vcpu: VcpuFd,
	// TODO: Remove once the getenv/getargs hypercalls are removed
	kernel_info: Arc<KernelInfo<<KvmVm as VirtualizationBackendInternal>::MemLayout>>,
	peripherals: Arc<VmPeripherals<<KvmVm as VirtualizationBackendInternal>::VirtioNetImpl>>,
	pci_ports: arch::PciConfigPorts,
	stats: Option<CpuStats>,
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
		let kvcpu = KvmCpu {
			id,
			vcpu,
			peripherals: self.peripherals.clone(),
			kernel_info,
			pci_ports: Default::default(),
			stats: if enable_stats {
				Some(CpuStats::new(id))
			} else {
				None
			},
		};
		arch::init_vcpu(&kvcpu.vcpu, &kvcpu.kernel_info, id)?;

		Ok(kvcpu)
	}

	fn new(
		peripherals: Arc<VmPeripherals<Self::VirtioNetImpl>>,
		params: &Params,
	) -> HypervisorResult<Self> {
		let vm_fd = KVM.create_vm().unwrap();

		let mem = &peripherals.mem;
		let kvm_mem = kvm_userspace_memory_region {
			slot: 0,
			flags: 0, // Can be KVM_MEM_LOG_DIRTY_PAGES and KVM_MEM_READONLY
			memory_size: mem.size() as u64,
			guest_phys_addr: mem.guest_addr().as_u64(),
			userspace_addr: mem.host_start() as u64,
		};
		unsafe { vm_fd.set_user_memory_region(kvm_mem) }?;

		arch::setup_vm(&vm_fd, mem, params)?;

		if let Some(mut virtiodevice) = peripherals.virtio_device() {
			virtiodevice.setup(&vm_fd);
		}

		Ok(Self { vm_fd, peripherals })
	}

	fn init_guest_mem(
		mem: &mut MmapMemory,
		layout: &Self::MemLayout,
		memory_size: u64,
		legacy_mapping: bool,
	) {
		arch::init_guest_mem(mem, layout, memory_size, legacy_mapping);
	}

	fn virtio_net_device(mode: NetworkMode, memory: Arc<MmapMemory>) -> Self::VirtioNetImpl {
		KvmVirtioNetDevice::new(VirtioNetPciDevice::new(mode, memory))
	}
}

impl KvmCpu {
	pub(crate) fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}

	/// Returns `Some` if the vCPU should stop.
	fn handle_hypercall(
		&self,
		hypercall: GuestHypercall<'_>,
	) -> Option<HypervisorResult<VcpuStopReason>> {
		match hypercall {
			GuestHypercall::V2(hypercall) => {
				match hypercall::handle_hypercall_v2(&self.peripherals, hypercall) {
					HypercallAction::Stop(stop) => Some(Ok(stop)),
					HypercallAction::None => None,
				}
			}
			GuestHypercall::V1(hypercall) => hypercall::handle_hypercall_v1(
				&self.peripherals,
				&self.kernel_info,
				|| Ok(self.get_root_pagetable()),
				hypercall,
			),
		}
	}
}
impl VirtualCPU for KvmCpu {
	type KickHandle = KvmKickHandle;

	fn thread_local_init(&mut self) -> HypervisorResult<()> {
		// Block the kick signal in this vCPU thread (KVM will unblock it during `KVM_RUN`).
		KickSignal::block_in_current_thread().map_err(io::Error::from)?;
		unblock_all_signals_for_kvm(&self.vcpu).map_err(io::Error::from)?;
		Ok(())
	}

	fn create_kick_handle(&self) -> KvmKickHandle {
		KvmKickHandle(PthreadWrapper(pthread_self()))
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
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::PCIRead)
						}
						self.pci_ports.read(&self.peripherals, port, addr);
					}
					#[cfg(target_arch = "x86_64")]
					VcpuExit::IoOut(port, data) => {
						// The use of a mut ref would later render the non-mut ref
						// needed for getting the hypercall data adddress impossible.
						let data = data.to_owned();

						let port_write = arch::classify_port_write(
							&self.peripherals.mem,
							&self.vcpu,
							port,
							&data.to_owned(),
						);
						if let Some(s) = self.stats.as_mut() {
							s.increment_val((&port_write).into())
						}
						match port_write {
							PortWrite::Hypercall(hypercall) => {
								if let Some(stop) = self.handle_hypercall(hypercall) {
									return stop;
								}
							}
							PortWrite::PortIOAccess => {
								self.pci_ports.write(&self.peripherals, port, &data);
							}
						}
					}
					VcpuExit::MmioRead(addr, data) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::MMIORead)
						}
						match addr {
							_ if arch::handle_mmio_read(addr) => {}
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
		breakpoints: &AllBreakpoints,
		resume_mode: ResumeMode,
	) -> HypervisorResult<()> {
		arch::set_guest_debug(&self.vcpu, breakpoints, resume_mode)
	}

	fn print_registers(&self) {
		arch::print_registers(&self.vcpu, self.id);
	}

	fn get_cpu_frequency(&self) -> Option<NonZero<u32>> {
		arch::get_cpu_frequency(&self.vcpu)
	}

	fn get_root_pagetable(&self) -> GuestPhysAddr {
		arch::get_root_pagetable(&self.vcpu)
	}

	fn get_vcpu_id(&self) -> usize {
		self.id
	}
}
