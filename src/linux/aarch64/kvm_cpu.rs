use std::{
	io,
	num::NonZero,
	os::fd::AsRawFd,
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
};

use kvm_bindings::*;
use kvm_ioctls::{DeviceFd, VcpuExit, VcpuFd, VmFd};
use uhyve_interface::{GuestPhysAddr, v1};

use crate::{
	HypervisorError, HypervisorResult,
	arch::{
		Aarch64MemoryLayout, GICD_BASE_ADDRESS, GICR_BASE_ADDRESS, MT_DEVICE_GRE, MT_DEVICE_nGnRE,
		MT_DEVICE_nGnRnE, MT_NORMAL, MT_NORMAL_NC, PSR, TCR_FLAGS, TCR_TG1_4K, VA_BITS,
		init_guest_mem, mair, tcr_size,
	},
	gdb::resume::ResumeMode,
	hypercall,
	mem::MmapMemory,
	mem_layout::MemoryLayout,
	os::{
		KVM, KickSignal,
		aarch64::{regs, virtio_device::KvmVirtioNetDevice},
	},
	params::{NetworkMode, Params},
	stats::{CpuStats, VmExit},
	vcpu::{VcpuStopReason, VirtualCPU},
	virtio::net::VirtioNetPciDevice,
	vm::{KernelInfo, VirtualizationBackend, VirtualizationBackendInternal, VmPeripherals},
};

/// Tells KVM to unblock all signals during `KVM_RUN` for the given vCPU.
fn unblock_all_signals_for_kvm(vcpu: &VcpuFd) -> nix::Result<()> {
	// `_IOW(KVMIO=0xAE, 0x8b, kvm_signal_mask)`.
	const KVM_SET_SIGNAL_MASK: libc::c_ulong = 0x4004_ae8b;

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
	gic: DeviceFd,
	// The GIC's redistributor layout is derived from the vCPUs that exist when it
	// is initialized, so that has to wait until the last one has been created.
	cpu_count: usize,
	created_cpus: AtomicUsize,
	peripherals: Arc<VmPeripherals<<Self as VirtualizationBackendInternal>::VirtioNetImpl>>,
}

impl KvmVm {
	fn create_gic(vm: &VmFd) -> HypervisorResult<DeviceFd> {
		let mut gic_device = kvm_create_device {
			type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
			fd: 0,
			flags: 0,
		};
		let gic = vm.create_device(&mut gic_device)?;

		for (attr, addr) in [
			(KVM_VGIC_V3_ADDR_TYPE_DIST, GICD_BASE_ADDRESS),
			(KVM_VGIC_V3_ADDR_TYPE_REDIST, GICR_BASE_ADDRESS),
		] {
			gic.set_device_attr(&kvm_device_attr {
				group: KVM_DEV_ARM_VGIC_GRP_ADDR,
				attr: attr.into(),
				addr: &raw const addr as u64,
				flags: 0,
			})?;
		}

		Ok(gic)
	}

	fn init_gic(&self) -> HypervisorResult<()> {
		self.gic.set_device_attr(&kvm_device_attr {
			group: KVM_DEV_ARM_VGIC_GRP_CTRL,
			attr: KVM_DEV_ARM_VGIC_CTRL_INIT.into(),
			addr: 0,
			flags: 0,
		})?;

		Ok(())
	}
}

impl VirtualizationBackendInternal for KvmVm {
	type VCPU = KvmCpu;
	type VirtioNetImpl = KvmVirtioNetDevice;
	type MemLayout = Aarch64MemoryLayout;
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
			stats: if enable_stats {
				Some(CpuStats::new(id))
			} else {
				None
			},
		};
		kvcpu.init(&self.vm_fd)?;

		if self.created_cpus.fetch_add(1, Ordering::Relaxed) + 1 == self.cpu_count {
			self.init_gic()?;
		}

		Ok(kvcpu)
	}

	fn new(
		peripherals: Arc<VmPeripherals<Self::VirtioNetImpl>>,
		params: &Params,
	) -> HypervisorResult<Self> {
		let vm = KVM.create_vm().unwrap();

		// The hypercall MMIO window sits below `RAM_START` and is deliberately
		// left unbacked, so accesses to it leave the guest as MMIO exits.
		let kvm_mem = kvm_userspace_memory_region {
			slot: 0,
			flags: 0, // Can be KVM_MEM_LOG_DIRTY_PAGES and KVM_MEM_READONLY
			memory_size: peripherals.mem.size() as u64,
			guest_phys_addr: peripherals.mem.guest_addr().as_u64(),
			userspace_addr: peripherals.mem.host_start() as u64,
		};
		unsafe { vm.set_user_memory_region(kvm_mem) }?;

		trace!("Initialize interrupt controller");
		let gic = Self::create_gic(&vm)?;

		if let Some(virtiodevice) = &peripherals.virtio_device {
			virtiodevice.lock().unwrap().setup(&vm);
		}

		Ok(Self {
			vm_fd: vm,
			gic,
			cpu_count: params.cpu_count.get() as usize,
			created_cpus: AtomicUsize::new(0),
			peripherals,
		})
	}

	fn init_guest_mem(
		mem: &mut MmapMemory,
		layout: &Self::MemLayout,
		memory_size: u64,
		_legacy_mapping: bool,
	) {
		init_guest_mem(mem, layout, memory_size);
	}

	fn virtio_net_device(mode: NetworkMode, memory: Arc<MmapMemory>) -> Self::VirtioNetImpl {
		KvmVirtioNetDevice::new(VirtioNetPciDevice::new(mode, memory))
	}
}

impl VirtualizationBackend for KvmVm {}

pub struct KvmCpu {
	id: usize,
	vcpu: VcpuFd,
	peripherals: Arc<VmPeripherals<<KvmVm as VirtualizationBackendInternal>::VirtioNetImpl>>,
	// TODO: Remove once the getenv/getargs hypercalls are removed
	kernel_info: Arc<KernelInfo<<KvmVm as VirtualizationBackendInternal>::MemLayout>>,
	stats: Option<CpuStats>,
}

impl KvmCpu {
	fn init(&mut self, vm_fd: &VmFd) -> HypervisorResult<()> {
		let mut kvi = kvm_vcpu_init::default();
		vm_fd.get_preferred_target(&mut kvi)?;
		self.vcpu.vcpu_init(&kvi)?;

		self.setup_registers()?;

		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};
		self.vcpu.set_mp_state(mp_state)?;

		Ok(())
	}

	fn setup_registers(&self) -> Result<(), kvm_ioctls::Error> {
		let KernelInfo {
			entry_point,
			layout,
			..
		} = &*self.kernel_info;
		let vcpu = &self.vcpu;

		/* pstate = all interrupts masked */
		let pstate = PSR::D_BIT | PSR::A_BIT | PSR::I_BIT | PSR::F_BIT | PSR::MODE_EL1H;
		regs::set_u64(vcpu, regs::PSTATE, pstate.bits())?;
		regs::set_u64(vcpu, regs::PC, entry_point.as_u64())?;
		regs::set_u64(vcpu, regs::SP_EL1, layout.stack().0.addr.as_u64())?;
		regs::set_u64(vcpu, regs::x(0), layout.boot_info().0.addr.as_u64())?;
		regs::set_u64(vcpu, regs::x(1), self.id as u64)?;

		/*
		 * Setup memory attribute type tables
		 *
		 * Memory regioin attributes for LPAE:
		 *
		 *   n = AttrIndx[2:0]
		 *                      n       MAIR
		 *   DEVICE_nGnRnE      000     00000000 (0x00)
		 *   DEVICE_nGnRE       001     00000100 (0x04)
		 *   DEVICE_GRE         010     00001100 (0x0c)
		 *   NORMAL_NC          011     01000100 (0x44)
		 *   NORMAL             100     11111111 (0xff)
		 */
		let mair_el1 = mair(0x00, MT_DEVICE_nGnRnE)
			| mair(0x04, MT_DEVICE_nGnRE)
			| mair(0x0c, MT_DEVICE_GRE)
			| mair(0x44, MT_NORMAL_NC)
			| mair(0xff, MT_NORMAL);
		regs::set_u64(vcpu, regs::MAIR_EL1, mair_el1)?;

		/*
		 * Setup translation control register (TCR)
		 */
		let aa64mmfr0_el1 = regs::get_u64(vcpu, regs::ID_AA64MMFR0_EL1)?;
		let tcr = ((aa64mmfr0_el1 & 0xF) << 32) | (tcr_size(VA_BITS) | TCR_TG1_4K | TCR_FLAGS);
		let tcr_el1 = (tcr & 0xFFFFFFF0FFFFFFFFu64) | ((aa64mmfr0_el1 & 0xFu64) << 32);
		regs::set_u64(vcpu, regs::TCR_EL1, tcr_el1)?;

		/*
		 * Enable FP/ASIMD in Architectural Feature Access Control Register,
		 */
		let cpacr_el1 = regs::get_u64(vcpu, regs::CPACR_EL1)? | (3 << 20);
		regs::set_u64(vcpu, regs::CPACR_EL1, cpacr_el1)?;

		/*
		 * Reset debug control register
		 */
		regs::set_u64(vcpu, regs::MDSCR_EL1, 0)?;

		// Load TTBRx
		regs::set_u64(vcpu, regs::TTBR1_EL1, 0)?;
		regs::set_u64(vcpu, regs::TTBR0_EL1, layout.pgt_address().as_u64())?;

		/*
		* Prepare system control register (SCTRL)
		* Todo: - Verify if all of these bits actually should be explicitly set
			   - Link origin of this documentation and check to which instruction set versions
				 it applies (if applicable)
			   - Fill in the missing Documentation for some of the bits and verify if we care about them
				 or if loading and not setting them would be the appropriate action.
		*/
		#[expect(clippy::identity_op)]
		let sctrl_el1: u64 = 0
		 | (1 << 26) 	    /* UCI	Enables EL0 access in AArch64 for DC CVAU, DC CIVAC,
									DC CVAC and IC IVAU instructions */
		 | (0 << 25)		/* EE	Explicit data accesses at EL1 and Stage 1 translation
									table walks at EL1 & EL0 are little-endian */
		 | (0 << 24)		/* EOE	Explicit data accesses at EL0 are little-endian */
		 | (1 << 23)
		 | (1 << 22)
		 | (1 << 20)
		 | (0 << 19)		/* WXN	Regions with write permission are not forced to XN */
		 | (1 << 18)		/* nTWE	WFE instructions are executed as normal */
		 | (0 << 17)
		 | (1 << 16)		/* nTWI	WFI instructions are executed as normal */
		 | (1 << 15)		/* UCT	Enables EL0 access in AArch64 to the CTR_EL0 register */
		 | (1 << 14)		/* DZE	Execution of the DC ZVA instruction is allowed at EL0 */
		 | (0 << 13)
		 | (1 << 12)		/* I	Instruction caches enabled at EL0 and EL1 */
		 | (1 << 11)
		 | (0 << 10)
		 | (0 << 9)			/* UMA	Disable access to the interrupt masks from EL0 */
		 | (1 << 8)			/* SED	The SETEND instruction is available */
		 | (0 << 7)			/* ITD	The IT instruction functionality is available */
		 | (0 << 6)			/* THEE	ThumbEE is disabled */
		 | (0 << 5)			/* CP15BEN	CP15 barrier operations disabled */
		 | (1 << 4)			/* SA0	Stack Alignment check for EL0 enabled */
		 | (1 << 3)			/* SA	Stack Alignment check enabled */
		 | (1 << 2)			/* C	Data and unified enabled */
		 | (0 << 1)			/* A	Alignment fault checking disabled */
		 | (1 << 0)			/* M	MMU enable */
		;
		regs::set_u64(vcpu, regs::SCTLR_EL1, sctrl_el1)?;

		Ok(())
	}

	pub(crate) fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}

	/// Handles an MMIO exit, dispatching it as a hypercall.
	///
	/// Returns `Some` if the vCPU should stop.
	fn handle_mmio(&mut self, addr: u64) -> Option<HypervisorResult<VcpuStopReason>> {
		// The hypercall window is identity mapped, so the faulting address is the
		// hypercall address itself.
		// The hypercall's argument struct is passed in X8.
		let data_addr = GuestPhysAddr::new(regs::get_u64(&self.vcpu, regs::x(8)).unwrap());

		if let Some(hypercall) =
			unsafe { hypercall::address_to_hypercall_v2(&self.peripherals.mem, addr, data_addr) }
		{
			if let Some(s) = self.stats.as_mut() {
				s.increment_val((&hypercall).into())
			}

			hypercall::handle_hypercall_v2(&self.peripherals, hypercall).map(Ok)
		} else if let Some(hypercall) = unsafe {
			hypercall::address_to_hypercall_v1(
				&self.peripherals.mem,
				addr.try_into().unwrap(),
				data_addr,
			)
		} {
			if let Some(s) = self.stats.as_mut() {
				s.increment_val((&hypercall).into())
			}

			if let v1::Hypercall::SerialWriteByte(_) = &hypercall {
				let x8 = (regs::get_u64(&self.vcpu, regs::x(8)).unwrap() & 0xFF) as u8;
				self.peripherals
					.serial
					.output(&[x8])
					.unwrap_or_else(|e| error!("{e:?}"));
				None
			} else {
				hypercall::handle_hypercall_v1(
					&self.peripherals,
					&self.kernel_info,
					|| Ok(self.get_root_pagetable()),
					hypercall,
				)
			}
		} else {
			self.print_registers();
			panic!("undefined mmio access to {addr:#x?}");
		}
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
			match self.vcpu.run() {
				Ok(vcpu_stop_reason) => match vcpu_stop_reason {
					// Unlike x86's port I/O, every hypercall on aarch64 arrives as
					// an MMIO access. KVM emulates the faulting instruction and
					// advances the program counter itself.
					VcpuExit::MmioRead(addr, _data) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::MMIORead)
						}
						if let Some(stop) = self.handle_mmio(addr) {
							return stop;
						}
					}
					VcpuExit::MmioWrite(addr, _data) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::MMIOWrite)
						}
						if let Some(stop) = self.handle_mmio(addr) {
							return stop;
						}
					}
					VcpuExit::SystemEvent(KVM_SYSTEM_EVENT_SHUTDOWN, _) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::Shutdown)
						}
						return Ok(VcpuStopReason::Exit(0));
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
						let err = io::Error::other(format!(
							"FailEntry {{ hardware_entry_failure_reason: {hardware_entry_failure_reason:#x}, cpu: {cpu} }}"
						));
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
		let registers = breakpoints.hard.registers();
		let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW;
		if resume_mode == ResumeMode::Step {
			control |= KVM_GUESTDBG_SINGLESTEP;
		}
		let debug_struct = kvm_guest_debug {
			control,
			pad: 0,
			arch: kvm_guest_debug_arch {
				dbg_bcr: registers.bcr,
				dbg_bvr: registers.bvr,
				dbg_wcr: registers.wcr,
				dbg_wvr: registers.wvr,
			},
		};

		self.vcpu
			.set_guest_debug(&debug_struct)
			.map_err(HypervisorError::from)
	}

	fn print_registers(&self) {
		let get = |id| regs::get_u64(&self.vcpu, id).unwrap();

		println!();
		println!("Dump state of CPU {}", self.id);
		println!();
		println!("Registers:");
		println!("----------");
		for n in 0..31 {
			println!("x{n:<2}: {:#18x}", get(regs::x(n)));
		}
		println!("sp:  {:#18x}", get(regs::SP_EL1));
		println!("pc:  {:#18x}", get(regs::PC));
		println!("pstate: {:#18x}", get(regs::PSTATE));
		println!();
		println!("System registers:");
		println!("-----------------");
		println!("sctlr_el1: {:#18x}", get(regs::SCTLR_EL1));
		println!("tcr_el1:   {:#18x}", get(regs::TCR_EL1));
		println!("mair_el1:  {:#18x}", get(regs::MAIR_EL1));
		println!("ttbr0_el1: {:#18x}", get(regs::TTBR0_EL1));
		println!("ttbr1_el1: {:#18x}", get(regs::TTBR1_EL1));
	}

	fn get_cpu_frequency(&self) -> Option<NonZero<u32>> {
		warn!("CPU base frequency detection not implemented!");
		None
	}

	fn get_root_pagetable(&self) -> GuestPhysAddr {
		GuestPhysAddr::new(regs::get_u64(&self.vcpu, regs::TTBR0_EL1).unwrap())
	}

	fn get_vcpu_id(&self) -> usize {
		self.id
	}
}
