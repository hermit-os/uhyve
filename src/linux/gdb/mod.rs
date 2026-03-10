mod breakpoints;
mod regs;
mod section_offsets;

use async_io::block_on;
use gdbstub::{
	common::Signal,
	stub::SingleThreadStopReason,
	target::{self, Target, TargetError, TargetResult, ext::base::singlethread::SingleThreadBase},
};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::{
	BP_VECTOR, DB_VECTOR, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
	KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug, kvm_guest_debug_arch,
};
use libc::EINVAL;
use uhyve_interface::GuestVirtAddr;
use x86_64::registers::debug::Dr6Flags;

use self::breakpoints::SwBreakpoints;
use super::{KickSignal, PthreadWrapper};
use crate::{
	HypervisorError, HypervisorResult,
	arch::x86_64::{registers::debug::HwBreakpoints, virt_to_phys},
	linux::x86_64::kvm_cpu::KvmVm,
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::UhyveVm,
};

pub(crate) struct GdbUhyve {
	pub(crate) vm: UhyveVm<KvmVm>,
	hw_breakpoints: HwBreakpoints,
	sw_breakpoints: SwBreakpoints,
}

pub(crate) struct UhyveToGdbPacket {
	pub(crate) stop_reason: SingleThreadStopReason<u64>,
	pub(crate) this: GdbUhyve,
	resume: async_channel::Sender<GdbUhyve>,
}

/// This automatically handles the attached (stopped) and detached (running) states of a vCPU
pub(crate) struct MaybeUhyveToGdbPacket(pub(crate) Option<UhyveToGdbPacket>);

#[derive(Clone)]
pub(crate) struct GdbUhyveFreewheel {
	pub(crate) stops: async_channel::Receiver<UhyveToGdbPacket>,

	pthread: PthreadWrapper,
}

impl GdbUhyve {
	pub fn new(vm: UhyveVm<KvmVm>) -> Self {
		Self {
			vm,
			hw_breakpoints: HwBreakpoints::new(),
			sw_breakpoints: SwBreakpoints::new(),
		}
	}
}

impl Target for GdbUhyve {
	type Arch = gdbstub_arch::x86::X86_64_SSE;
	type Error = HypervisorError;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate IDET enable methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.

	#[inline(always)]
	fn base_ops(&mut self) -> target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
		target::ext::base::BaseOps::SingleThread(self)
	}

	#[inline(always)]
	fn support_breakpoints(
		&mut self,
	) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	fn support_section_offsets(
		&mut self,
	) -> Option<target::ext::section_offsets::SectionOffsetsOps<'_, Self>> {
		Some(self)
	}
}

impl GdbUhyve {
	fn apply_guest_debug(&mut self, step: bool) -> HypervisorResult<()> {
		let debugreg = self.hw_breakpoints.registers();
		let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP;
		if step {
			control |= KVM_GUESTDBG_SINGLESTEP;
		}
		let debug_struct = kvm_guest_debug {
			control,
			pad: 0,
			arch: kvm_guest_debug_arch { debugreg },
		};

		self.vm.vcpus[0]
			.get_vcpu()
			.set_guest_debug(&debug_struct)
			.map_err(HypervisorError::from)
	}

	pub fn run(&mut self) -> HypervisorResult<SingleThreadStopReason<u64>> {
		let stop_reason = match self.vm.vcpus[0].r#continue()? {
			VcpuStopReason::Debug(debug) => match debug.exception {
				DB_VECTOR => {
					let dr6 = Dr6Flags::from_bits_truncate(debug.dr6);
					self.hw_breakpoints.stop_reason(dr6)
				}
				BP_VECTOR => SingleThreadStopReason::SwBreak(()),
				vector => unreachable!("unknown KVM exception vector: {}", vector),
			},
			VcpuStopReason::Exit(code) => SingleThreadStopReason::Exited(code.try_into().unwrap()),
			VcpuStopReason::Kick => SingleThreadStopReason::Signal(Signal::SIGINT),
		};
		Ok(stop_reason)
	}

	pub fn spawn_freewheel(self) -> GdbUhyveFreewheel {
		use std::os::unix::thread::JoinHandleExt;

		let (stops_s, stops_r) = async_channel::unbounded();
		let (resume_s, resume_r) = async_channel::bounded(1);
		let packet = UhyveToGdbPacket {
			stop_reason: SingleThreadStopReason::SwBreak(()),
			this: self,
			resume: resume_s,
		};

		block_on(async { stops_s.send(packet).await }).expect("unable to send info to GDB");

		let join_handle = std::thread::spawn(move || {
			let mut this = Some(block_on(async {
				resume_r
					.recv()
					.await
					.expect("unable to resume with updates from GDB")
			}));

			loop {
				let mut this2 = match this {
					Some(this2) => this2,
					None => break,
				};
				let stop_reason = this2.run().expect("GDB target error");
				let (resume_s, resume_r) = async_channel::bounded(1);
				let packet = UhyveToGdbPacket {
					stop_reason,
					this: this2,
					resume: resume_s,
				};
				this = block_on(async {
					stops_s
						.send(packet)
						.await
						.expect("unable to send info to GDB");
					resume_r.recv().await.ok()
				});
			}
		});

		let ret = GdbUhyveFreewheel {
			stops: stops_r,
			pthread: PthreadWrapper(join_handle.as_pthread_t()),
		};

		ret
	}
}

impl GdbUhyveFreewheel {
	/// Kick the vCPU
	pub fn kick(&self) {
		KickSignal::pthread_kill(self.pthread.0).unwrap();
	}
}

impl UhyveToGdbPacket {
	/// Give control of the vCPU from GDB back to Uhyve
	pub fn resume(self) {
		let _ = block_on(self.resume.send(self.this));
	}
}

impl Target for MaybeUhyveToGdbPacket {
	type Arch = gdbstub_arch::x86::X86_64_SSE;
	type Error = HypervisorError;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate IDET enable methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.

	#[inline(always)]
	fn base_ops(&mut self) -> target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
		target::ext::base::BaseOps::SingleThread(self)
	}

	#[inline(always)]
	fn support_breakpoints(
		&mut self,
	) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
		self.0.as_mut().map(|i| &mut i.this as &mut _)
	}

	#[inline(always)]
	fn support_section_offsets(
		&mut self,
	) -> Option<target::ext::section_offsets::SectionOffsetsOps<'_, Self>> {
		self.0.as_mut().map(|i| &mut i.this as &mut _)
	}
}

impl SingleThreadBase for MaybeUhyveToGdbPacket {
	fn read_registers(&mut self, regs: &mut X86_64CoreRegs) -> TargetResult<(), Self> {
		if let Some(this) = &mut self.0 {
			this.this.read_registers(regs)
		} else {
			Err(TargetError::NonFatal)
		}
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs) -> TargetResult<(), Self> {
		if let Some(this) = &mut self.0 {
			this.this.write_registers(regs)
		} else {
			Err(TargetError::NonFatal)
		}
	}

	fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
		if let Some(this) = &mut self.0 {
			this.this.read_addrs(start_addr, data)
		} else {
			Err(TargetError::NonFatal)
		}
	}

	fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
		if let Some(this) = &mut self.0 {
			this.this.write_addrs(start_addr, data)
		} else {
			Err(TargetError::NonFatal)
		}
	}

	#[inline(always)]
	fn support_resume(
		&mut self,
	) -> Option<target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
		Some(self)
	}
}

impl target::ext::base::singlethread::SingleThreadResume for MaybeUhyveToGdbPacket {
	fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
		let this = match &mut self.0 {
			// cannot resume while running
			None => return Err(kvm_ioctls::Error::new(EINVAL).into()),
			Some(this) => this,
		};
		if signal.is_some() {
			// cannot resume with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		this.this.apply_guest_debug(false)?;
		self.0.take().unwrap().resume();
		Ok(())
	}

	#[inline(always)]
	fn support_single_step(
		&mut self,
	) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
		self.0.as_mut().map(|i| &mut i.this as &mut _)
	}
}

impl SingleThreadBase for GdbUhyve {
	fn read_registers(&mut self, regs: &mut X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::read(self.vm.vcpus[0].get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::write(regs, self.vm.vcpus[0].get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
		let guest_addr = GuestVirtAddr::try_new(start_addr).map_err(|_e| TargetError::NonFatal)?;
		// Safety: mem is copied to data before mem can be modified.
		let src = unsafe {
			self.vm.peripherals.mem.slice_at(
				virt_to_phys(
					guest_addr,
					&self.vm.peripherals.mem,
					self.vm.vcpus[0].get_root_pagetable(),
				)
				.map_err(|_err| ())?,
				data.len(),
			)
		}
		.map_err(|_e| TargetError::NonFatal)?;
		data.copy_from_slice(src);
		Ok(data.len())
	}

	fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
		// Safety: self.vm.mem is not altered during the lifetime of mem.
		let mem = unsafe {
			self.vm.peripherals.mem.slice_at_mut(
				virt_to_phys(
					GuestVirtAddr::new(start_addr),
					&self.vm.peripherals.mem,
					self.vm.vcpus[0].get_root_pagetable(),
				)
				.map_err(|_err| ())?,
				data.len(),
			)
		}
		.unwrap();

		mem.copy_from_slice(data);
		Ok(())
	}

	#[inline(always)]
	fn support_resume(
		&mut self,
	) -> Option<target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
		Some(self)
	}
}

impl target::ext::base::singlethread::SingleThreadResume for GdbUhyve {
	fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot resume with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		self.apply_guest_debug(false)
	}

	#[inline(always)]
	fn support_single_step(
		&mut self,
	) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
		Some(self)
	}
}

impl target::ext::base::singlethread::SingleThreadSingleStep for GdbUhyve {
	fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot step with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		self.apply_guest_debug(true)
	}
}
