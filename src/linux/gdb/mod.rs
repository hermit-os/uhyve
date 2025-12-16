mod breakpoints;
mod regs;
mod section_offsets;

use std::{io::Read, net::TcpStream, sync::Once, thread, time::Duration};

use gdbstub::{
	common::{Signal, Tid},
	conn::{Connection, ConnectionExt},
	stub::{MultiThreadStopReason, run_blocking},
	target::{self, Target, TargetError, TargetResult, ext::base::multithread::MultiThreadBase},
};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::{
	BP_VECTOR, DB_VECTOR, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
	KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug, kvm_guest_debug_arch,
};
use libc::EINVAL;
use nix::sys::pthread::pthread_self;
use uhyve_interface::GuestVirtAddr;
use x86_64::registers::debug::Dr6Flags;

use self::breakpoints::SwBreakpoints;
use crate::{
	HypervisorError, HypervisorResult,
	arch::x86_64::{registers::debug::HwBreakpoints, virt_to_phys},
	linux::{KickSignal, PthreadWrapper, x86_64::kvm_cpu::KvmVm},
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::UhyveVm,
};

pub(crate) struct GdbUhyve {
	pub(crate) vm: UhyveVm<KvmVm>,
	hw_breakpoints: HwBreakpoints,
	sw_breakpoints: SwBreakpoints,
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
		target::ext::base::BaseOps::MultiThread(self)
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

#[inline(always)]
fn tid_from_cpuid(cpu_id: usize) -> Tid {
	Tid::new(cpu_id + 1).unwrap()
}

#[inline(always)]
fn cpuid_from_tid(tid: Tid) -> usize {
	tid.get() - 1
}

impl GdbUhyve {
	fn apply_guest_debug(&mut self, id: usize, step: bool) -> HypervisorResult<()> {
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

		self.vm.vcpus[id]
			.get_vcpu()
			.set_guest_debug(&debug_struct)
			.map_err(HypervisorError::from)
	}

	pub fn run(&mut self) -> HypervisorResult<MultiThreadStopReason<u64>> {
		// FIXME: Apply this to all cores.
		let cpu_id: usize = 0;
		let stop_reason = match self.vm.vcpus[cpu_id].r#continue()? {
			VcpuStopReason::Debug(debug) => match debug.exception {
				DB_VECTOR => {
					let dr6 = Dr6Flags::from_bits_truncate(debug.dr6);
					MultiThreadStopReason::from(
						self.hw_breakpoints.stop_reason(tid_from_cpuid(cpu_id), dr6),
					)
				}
				BP_VECTOR => MultiThreadStopReason::SwBreak(tid_from_cpuid(cpu_id)),
				vector => unreachable!("unknown KVM exception vector: {}", vector),
			},
			VcpuStopReason::Exit(code) => MultiThreadStopReason::Exited(code.try_into().unwrap()),
			VcpuStopReason::Kick => MultiThreadStopReason::Signal(Signal::SIGINT),
		};
		Ok(stop_reason)
	}

	#[inline(always)]
	fn halt(&mut self) {
		for vcpu_id in 0..self.vm.vcpus.len() {
			let _ = self.apply_guest_debug(vcpu_id, true);
		}
	}
}

impl MultiThreadBase for GdbUhyve {
	#[inline(always)]
	fn read_registers(&mut self, regs: &mut X86_64CoreRegs, tid: Tid) -> TargetResult<(), Self> {
		regs::read(self.vm.vcpus[cpuid_from_tid(tid)].get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	#[inline(always)]
	fn write_registers(&mut self, regs: &X86_64CoreRegs, tid: Tid) -> TargetResult<(), Self> {
		regs::write(regs, self.vm.vcpus[cpuid_from_tid(tid)].get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	#[inline(always)]
	fn read_addrs(
		&mut self,
		start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
		data: &mut [u8],
		_tid: Tid, // Assumption: All cores share the same memory.
	) -> TargetResult<usize, Self> {
		let guest_addr = GuestVirtAddr::try_new(start_addr).map_err(|_e| TargetError::NonFatal)?;
		// SAFETY: mem is copied to data before mem can be modified.
		// SAFETY: vCPU 0 presumed to have same memory as all other vCPUs.
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

	#[inline(always)]
	fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
		// SAFETY: self.vm.mem is not altered during the lifetime of mem.
		// SAFETY: vCPU 0 presumed to have same memory as all other vCPUs.
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
	fn list_active_threads(
		&mut self,
		thread_is_active: &mut dyn FnMut(Tid),
	) -> Result<(), Self::Error> {
		for vcpu_id in 0..self.vm.vcpus.len() {
			thread_is_active(tid_from_cpuid(vcpu_id));
		}
		Ok(())
	}

	#[inline(always)]
	fn support_resume(
		&mut self,
	) -> Option<target::ext::base::multithread::MultiThreadResumeOps<'_, Self>> {
		Some(self)
	}
}

impl target::ext::base::multithread::MultiThreadResume for GdbUhyve {
	#[inline(always)]
	fn set_resume_action_continue(
		&mut self,
		tid: Tid,
		signal: Option<Signal>,
	) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot resume with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		let _ = self.apply_guest_debug(cpuid_from_tid(tid), false);
		Ok(())
	}

	/// Handled by clear_resume_actions and set_resume_action_XXX.
	#[inline(always)]
	fn resume(&mut self) -> Result<(), Self::Error> {
		Ok(())
	}

	/// Called before resume and set_resume_action_step.
	#[inline(always)]
	fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
		for vcpu_id in 0..self.vm.vcpus.len() {
			let _ = self.apply_guest_debug(vcpu_id, false);
		}
		Ok(())
	}

	#[inline(always)]
	fn support_single_step(
		&mut self,
	) -> Option<target::ext::base::multithread::MultiThreadSingleStepOps<'_, Self>> {
		Some(self)
	}
}

impl target::ext::base::multithread::MultiThreadSingleStep for GdbUhyve {
	/// Called before resume and after clear_resume_actions.
	#[inline(always)]
	fn set_resume_action_step(
		&mut self,
		tid: Tid,
		signal: Option<Signal>,
	) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot step with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		let _ = self.apply_guest_debug(cpuid_from_tid(tid), true);
		Ok(())
	}
}

pub(crate) enum UhyveGdbEventLoop {}

impl run_blocking::BlockingEventLoop for UhyveGdbEventLoop {
	type Target = GdbUhyve;
	type Connection = TcpStream;
	type StopReason = MultiThreadStopReason<u64>;

	fn wait_for_stop_reason(
		target: &mut Self::Target,
		conn: &mut Self::Connection,
	) -> Result<
		run_blocking::Event<MultiThreadStopReason<u64>>,
		run_blocking::WaitForStopReasonError<
			<Self::Target as Target>::Error,
			<Self::Connection as Connection>::Error,
		>,
	> {
		use run_blocking::WaitForStopReasonError;

		static SPAWN_THREAD: Once = Once::new();

		SPAWN_THREAD.call_once(|| {
			let parent_thread = PthreadWrapper(pthread_self());
			let mut conn_clone = conn.try_clone().unwrap();
			thread::spawn(move || {
				loop {
					// Block on TCP stream without consuming any data.
					Read::read(&mut conn_clone, &mut []).unwrap();

					// Kick VCPU out of KVM_RUN
					KickSignal::pthread_kill(parent_thread.0).unwrap();

					// Wait for all inputs to be processed and for VCPU to be running again
					thread::sleep(Duration::from_millis(20));
				}
			});
		});

		let stop_reason = target.run().map_err(WaitForStopReasonError::Target)?;

		let event = match stop_reason {
			MultiThreadStopReason::Signal(Signal::SIGINT) => {
				assert!(
					conn.peek()
						.map_err(WaitForStopReasonError::Connection)?
						.is_some()
				);
				run_blocking::Event::IncomingData(
					ConnectionExt::read(conn).map_err(WaitForStopReasonError::Connection)?,
				)
			}
			stop_reason => run_blocking::Event::TargetStopped(stop_reason),
		};

		Ok(event)
	}

	fn on_interrupt(
		target: &mut Self::Target,
	) -> Result<Option<MultiThreadStopReason<u64>>, <Self::Target as Target>::Error> {
		// TODO: Reevaluate usefulness.
		target.halt();
		Ok(Some(MultiThreadStopReason::Signal(Signal::SIGINT)))
	}
}
