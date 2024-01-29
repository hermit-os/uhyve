mod breakpoints;
mod regs;
mod section_offsets;

use std::{
	io::Read,
	net::TcpStream,
	sync::{Arc, Once},
	thread,
	time::Duration,
};

use gdbstub::{
	common::Signal,
	conn::{Connection, ConnectionExt},
	stub::{run_blocking, SingleThreadStopReason},
	target::{self, ext::base::singlethread::SingleThreadBase, Target, TargetError, TargetResult},
};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::{
	kvm_guest_debug, kvm_guest_debug_arch, BP_VECTOR, DB_VECTOR, KVM_GUESTDBG_ENABLE,
	KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
};
use libc::EINVAL;
use nix::sys::pthread::pthread_self;
use uhyve_interface::GuestVirtAddr;
use x86_64::registers::debug::Dr6Flags;

use self::breakpoints::SwBreakpoints;
use super::HypervisorError;
use crate::{
	arch::x86_64::{registers::debug::HwBreakpoints, virt_to_phys},
	linux::{x86_64::kvm_cpu::KvmCpu, KickSignal},
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::UhyveVm,
};

pub struct GdbUhyve {
	vm: Arc<UhyveVm<KvmCpu>>,
	vcpu: KvmCpu,
	hw_breakpoints: HwBreakpoints,
	sw_breakpoints: SwBreakpoints,
}

impl GdbUhyve {
	pub fn new(vm: Arc<UhyveVm<KvmCpu>>, vcpu: KvmCpu) -> Self {
		Self {
			vm,
			vcpu,
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
	fn apply_guest_debug(&mut self, step: bool) -> Result<(), kvm_ioctls::Error> {
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
		self.vcpu.get_vcpu().set_guest_debug(&debug_struct)
	}

	pub fn run(&mut self) -> Result<SingleThreadStopReason<u64>, kvm_ioctls::Error> {
		let stop_reason = match self.vcpu.r#continue()? {
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
}

impl SingleThreadBase for GdbUhyve {
	fn read_registers(&mut self, regs: &mut X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::read(self.vcpu.get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::write(regs, self.vcpu.get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
		let guest_addr = GuestVirtAddr::try_new(start_addr).map_err(|_e| TargetError::NonFatal)?;
		// Safety: mem is copied to data before mem can be modified.
		let src = unsafe {
			self.vm.mem.slice_at(
				virt_to_phys(guest_addr, &self.vm.mem).map_err(|_err| ())?,
				data.len(),
			)
		}
		.unwrap();
		data.copy_from_slice(src);
		Ok(data.len())
	}

	fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
		// Safety: self.vm.mem is not altered during the lifetime of mem.
		let mem = unsafe {
			self.vm.mem.slice_at_mut(
				virt_to_phys(GuestVirtAddr::new(start_addr), &self.vm.mem).map_err(|_err| ())?,
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
			return Err(kvm_ioctls::Error::new(EINVAL));
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
			return Err(kvm_ioctls::Error::new(EINVAL));
		}

		self.apply_guest_debug(true)
	}
}

pub enum UhyveGdbEventLoop {}

impl run_blocking::BlockingEventLoop for UhyveGdbEventLoop {
	type Target = GdbUhyve;
	type Connection = TcpStream;
	type StopReason = SingleThreadStopReason<u64>;

	#[allow(clippy::type_complexity)]
	fn wait_for_stop_reason(
		target: &mut Self::Target,
		conn: &mut Self::Connection,
	) -> Result<
		run_blocking::Event<SingleThreadStopReason<u64>>,
		run_blocking::WaitForStopReasonError<
			<Self::Target as Target>::Error,
			<Self::Connection as Connection>::Error,
		>,
	> {
		use run_blocking::WaitForStopReasonError;

		static SPAWN_THREAD: Once = Once::new();

		SPAWN_THREAD.call_once(|| {
			let parent_thread = pthread_self();
			let mut conn_clone = conn.try_clone().unwrap();
			thread::spawn(move || {
				loop {
					// Block on TCP stream without consuming any data.
					Read::read(&mut conn_clone, &mut []).unwrap();

					// Kick VCPU out of KVM_RUN
					KickSignal::pthread_kill(parent_thread).unwrap();

					// Wait for all inputs to be processed and for VCPU to be running again
					thread::sleep(Duration::from_millis(20));
				}
			});
		});

		let stop_reason = target.run().map_err(WaitForStopReasonError::Target)?;

		let event = match stop_reason {
			SingleThreadStopReason::Signal(Signal::SIGINT) => {
				assert!(conn
					.peek()
					.map_err(WaitForStopReasonError::Connection)?
					.is_some());
				run_blocking::Event::IncomingData(
					ConnectionExt::read(conn).map_err(WaitForStopReasonError::Connection)?,
				)
			}
			stop_reason => run_blocking::Event::TargetStopped(stop_reason),
		};

		Ok(event)
	}

	fn on_interrupt(
		_target: &mut Self::Target,
	) -> Result<Option<SingleThreadStopReason<u64>>, <Self::Target as Target>::Error> {
		Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
	}
}
