mod breakpoints;
mod regs;
mod section_offsets;

use gdbstub::target::{
	self,
	ext::base::singlethread::{GdbInterrupt, ResumeAction, SingleThreadOps, StopReason},
	Target, TargetError, TargetResult,
};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::{
	kvm_guest_debug, kvm_guest_debug_arch, BP_VECTOR, DB_VECTOR, KVM_GUESTDBG_ENABLE,
	KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
};
use std::convert::TryInto;
use x86_64::registers::debug::Dr6Flags;

use crate::linux::vcpu::UhyveCPU;
use crate::vm::{VcpuStopReason, VirtualCPU};
use crate::{arch::x86_64::registers::debug::HwBreakpoints, Uhyve};

use self::breakpoints::SwBreakpoints;

use super::HypervisorError;

pub struct GdbUhyve {
	vm: Uhyve,
	vcpu: UhyveCPU,
	hw_breakpoints: HwBreakpoints,
	sw_breakpoints: SwBreakpoints,
}

impl GdbUhyve {
	pub fn new(vm: Uhyve, vcpu: UhyveCPU) -> Self {
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
	fn breakpoints(&mut self) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	fn section_offsets(
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
}

impl SingleThreadOps for GdbUhyve {
	fn resume(
		&mut self,
		action: ResumeAction,
		gdb_interrupt: GdbInterrupt<'_>,
	) -> Result<Option<StopReason<u64>>, Self::Error> {
		let step = matches!(action, ResumeAction::Step | ResumeAction::StepWithSignal(_));
		self.apply_guest_debug(step)?;
		let mut gdb_interrupt = gdb_interrupt.no_async();
		match self.vcpu.r#continue()? {
			VcpuStopReason::Debug(debug) => match debug.exception {
				DB_VECTOR => {
					let dr6 = Dr6Flags::from_bits_truncate(debug.dr6);
					Ok(Some(self.hw_breakpoints.stop_reason(dr6)))
				}
				BP_VECTOR => Ok(Some(StopReason::SwBreak)),
				vector => unreachable!("unknown KVM exception vector: {}", vector),
			},
			VcpuStopReason::Exit(code) => {
				let status = if code == 0 { 0 } else { 1 };
				Ok(Some(StopReason::Exited(status)))
			}
			VcpuStopReason::Kick => {
				assert!(
					gdb_interrupt.pending(),
					"VCPU got kicked without a pending GDB interrupt"
				);
				Ok(None)
			}
		}
	}

	fn read_registers(&mut self, regs: &mut X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::read(self.vcpu.get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::write(regs, self.vcpu.get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<(), Self> {
		let src = unsafe { self.vcpu.memory(start_addr, data.len()) };
		data.copy_from_slice(src);
		Ok(())
	}

	fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
		let mem = unsafe { self.vcpu.memory(start_addr, data.len()) };
		mem.copy_from_slice(data);
		Ok(())
	}
}
