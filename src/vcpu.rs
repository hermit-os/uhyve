/// The trait and fns that a virtual cpu requires
use crate::{os::DebugExitInfo, HypervisorResult};
use crate::{stats::CpuStats, vm::VirtualizationBackend};

/// Reasons for vCPU exits.
#[allow(dead_code)]
pub enum VcpuStopReason {
	/// The vCPU stopped for debugging.
	Debug(DebugExitInfo),

	/// The vCPU exited with the specified exit code.
	Exit(i32),

	/// The vCPU got kicked.
	Kick,
}

/// Functionality a virtual CPU backend must provide to be used by uhyve
pub trait VirtualCPU: Sized {
	type VirtIf: VirtualizationBackend;

	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)>;

	/// Prints the VCPU's registers to stdout.
	#[allow(dead_code)]
	fn print_registers(&self);
}
