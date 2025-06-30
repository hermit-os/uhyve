use std::num::NonZeroU32;

use crate::stats::CpuStats;
/// The trait and fns that a virtual cpu requires
use crate::{HypervisorResult, os::DebugExitInfo};

/// Reasons for vCPU exits.
#[cfg_attr(target_os = "macos", expect(dead_code))]
pub enum VcpuStopReason {
	/// The vCPU stopped for debugging.
	Debug(DebugExitInfo),

	/// The vCPU exited with the specified exit code.
	Exit(i32),

	/// The vCPU got kicked.
	Kick,
}

/// Functionality a virtual CPU backend must provide to be used by uhyve
pub trait VirtualCPU: Sized + Send {
	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)>;

	/// Prints the VCPU's registers to stdout.
	fn print_registers(&self);

	/// Queries the CPUs base frequency in kHz
	fn get_cpu_frequency(&self) -> Option<NonZeroU32>;

	/// Perform thread-local initializations for this vcpu
	fn thread_local_init(&mut self) -> HypervisorResult<()>;
}
