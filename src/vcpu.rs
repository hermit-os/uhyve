use std::sync::Arc;

use crate::vm::UhyveVm;
/// The trait and fns that a virtual cpu requires
use crate::{os::DebugExitInfo, HypervisorResult};

/// Reasons for vCPU exits.
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
	/// Create a new CPU object
	fn new(id: u32, vm: Arc<UhyveVm<Self>>) -> HypervisorResult<Self>;

	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<Option<i32>>;

	/// Prints the VCPU's registers to stdout.
	fn print_registers(&self);
}
