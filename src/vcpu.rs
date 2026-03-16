use std::num::NonZero;

use uhyve_interface::GuestPhysAddr;

/// The trait and fns that a virtual cpu requires
use crate::{HypervisorResult, os::DebugExitInfo};
use crate::{gdb::resume::ResumeMode, stats::CpuStats};

/// Reasons for vCPU exits.
pub enum VcpuStopReason {
	/// The vCPU stopped for debugging.
	#[cfg_attr(target_os = "macos", expect(dead_code))]
	Debug(DebugExitInfo),

	/// The vCPU exited with the specified exit code.
	Exit(i32),

	/// The vCPU got kicked.
	#[cfg_attr(target_os = "macos", expect(dead_code))]
	Kick,
}

// The following duplication of `VirtualCPU` is a work-around
// for https://github.com/rust-lang/rust/issues/115590

/// Functionality a virtual CPU backend must provide to be used by uhyve
#[cfg(not(target_os = "macos"))]
pub trait VirtualCPU: Sized + Send + Sync {
	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)>;

	/// Updates the vCPU debug context to correspond to the currently active
	/// `ResumeMode`, and `breakpoints`.
	///
	/// This handles e.g. single-stepping of the vCPU.
	fn apply_current_guest_debug(
		&mut self,
		breakpoints: &crate::os::Breakpoints,
		resume_mode: ResumeMode,
	) -> HypervisorResult<()>;

	/// Prints the VCPU's registers to stdout.
	fn print_registers(&self);

	/// Queries the CPUs base frequency in kHz
	fn get_cpu_frequency(&self) -> Option<NonZero<u32>>;

	/// Perform thread-local initializations for this vcpu
	fn thread_local_init(&mut self) -> HypervisorResult<()>;

	/// Get the address to the root page table
	fn get_root_pagetable(&self) -> GuestPhysAddr;

	/// Get the vCPU ID
	fn get_vcpu_id(&self) -> usize;
}

/// Functionality a virtual CPU backend must provide to be used by uhyve
#[cfg(target_os = "macos")]
pub trait VirtualCPU: Sized + Send {
	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)>;

	/// Updates the vCPU debug context to correspond to the currently active
	/// `ResumeMode`, and `breakpoints`.
	///
	/// This handles e.g. single-stepping of the vCPU.
	#[expect(dead_code)]
	fn apply_current_guest_debug(
		&mut self,
		breakpoints: &crate::os::Breakpoints,
		resume_mode: ResumeMode,
	) -> HypervisorResult<()>;

	/// Prints the VCPU's registers to stdout.
	fn print_registers(&self);

	/// Queries the CPUs base frequency in kHz
	fn get_cpu_frequency(&self) -> Option<NonZero<u32>>;

	/// Perform thread-local initializations for this vcpu
	fn thread_local_init(&mut self) -> HypervisorResult<()>;

	/// Get the address to the root page table
	#[expect(dead_code)]
	fn get_root_pagetable(&self) -> GuestPhysAddr;

	/// Get the vCPU ID
	fn get_vcpu_id(&self) -> usize;
}
