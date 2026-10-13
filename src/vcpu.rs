use std::{
	fmt::Debug,
	num::NonZero,
	sync::{Arc, Barrier, Condvar, Mutex},
};

use serde::{Serialize, de::DeserializeOwned};
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

/// An action to be executed by a vCPU when it next exits the guest.
pub(crate) enum MailboxAction<S> {
	Snapshot {
		/// Shared collector each vCPU appends its snapshot into.
		state_target: Arc<Mutex<S>>,
		/// Released by every vCPU once it has written its state.
		done_barrier: Arc<Barrier>,
		/// Released by the backend once it has finished serializing the snapshot.
		resume_barrier: Arc<Barrier>,
		/// When false, the vCPU exits after the backend releases `resume_barrier`.
		resume_after_snapshot: bool,
	},
	Quit,
}

/// Per-vCPU mailbox used by the backend thread to deliver actions to a vCPU.
///
/// The idea is to be resilient to spurious kicks. In these cases, the mailbox
/// is empty and the vCPU can resume.
pub(crate) struct VcpuMailbox<S> {
	slot: Mutex<Option<MailboxAction<S>>>,
	notify: Condvar,
}

impl<S> VcpuMailbox<S> {
	/// Stores `action` in the slot, overwriting any previous unread action, and wakes
	/// any thread blocked in [`Self::wait_for_action`].
	pub(crate) fn put(&self, action: MailboxAction<S>) {
		*self.slot.lock().unwrap() = Some(action);
		self.notify.notify_all();
	}

	/// Returns the pending action without blocking.
	pub(crate) fn try_take(&self) -> Option<MailboxAction<S>> {
		self.slot.lock().unwrap().take()
	}

	/// Blocks until the slot is populated, then returns the action.
	///
	/// Used by a vCPU that has explicitly requested an action (e.g. via the snapshot
	/// hypercall) and now needs to wait for the backend to deliver it.
	pub(crate) fn wait_for_action(&self) -> MailboxAction<S> {
		let mut slot = self.slot.lock().unwrap();
		while slot.is_none() {
			slot = self.notify.wait(slot).unwrap();
		}
		slot.take().unwrap()
	}
}

// Manual impl rather than `#[derive(Default)]`: derive would add an `S: Default` bound
// even though `Mutex<Option<T>>` and `Condvar` are `Default` for any `T`.
impl<S> Default for VcpuMailbox<S> {
	fn default() -> Self {
		Self {
			slot: Mutex::new(None),
			notify: Condvar::new(),
		}
	}
}

// The following duplication of `VirtualCPU` is a work-around
// for https://github.com/rust-lang/rust/issues/115590

/// Functionality a virtual CPU backend must provide to be used by uhyve
#[cfg(not(target_os = "macos"))]
pub trait VirtualCPU: Sized + Send + Sync {
	/// Per-vCPU portion of a snapshot.
	type SnapshotState: Send + Debug + Clone + Serialize + DeserializeOwned;

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

	/// Restores this vCPU's architectural state from a snapshot.
	fn init_from_snapshot(&mut self, state: Self::SnapshotState) -> HypervisorResult<()>;
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
