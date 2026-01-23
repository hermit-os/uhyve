#[cfg(target_arch = "aarch64")]
pub mod aarch64;

use core_affinity::CoreId;
use nix::sys::{
	pthread::{Pthread, pthread_kill},
	signal::{SIGUSR1, SigHandler, Signal, signal},
};

#[cfg(target_arch = "aarch64")]
pub use crate::macos::aarch64::vcpu::{XhyveCpu, XhyveVm};
#[cfg(target_arch = "x86_64")]
pub use crate::macos::x86_64::vcpu::{XhyveCpu, XhyveVm};
use crate::vm::{UhyveVm, VmResult};

/// The signal for kicking vCPUs out of KVM_RUN.
///
/// It is used to stop a vCPU from another thread.
pub(crate) struct KickSignal;

impl KickSignal {
	fn get() -> Signal {
		SIGUSR1
	}

	pub(crate) fn register_handler() -> nix::Result<()> {
		extern "C" fn handle_signal(_signal: libc::c_int) {}
		// SAFETY: We don't use the `signal`'s return value.
		unsafe {
			signal(Self::get(), SigHandler::Handler(handle_signal))?;
		}
		Ok(())
	}

	/// Sends the kick signal to a thread.
	///
	/// [`KickSignal::register_handler`] should be called prior to this to avoid crashing the program with the default handler.
	pub(crate) fn pthread_kill(pthread: Pthread) -> nix::Result<()> {
		pthread_kill(pthread, Self::get())
	}
}

pub(crate) type DebugExitInfo = ();

impl UhyveVm<XhyveVm> {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		self.run_no_gdb(cpu_affinity)
	}
}
