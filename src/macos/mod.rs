#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub(crate) mod gdb;

use nix::sys::{
	pthread::{Pthread, pthread_kill},
	signal::{SIGUSR1, SigHandler, Signal, signal},
};

pub use crate::os::aarch64::vcpu::{XhyveCpu, XhyveVm};
use crate::vm::KickSignal;

/// TODO: Use proper structure and methods for this
pub(crate) type DebugExitInfo = xhypervisor::ffi::hv_vcpu_exit_exception_t;
pub(crate) type Breakpoints = gdb::breakpoints::AllBreakpoints;

impl KickSignal {
	const SIG: Signal = SIGUSR1;

	pub(crate) fn register_handler() -> nix::Result<()> {
		extern "C" fn handle_signal(_signal: libc::c_int) {}
		// SAFETY: We don't use the `signal`'s return value.
		unsafe {
			signal(Self::SIG, SigHandler::Handler(handle_signal))?;
		}
		Ok(())
	}

	/// Sends the kick signal to a thread.
	///
	/// [`KickSignal::register_handler`] should be called prior to this to avoid crashing the program with the default handler.
	pub(crate) fn pthread_kill(pthread: Pthread) -> nix::Result<()> {
		pthread_kill(pthread, Self::SIG)
	}
}
