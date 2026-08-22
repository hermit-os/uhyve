#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub(crate) mod fs;
pub(crate) mod gdb;

use std::sync::Mutex;

use nix::sys::{
	pthread::{Pthread, pthread_kill},
	signal::{SIGUSR1, SigHandler, Signal, signal},
};
use xhypervisor::ffi::{hv_vcpu_t, hv_vcpus_exit};

pub use crate::os::aarch64::vcpu::XhyveVm;
use crate::vm::KickSignal;

/// Handles of the vCPUs created so far, for [`KickSignal::kick_all_vcpus`].
static VCPU_HANDLES: Mutex<Vec<hv_vcpu_t>> = Mutex::new(Vec::new());

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

	/// Makes the vCPU known to [`KickSignal::kick_all_vcpus`].
	pub(crate) fn register_vcpu(handle: hv_vcpu_t) {
		VCPU_HANDLES.lock().unwrap().push(handle);
	}

	/// Forces every vCPU out of `hv_vcpu_run`.
	///
	/// The kick signal alone does not reach them: a guest that executed `WFI`
	/// waits inside the framework for an interrupt, not for a POSIX signal,
	/// and `hv_vcpus_exit` is what the framework listens to.
	pub(crate) fn kick_all_vcpus() {
		let handles = VCPU_HANDLES.lock().unwrap();
		if handles.is_empty() {
			return;
		}

		// SAFETY: The handles were created by `hv_vcpu_create` and the vCPUs
		// are still alive, since their threads have not been joined yet.
		unsafe {
			hv_vcpus_exit(handles.as_ptr(), handles.len() as u32);
		}
	}
}
