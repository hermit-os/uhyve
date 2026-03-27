#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub(crate) mod gdb;

pub(crate) type DebugExitInfo = kvm_bindings::kvm_debug_exit_arch;
pub(crate) type Breakpoints = gdb::breakpoints::AllBreakpoints;

use std::sync::LazyLock;

use gdbstub::{common::Tid, stub::MultiThreadStopReason};
use kvm_ioctls::Kvm;
use libc::{SIGRTMAX, SIGRTMIN};
use nix::sys::pthread::Pthread;

use crate::{os::x86_64::kvm_cpu::KvmVm, vm::KickSignal};

static KVM: LazyLock<Kvm> = LazyLock::new(|| Kvm::new().unwrap());

// TODO: nix::signal::Signal doesn't support real-time signals yet.
// Start using the Signal type once this no longer is the case.
//
// See: https://github.com/nix-rust/nix/issues/495
impl KickSignal {
	const RTSIG_OFFSET: libc::c_int = 0;

	fn get() -> libc::c_int {
		let kick_signal: libc::c_int = SIGRTMIN() + Self::RTSIG_OFFSET;
		assert!(kick_signal <= SIGRTMAX());
		kick_signal
	}

	pub(crate) fn register_handler() -> nix::Result<()> {
		extern "C" fn handle_signal(_signal: libc::c_int) {}
		// SAFETY: We don't use the `signal`'s return value and use an empty handler.
		// (Sidenote: SIG_DFL and SIG_IGN don't do the trick.)
		let res = unsafe {
			libc::signal(
				Self::get(),
				handle_signal as *const () as libc::sighandler_t,
			)
		};
		nix::errno::Errno::result(res).map(drop)
	}

	/// Sends the kick signal to a thread.
	///
	/// [`KickSignal::register_handler`] should be called prior to this to avoid crashing the program with the default handler.
	pub(crate) fn pthread_kill(pthread: Pthread) -> nix::Result<()> {
		// SAFETY: Trivially safe, as long as register_handler has been called.
		let res = unsafe { libc::pthread_kill(pthread, Self::get()) };
		nix::errno::Errno::result(res).map(drop)
	}
}

pub(crate) fn debug_info_to_stop_reason(
	debug: DebugExitInfo,
	tid: Tid,
	breakpoints: &Breakpoints,
) -> MultiThreadStopReason<u64> {
	use kvm_bindings::{BP_VECTOR, DB_VECTOR};
	match debug.exception {
		DB_VECTOR => {
			use ::x86_64::registers::debug::Dr6Flags;
			let dr6 = Dr6Flags::from_bits_truncate(debug.dr6);
			breakpoints.hard.stop_reason(tid, dr6)
		}
		BP_VECTOR => MultiThreadStopReason::SwBreak(tid),
		vector => unreachable!("unknown KVM exception vector: {}", vector),
	}
}
