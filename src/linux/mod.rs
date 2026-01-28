#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub(crate) mod gdb;

pub(crate) type DebugExitInfo = kvm_bindings::kvm_debug_exit_arch;

use std::{
	io,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
	sync::LazyLock,
};

use core_affinity::CoreId;
use gdbstub::stub::{DisconnectReason, GdbStub};
use kvm_ioctls::Kvm;
use libc::{SIGRTMAX, SIGRTMIN};
use nix::sys::pthread::Pthread;

use crate::{
	linux::{
		gdb::{GdbUhyve, UhyveGdbEventLoop},
		x86_64::kvm_cpu::KvmVm,
	},
	serial::Destination,
	vcpu::VirtualCPU,
	vm::{UhyveVm, VmResult},
};

static KVM: LazyLock<Kvm> = LazyLock::new(|| Kvm::new().unwrap());

/// The signal for kicking vCPUs out of KVM_RUN.
///
/// It is used to stop a vCPU from another thread.
pub(crate) struct KickSignal;

/// A way of sending pthread IDs reliably across threads.
///
/// # Platform-specific behavior
///
/// This is particularly necessary for musl, as `Pthread` is equal to `*mut c_void` there,
/// which can't be passed to thread as easily
///
/// # Safety
///
/// This can be safely sent across threads because pthread IDs are just opaque identifiers
/// and thread-safety is ensured by the pthread library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PthreadWrapper(pub Pthread);

unsafe impl Send for PthreadWrapper {}
unsafe impl Sync for PthreadWrapper {}

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

impl UhyveVm<KvmVm> {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		KickSignal::register_handler().unwrap();

		if self.kernel_info.params.gdb_port.is_none() {
			self.run_no_gdb(cpu_affinity)
		} else {
			self.run_gdb(cpu_affinity)
		}
	}

	fn run_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		let cpu_id = 0;

		let local_cpu_affinity = cpu_affinity
			.as_ref()
			.and_then(|core_ids| core_ids.get(cpu_id as usize).copied());

		match local_cpu_affinity {
			Some(core_id) => {
				debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
				core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
			}
			None => debug!("No affinity specified, not binding thread"),
		}

		self.vcpus[0]
			.lock()
			.unwrap()
			.thread_local_init()
			.expect("Unable to initialize vCPU");

		let connection =
			wait_for_gdb_connection(self.kernel_info.params.gdb_port.unwrap()).unwrap();
		let debugger = GdbStub::new(connection);
		let mut debuggable_vcpu = GdbUhyve::new(self);

		let code = match debugger
			.run_blocking::<UhyveGdbEventLoop>(&mut debuggable_vcpu)
			.unwrap()
		{
			DisconnectReason::TargetExited(code) => code.into(),
			DisconnectReason::TargetTerminated(_) => unreachable!(),
			DisconnectReason::Disconnect => {
				eprintln!("Debugger disconnected.");
				0
			}
			DisconnectReason::Kill => {
				eprintln!("Kill command received.");
				0
			}
		};

		let output =
			if let Destination::Buffer(b) = &debuggable_vcpu.vm.peripherals.serial.destination {
				Some(String::from_utf8_lossy(&b.lock().unwrap()).into_owned())
			} else {
				None
			};

		VmResult {
			code,
			output,
			stats: None,
		}
	}
}

const LOCALHOST: [IpAddr; 2] = [
	IpAddr::V4(Ipv4Addr::LOCALHOST),
	IpAddr::V6(Ipv6Addr::LOCALHOST),
];

fn wait_for_gdb_connection(port: u16) -> io::Result<TcpStream> {
	let sock = TcpListener::bind(
		[
			SocketAddr::new(LOCALHOST[0], port),
			SocketAddr::new(LOCALHOST[1], port),
		]
		.as_ref(),
	)?;
	eprintln!(
		"Waiting for a local GDB connection on port {}...",
		sock.local_addr().unwrap().port()
	);
	let (stream, addr) = sock.accept()?;

	// Blocks until a GDB client connects via TCP.
	// i.e: Running `target remote localhost:<port>` from the GDB prompt.

	eprintln!("Debugger connected from {addr}");
	Ok(stream) // `TcpStream` implements `gdbstub::Connection`
}
