#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub(crate) mod gdb;

pub(crate) type DebugExitInfo = kvm_bindings::kvm_debug_exit_arch;

use std::{
	io,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
	sync::LazyLock,
};

use async_io::block_on;
use core_affinity::CoreId;
use gdbstub::{
	conn::ConnectionExt,
	stub::{DisconnectReason, GdbStub, SingleThreadStopReason, state_machine::GdbStubStateMachine},
};
use kvm_ioctls::Kvm;
use libc::{SIGRTMAX, SIGRTMIN};
use nix::sys::pthread::Pthread;

use crate::{
	linux::{gdb::GdbUhyve, x86_64::kvm_cpu::KvmVm},
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
		let connection =
			wait_for_gdb_connection(self.kernel_info.params.gdb_port.unwrap()).unwrap();
		let debugger = GdbStub::new(connection);
		// The Uhyve VCPU freewheel thread.
		let mut freewheel = GdbUhyve::new(self).spawn_freewheel(cpu_affinity);

		let mut gdb = debugger
			.run_state_machine(&mut freewheel)
			.expect("GDB run_state_machine initialization failed");

		use gdbstub::target::ext::base::multithread::MultiThreadBase;
		freewheel
			.list_active_threads(&mut |tid| trace!("Active thread: {tid:?}"))
			.expect("Expecting active thread");

		let code = loop {
			gdb = match gdb {
				GdbStubStateMachine::Idle(mut gdb) => {
					// needs more data, so perform a blocking read on the connection
					let byte = gdb.borrow_conn().read().expect("GDB connection read error");
					gdb.incoming_data(&mut freewheel, byte)
						.expect("GDB incoming_data error")
				}

				GdbStubStateMachine::Disconnected(gdb) => {
					// we keep things simple, and doesn't expose a way to re-use the
					// state machine
					break match gdb.get_reason() {
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
				}

				GdbStubStateMachine::CtrlCInterrupt(gdb) => {
					// defer to the implementation on how it wants to handle the interrupt

					//let stop_reason = Some(SingleThreadStopReason::Signal(Signal::SIGINT));

					// Kick VCPU out of KVM_RUN
					for i in &freewheel.vcpus {
						i.kick();
					}

					//let stop_reason = block_on(freewheel.stop_reasons.recv())
					//	.expect("unable to receive vCPU stop reason");

					gdb.interrupt_handled(&mut freewheel, None::<SingleThreadStopReason<u64>>)
						.expect("GDB interrupt_handled packet write failed")
				}

				GdbStubStateMachine::Running(mut gdb) => {
					use futures_lite::AsyncReadExt;
					// block waiting either for stop reason or new data from GDB
					enum UhyveOrGdb<X, Y> {
						Uhyve(X),
						Gdb(Y),
					}

					let borrow_conn = gdb.borrow_conn();
					let inp = block_on(futures_lite::future::or(
						async move {
							let mut gdb_conn_async = async_io::Async::new(borrow_conn)
								.expect("unable to asynchronize gdb connection");
							let mut data_from_gdb_buf = [0u8];
							let ret = gdb_conn_async
								.read_exact(&mut data_from_gdb_buf)
								.await
								.map(|_| data_from_gdb_buf[0]);
							let _ = gdb_conn_async.into_inner();
							UhyveOrGdb::Gdb(ret)
						},
						async { UhyveOrGdb::Uhyve(freewheel.stops.recv().await) },
					));

					match inp {
						UhyveOrGdb::Gdb(byte) => {
							let byte = byte.expect("error during GDB recv");
							gdb.incoming_data(&mut freewheel, byte)
								.expect("GDB incoming_data error")
						}
						UhyveOrGdb::Uhyve(stop_reason) => {
							let stop_reason = stop_reason.expect("error during stop packet recv");
							gdb.report_stop(&mut freewheel, stop_reason)
								.expect("GDB report_stop error")
						}
					}
				}
			}
		};

		for i in &freewheel.vcpus {
			i.kick();
		}

		let output = if let Destination::Buffer(b) = &freewheel.peripherals.serial.destination {
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
