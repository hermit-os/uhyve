pub mod gdb;
pub mod uhyve;
pub mod vcpu;
pub mod virtio;
pub mod virtqueue;

pub type HypervisorError = kvm_ioctls::Error;
pub type DebugExitInfo = kvm_bindings::kvm_debug_exit_arch;

use std::{
	hint,
	io::{self, Read},
	mem,
	net::{TcpListener, TcpStream},
	os::unix::prelude::JoinHandleExt,
	sync::{Arc, Barrier},
	thread,
	time::Duration,
};

use core_affinity::CoreId;
use gdbstub::{
	state_machine::Event,
	target::{ext::base::multithread::ThreadStopReason, Target},
	ConnectionExt, DisconnectReason, GdbStub, GdbStubStateMachine,
};
use kvm_ioctls::Kvm;
use lazy_static::lazy_static;
use libc::{SIGRTMAX, SIGRTMIN};
use nix::sys::{
	pthread::{pthread_kill, pthread_self, Pthread},
	signal::{signal, SigHandler, Signal},
};

use crate::{
	linux::gdb::GdbUhyve,
	vm::{VirtualCPU, Vm},
	Uhyve,
};

lazy_static! {
	static ref KVM: Kvm = Kvm::new().unwrap();
}

/// The signal for kicking vCPUs out of KVM_RUN.
///
/// It is used to stop a vCPU from another thread.
struct KickSignal;

impl KickSignal {
	const RTSIG_OFFSET: libc::c_int = 0;

	fn get() -> Signal {
		let kick_signal = SIGRTMIN() + Self::RTSIG_OFFSET;
		assert!(kick_signal <= SIGRTMAX());
		// TODO: Remove the transmute once realtime signals are properly supported by nix
		// https://github.com/nix-rust/nix/issues/495
		unsafe { mem::transmute(kick_signal) }
	}

	fn register_handler() -> nix::Result<()> {
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
	fn pthread_kill(pthread: Pthread) -> nix::Result<()> {
		pthread_kill(pthread, Self::get())
	}
}

impl Uhyve {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(mut self, cpu_affinity: Option<Vec<CoreId>>) -> i32 {
		KickSignal::register_handler().unwrap();

		unsafe {
			self.load_kernel().expect("Unabled to load the kernel");
		}

		if self.gdb_port.is_none() {
			self.run_no_gdb(cpu_affinity)
		} else {
			self.run_gdb(cpu_affinity)
		}
	}

	fn run_no_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> i32 {
		// After spinning up all vCPU threads, the main thread waits for any vCPU to end execution.
		let barrier = Arc::new(Barrier::new(2));

		let this = Arc::new(self);
		let threads = (0..this.num_cpus())
			.map(|cpu_id| {
				let vm = this.clone();
				let barrier = barrier.clone();
				let local_cpu_affinity = cpu_affinity
					.as_ref()
					.map(|core_ids| core_ids.get(cpu_id as usize).copied())
					.flatten();

				thread::spawn(move || {
					debug!("Create thread for CPU {}", cpu_id);
					match local_cpu_affinity {
						Some(core_id) => {
							debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
							core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
						}
						None => debug!("No affinity specified, not binding thread"),
					}

					let mut cpu = vm.create_cpu(cpu_id).unwrap();
					cpu.init(vm.get_entry_point()).unwrap();

					// only one core is able to enter startup code
					// => the wait for the predecessor core
					while cpu_id != vm.cpu_online() {
						hint::spin_loop();
					}

					// jump into the VM and execute code of the guest
					match cpu.run() {
						Ok(code) => {
							if code.is_some() {
								// Let the main thread continue with kicking the other vCPUs
								barrier.wait();
							}
							code
						}
						Err(err) => {
							error!("CPU {} crashed with {:?}", cpu_id, err);
							None
						}
					}
				})
			})
			.collect::<Vec<_>>();

		// Wait for one vCPU to return with an exit code.
		barrier.wait();
		for thread in &threads {
			KickSignal::pthread_kill(thread.as_pthread_t()).unwrap();
		}

		let code = threads
			.into_iter()
			.filter_map(|thread| thread.join().unwrap())
			.collect::<Vec<_>>();
		assert_eq!(
			1,
			code.len(),
			"more than one thread finished with an exit code"
		);
		code[0]
	}

	fn run_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> i32 {
		let cpu_id = 0;

		let local_cpu_affinity = cpu_affinity
			.as_ref()
			.map(|core_ids| core_ids.get(cpu_id as usize).copied())
			.flatten();

		match local_cpu_affinity {
			Some(core_id) => {
				debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
				core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
			}
			None => debug!("No affinity specified, not binding thread"),
		}

		let mut cpu = self.create_cpu(cpu_id).unwrap();
		cpu.init(self.get_entry_point()).unwrap();

		let connection = wait_for_gdb_connection(self.gdb_port.unwrap()).unwrap();

		let debugger = gdbstub::GdbStub::new(connection.try_clone().unwrap());
		let mut debuggable_vcpu = GdbUhyve::new(self, cpu);

		match run_debugger(&mut debuggable_vcpu, debugger, connection).unwrap() {
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
		}
	}
}

fn run_debugger<T: Target, C: ConnectionExt>(
	target: &mut T,
	gdb: GdbStub<'_, T, C>,
	mut tcp_stream: TcpStream,
) -> Result<DisconnectReason, gdbstub::GdbStubError<T::Error, C::Error>> {
	let parent_thread = pthread_self();
	thread::spawn(move || {
		loop {
			// Block on TCP stream without consuming any data.
			Read::read(&mut tcp_stream, &mut []).unwrap();

			// Kick VCPU out of KVM_RUN
			KickSignal::pthread_kill(parent_thread).unwrap();

			// Wait for all inputs to be processed and for VCPU to be running again
			thread::sleep(Duration::from_millis(20));
		}
	});

	let mut gdb = gdb.run_state_machine()?;
	loop {
		gdb = match gdb {
			GdbStubStateMachine::Pump(mut gdb) => {
				let byte = gdb
					.borrow_conn()
					.read()
					.map_err(gdbstub::GdbStubError::ConnectionRead)?;

				let (gdb, disconnect_reason) = gdb.pump(target, byte)?;
				if let Some(disconnect_reason) = disconnect_reason {
					break Ok(disconnect_reason);
				}
				gdb
			}
			GdbStubStateMachine::DeferredStopReason(mut gdb) => {
				let byte = gdb
					.borrow_conn()
					.read()
					.map_err(gdbstub::GdbStubError::ConnectionRead)?;

				let (gdb, event) = gdb.pump(target, byte)?;
				match event {
					Event::None => gdb,
					Event::Disconnect(disconnect_reason) => break Ok(disconnect_reason),
					Event::CtrlCInterrupt => {
						// when an interrupt is received, report the `GdbInterrupt` stop reason.
						if let GdbStubStateMachine::DeferredStopReason(gdb) = gdb {
							match gdb
								.deferred_stop_reason(target, ThreadStopReason::GdbInterrupt)?
							{
								(_, Some(disconnect_reason)) => break Ok(disconnect_reason),
								(gdb, None) => gdb,
							}
						} else {
							gdb
						}
					}
				}
			}
		}
	}
}

fn wait_for_gdb_connection(port: u16) -> io::Result<TcpStream> {
	let sockaddr = format!("localhost:{}", port);
	eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);
	let sock = TcpListener::bind(sockaddr)?;
	let (stream, addr) = sock.accept()?;

	// Blocks until a GDB client connects via TCP.
	// i.e: Running `target remote localhost:<port>` from the GDB prompt.

	eprintln!("Debugger connected from {}", addr);
	Ok(stream) // `TcpStream` implements `gdbstub::Connection`
}
