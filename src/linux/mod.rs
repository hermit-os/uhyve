#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub mod gdb;

pub type HypervisorError = kvm_ioctls::Error;
pub type DebugExitInfo = kvm_bindings::kvm_debug_exit_arch;

use std::{
	io,
	net::{TcpListener, TcpStream},
	os::unix::prelude::JoinHandleExt,
	sync::{Arc, Barrier, LazyLock},
	thread,
};

use core_affinity::CoreId;
use gdbstub::stub::{DisconnectReason, GdbStub};
use kvm_ioctls::Kvm;
use libc::{SIGRTMAX, SIGRTMIN};
use nix::sys::{
	pthread::{pthread_kill, Pthread},
	signal::{signal, SigHandler, Signal},
};

use crate::{
	linux::{
		gdb::{GdbUhyve, UhyveGdbEventLoop},
		x86_64::kvm_cpu::KvmVm,
	},
	stats::{CpuStats, VmStats},
	vcpu::VirtualCPU,
	vm::{Output, UhyveVm, VirtualizationBackend, VmResult},
};

static KVM: LazyLock<Kvm> = LazyLock::new(|| Kvm::new().unwrap());

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
		unsafe { std::mem::transmute(kick_signal) }
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

impl UhyveVm<KvmVm> {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(mut self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		KickSignal::register_handler().unwrap();

		self.load_kernel().expect("Unabled to load the kernel");

		if self.gdb_port.is_none() {
			self.run_no_gdb(cpu_affinity)
		} else {
			self.run_gdb(cpu_affinity)
		}
	}

	fn run_no_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		// After spinning up all vCPU threads, the main thread waits for any vCPU to end execution.
		let barrier = Arc::new(Barrier::new(2));

		let this = Arc::new(self);
		let threads = (0..this.num_cpus())
			.map(|cpu_id| {
				let parent_vm = this.clone();
				let barrier = barrier.clone();
				let local_cpu_affinity = cpu_affinity
					.as_ref()
					.and_then(|core_ids| core_ids.get(cpu_id as usize).copied());

				let mut cpu = parent_vm
					.virt_backend
					.new_cpu(cpu_id, parent_vm.clone(), this.get_params().stats)
					.unwrap();

				thread::spawn(move || {
					debug!("Create thread for CPU {}", cpu_id);
					match local_cpu_affinity {
						Some(core_id) => {
							debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
							core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
						}
						None => debug!("No affinity specified, not binding thread"),
					}

					thread::sleep(std::time::Duration::from_millis(cpu_id as u64 * 50));

					// jump into the VM and execute code of the guest
					match cpu.run() {
						Ok((code, stats)) => {
							if code.is_some() {
								// Let the main thread continue with kicking the other vCPUs
								barrier.wait();
							}
							(code, stats)
						}
						Err(err) => {
							error!("CPU {} crashed with {:?}", cpu_id, err);
							barrier.wait();
							(Some(err.errno()), None)
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

		let cpu_results = threads
			.into_iter()
			.map(|thread| thread.join().unwrap())
			.collect::<Vec<_>>();
		let code = match cpu_results.iter().filter_map(|(ret, _stats)| *ret).count() {
			0 => panic!("No return code from any CPU? Maybe all have been kicked?"),
			1 => cpu_results[0].0.unwrap(),
			_ => panic!("more than one thread finished with an exit code (codes: {cpu_results:?})"),
		};

		let stats: Vec<CpuStats> = cpu_results
			.iter()
			.filter_map(|(_ret, stats)| stats.clone())
			.collect();
		let output = if let Output::Buffer(b) = &this.output {
			Some(b.lock().unwrap().clone())
		} else {
			None
		};

		VmResult {
			code,
			output,
			stats: Some(VmStats::new(&stats)),
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

		let this = Arc::new(self);
		let cpu = this
			.virt_backend
			// TODO: enable stats for gdb sessions as well
			.new_cpu(cpu_id, this.clone(), false)
			.unwrap();

		let connection = wait_for_gdb_connection(this.gdb_port.unwrap()).unwrap();
		let debugger = GdbStub::new(connection);
		let mut debuggable_vcpu = GdbUhyve::new(this.clone(), cpu);

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

		let output = if let Output::Buffer(b) = &this.output {
			Some(b.lock().unwrap().clone())
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

fn wait_for_gdb_connection(port: u16) -> io::Result<TcpStream> {
	let sockaddr = format!("localhost:{port}");
	eprintln!("Waiting for a GDB connection on {sockaddr:?}...");
	let sock = TcpListener::bind(sockaddr)?;
	let (stream, addr) = sock.accept()?;

	// Blocks until a GDB client connects via TCP.
	// i.e: Running `target remote localhost:<port>` from the GDB prompt.

	eprintln!("Debugger connected from {addr}");
	Ok(stream) // `TcpStream` implements `gdbstub::Connection`
}
