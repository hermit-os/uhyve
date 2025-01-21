#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use std::{
	os::unix::prelude::JoinHandleExt,
	sync::{Arc, Barrier},
	thread,
};

use core_affinity::CoreId;
use nix::sys::{
	pthread::{pthread_kill, Pthread},
	signal::{signal, SigHandler, Signal, SIGUSR1},
};

#[cfg(target_arch = "aarch64")]
pub use crate::macos::aarch64::vcpu::{XhyveCpu, XhyveVm};
#[cfg(target_arch = "x86_64")]
pub use crate::macos::x86_64::vcpu::{XhyveCpu, XhyveVm};
use crate::{
	serial::Destination,
	stats::{CpuStats, VmStats},
	vcpu::VirtualCPU,
	vm::{UhyveVm, VmResult},
};

/// The signal for kicking vCPUs out of KVM_RUN.
///
/// It is used to stop a vCPU from another thread.
struct KickSignal;

impl KickSignal {
	fn get() -> Signal {
		SIGUSR1
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

pub type DebugExitInfo = ();

impl UhyveVm<XhyveVm> {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		KickSignal::register_handler().unwrap();

		let barrier = Arc::new(Barrier::new(2));

		debug!("Starting vCPUs");
		let threads = self
			.vcpus
			.into_iter()
			.enumerate()
			.map(|(cpu_id, mut cpu)| {
				let barrier = barrier.clone();
				let local_cpu_affinity = cpu_affinity
					.as_ref()
					.and_then(|core_ids| core_ids.get(cpu_id as usize).copied());

				// create thread for each CPU
				thread::spawn(move || {
					debug!("Create thread for CPU {}", cpu_id);
					match local_cpu_affinity {
						Some(core_id) => {
							debug!("Trying to pin thread {} to CPU {}", cpu_id, core_id.id);
							core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
						}
						None => debug!("No affinity specified, not binding thread"),
					}

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
							(Some(-1), None)
						}
					}
				})
			})
			.collect::<Vec<_>>();
		debug!("Waiting for first CPU to finish");

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
		let output = if let Destination::Buffer(b) = &self.peripherals.serial.destination {
			Some(String::from_utf8_lossy(&b.lock().unwrap()).into_owned())
		} else {
			None
		};

		VmResult {
			code,
			output,
			stats: Some(VmStats::new(&stats)),
		}
	}
}
