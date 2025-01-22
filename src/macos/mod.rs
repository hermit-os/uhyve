#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use std::{
	sync::{mpsc, Arc},
	thread,
};

use core_affinity::CoreId;

#[cfg(target_arch = "aarch64")]
pub use crate::macos::aarch64::vcpu::{XhyveCpu, XhyveVm};
#[cfg(target_arch = "x86_64")]
pub use crate::macos::x86_64::vcpu::{XhyveCpu, XhyveVm};
use crate::{
	stats::VmStats,
	vcpu::VirtualCPU,
	vm::{UhyveVm, VirtualizationBackend, VmResult},
};

pub type DebugExitInfo = ();

impl UhyveVm<XhyveVm> {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(mut self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult {
		self.load_kernel().expect("Unabled to load the kernel");

		// For communication of the exit code from one vcpu to this thread as return
		// value.
		let (exit_tx, exit_rx) = mpsc::channel();

		let enable_stats = self.get_params().stats;
		let this = Arc::new(self);

		(0..this.num_cpus()).for_each(|cpu_id| {
			let parent_vm = this.clone();
			let exit_tx = exit_tx.clone();

			let local_cpu_affinity = match &cpu_affinity {
				Some(vec) => vec.get(cpu_id as usize).cloned(),
				None => None,
			};

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

				let mut cpu = parent_vm
					.virt_backend
					.new_cpu(cpu_id, parent_vm.clone(), enable_stats)
					.unwrap();

				// jump into the VM and execute code of the guest
				let result = cpu.run();
				match result {
					Ok((Some(exit_code), stats)) => exit_tx.send((exit_code, stats)).unwrap(),
					Ok((None, _stats)) => {}
					Err(err) => error!("CPU {} crashed with {:?}", cpu_id, err),
				}
			});
		});

		// This is a semi-bad design. We don't wait for the other cpu's threads to
		// finish, but as soon as one cpu sends an exit code, we return it and
		// ignore the remaining running threads. A better design would be to force
		// the VCPUs externally to stop, so that the other threads don't block and
		// can be terminated correctly.
		// Also we only have stats for the exiting CPU.
		let (code, stats) = exit_rx.recv().unwrap();
		let stats = if enable_stats {
			Some(VmStats::new(&[stats.unwrap()]))
		} else {
			None
		};
		VmResult {
			code,
			output: None,
			stats,
		}
	}
}
