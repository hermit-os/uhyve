use std::{
	hint,
	sync::{mpsc, Arc},
	thread,
};

use core_affinity::CoreId;

use crate::{
	vm::{VirtualCPU, Vm},
	Uhyve,
};

mod ioapic;
pub mod uhyve;
pub mod vcpu;

pub type HypervisorError = xhypervisor::Error;
pub type DebugExitInfo = ();

impl Uhyve {
	/// Runs the VM.
	///
	/// Blocks until the VM has finished execution.
	pub fn run(mut self, cpu_affinity: Option<Vec<CoreId>>) -> i32 {
		unsafe {
			self.load_kernel().expect("Unabled to load the kernel");
		}

		// For communication of the exit code from one vcpu to this thread as return
		// value.
		let (exit_tx, exit_rx) = mpsc::channel();

		let this = Arc::new(self);

		(0..this.num_cpus()).for_each(|cpu_id| {
			let vm = this.clone();
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

				let mut cpu = vm.create_cpu(cpu_id).unwrap();
				cpu.init(vm.get_entry_point()).unwrap();

				// only one core is able to enter startup code
				// => the wait for the predecessor core
				while cpu_id != vm.cpu_online() {
					hint::spin_loop();
				}

				// jump into the VM and execute code of the guest
				let result = cpu.run();
				match result {
					Ok(Some(exit_code)) => exit_tx.send(exit_code).unwrap(),
					Ok(None) => {}
					Err(err) => error!("CPU {} crashed with {:?}", cpu_id, err),
				}
			});
		});

		// This is a semi-bad design. We don't wait for the other cpu's threads to
		// finish, but as soon as one cpu sends an exit code, we return it and
		// ignore the remaining running threads. A better design would be to force
		// the VCPUs externally to stop, so that the other threads don't block and
		// can be terminated correctly.
		exit_rx.recv().unwrap()
	}
}
