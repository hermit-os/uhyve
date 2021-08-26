#![warn(rust_2018_idioms)]
#![allow(unused_macros)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
mod macros;

#[macro_use]
extern crate log;

pub mod arch;
pub mod consts;
pub mod debug_manager;
pub mod gdb_parser;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as os;
pub mod paging;
#[cfg(target_os = "linux")]
pub mod shared_queue;
pub mod utils;
pub mod vm;

pub use arch::*;
pub use os::uhyve::Uhyve;

use core_affinity::CoreId;
use std::hint;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use vm::Vm;

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
					Err(x) => {
						error!("CPU {} crashes! {:?}", cpu_id, x);
					}
					Ok(exit_code) => {
						exit_tx.send(exit_code).unwrap();
					}
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
