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
pub mod error;
pub mod gdb_parser;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod paging;
#[cfg(target_os = "linux")]
pub mod shared_queue;
pub mod utils;
pub mod vm;

pub use arch::*;
use core_affinity::CoreId;
use std::hint;
use std::sync::Arc;
use std::thread;
use std::path::PathBuf;
use vm::Vm;

/// Creates a uhyve vm and runs the binary given by `path` in it.
/// Blocks until the VM has finished execution.
pub fn uhyve_run(
	path: PathBuf,
	vm_params: &vm::Parameter<'_>,
	cpu_affinity: Option<Vec<core_affinity::CoreId>>,
) {
	// create and initialize the VM
	let vm = Arc::new({
		let mut vm = vm::create_vm(path, vm_params)
			.expect("Unable to create VM! Is the hypervisor interface (e.g. KVM) activated?");
		unsafe {
			vm.load_kernel().expect("Unabled to load the kernel");
		}
		vm
	});

	let num_cpus = vm.num_cpus();
	let threads: Vec<_> = (0..num_cpus)
		.map(|tid| {
			let vm = vm.clone();

			let local_cpu_affinity: Option<CoreId> = match &cpu_affinity {
				Some(vec) => vec.get(tid as usize).cloned(),
				None => None,
			};

			// create thread for each CPU
			thread::spawn(move || -> Option<i32> {
				debug!("Create thread for CPU {}", tid);
				match local_cpu_affinity {
					Some(core_id) => {
						debug!("Trying to pin thread {} to CPU {}", tid, core_id.id);
						core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
					}
					None => debug!("No affinity specified, not binding thread"),
				}

				let mut cpu = vm.create_cpu(tid).unwrap();
				cpu.init(vm.get_entry_point()).unwrap();

				// only one core is able to enter startup code
				// => the wait for the predecessor core
				while tid != vm.cpu_online() {
					hint::spin_loop();
				}

				// jump into the VM and execute code of the guest
				let result = cpu.run();
				match result {
					Err(x) => {
						error!("CPU {} crashes! {}", tid, x);
						None
					}
					Ok(exit_code) => {
						if let Some(code) = exit_code {
							std::process::exit(code);
						}

						None
					}
				}
			})
		})
		.collect();

	for t in threads {
		t.join().unwrap();
	}
}
