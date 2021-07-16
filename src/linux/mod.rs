pub mod uhyve;
pub mod vcpu;
pub mod virtio;
pub mod virtqueue;

pub type HypervisorError = kvm_ioctls::Error;

use std::{
	hint, mem,
	os::unix::prelude::JoinHandleExt,
	sync::{Arc, Barrier},
	thread,
};

use core_affinity::CoreId;
use kvm_ioctls::Kvm;
use lazy_static::lazy_static;
use libc::{SIGRTMAX, SIGRTMIN};
use nix::sys::{
	pthread::{pthread_kill, Pthread},
	signal::{signal, SigHandler, Signal},
};

use crate::{
	vm::{VirtualCPU, Vm},
	Uhyve,
};

lazy_static! {
	static ref KVM: Kvm = Kvm::new().unwrap();
}

trait MemoryRegion {
	fn flags(&self) -> u32;
	fn memory_size(&self) -> usize;
	fn guest_address(&self) -> usize;
	fn host_address(&self) -> usize;
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
}
