use std::{
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	thread::{self, Thread},
};

#[derive(Clone, Debug)]
pub struct Parker {
	thread: Thread,
	queued: Arc<AtomicBool>,
	flag: Arc<AtomicBool>,
}

impl Parker {
	pub fn current() -> Self {
		let thread = thread::current();
		let queued = Arc::new(AtomicBool::new(false));
		let flag = Arc::new(AtomicBool::new(false));
		Self {
			thread,
			queued,
			flag,
		}
	}

	pub fn park(&self) {
		// Signal that we are going to `park`. Between this store and our `park`, there may
		// be no other `park`, or else that `park` could consume our `unpark` token!
		self.queued.store(true, Ordering::Release);

		// We want to wait until the flag is set. We *could* just spin, but using
		// park/unpark is more efficient.
		while !self.flag.load(Ordering::Acquire) {
			// We can *not* use `println!` here since that could use thread parking internally.
			thread::park();
			// We *could* get here spuriously.
			// But that is no problem, we are in a loop until the flag is set anyway.
		}
	}

	fn try_unpark(&self) -> bool {
		// Ensure the thread is about to park.
		// This is crucial! It guarantees that the `unpark` below is not consumed
		// by some other code in the parked thread (e.g. inside `println!`).
		if !self.queued.load(Ordering::Acquire) {
			return false;
		}

		// Set the flag, and let the thread wake up.
		// There is no race condition here: if `unpark`
		// happens first, `park` will return immediately.
		// There is also no other `park` that could consume this token,
		// since we waited until the other thread got queued.
		// Hence there is no risk of a deadlock.
		self.flag.store(true, Ordering::Release);
		self.thread.unpark();
		true
	}

	pub fn unpark(&self) {
		while !self.try_unpark() {
			// Yielding is of course inefficient;
			// since we run this at the end of the vCPU thread, though,
			// we have nothing better to do.
			thread::yield_now();
		}
	}
}
