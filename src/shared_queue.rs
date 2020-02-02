use consts::*;
use std::sync::atomic::AtomicUsize;

#[repr(C)]
pub struct QueueInner {
	pub len: u16,
	pub data: [u8; UHYVE_NET_MTU],
}

#[repr(C)]
pub struct SharedQueue {
	pub read: AtomicUsize,
	pub written: AtomicUsize,
	pub inner: [QueueInner; UHYVE_QUEUE_SIZE],
}

impl SharedQueue {
	pub fn init(&mut self) {
		self.read = AtomicUsize::new(0);
		self.written = AtomicUsize::new(0);

		for i in self.inner.iter_mut() {
			i.len = 0;
		}
	}
}
