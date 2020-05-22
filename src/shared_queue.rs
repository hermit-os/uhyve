use crate::consts::*;

#[repr(C)]
pub struct QueueInner {
	pub len: u16,
	pub data: [u8; UHYVE_NET_MTU + 34],
}

#[repr(C)]
pub struct SharedQueue {
	pub read: usize,
	pad0: [u8; 64 - 8],
	pub written: usize,
	pad1: [u8; 64 - 8],
	pub inner: [QueueInner; UHYVE_QUEUE_SIZE],
}

impl SharedQueue {
	pub fn init(&mut self) {
		self.read = 0;
		self.written = 0;

		for i in self.inner.iter_mut() {
			i.len = 0;
		}
	}
}
