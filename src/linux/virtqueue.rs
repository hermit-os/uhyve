use std::{
	marker::PhantomData,
	mem,
	mem::size_of,
	sync::atomic::{AtomicPtr, Ordering},
};

use crate::consts::PAGE_SIZE;

pub const QUEUE_LIMIT: usize = 256;
pub const VIRTQ_DESC_F_AVAIL: u16 = 1 << 7;
pub const VIRTQ_DESC_F_USED: u16 = 1 << 15;

use virtio_bindings::bindings::virtio_ring::VRING_AVAIL_F_NO_INTERRUPT;
pub use virtio_bindings::bindings::virtio_ring::{
	VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
};

#[repr(C)]
#[derive(Debug)]
pub struct VringDescriptor {
	pub addr: u64,
	pub len: u32,
	pub flags: u16,
	pub next: u16,
}

impl VringDescriptor {
	pub fn is_writable(&self) -> bool {
		self.flags as u32 & VRING_DESC_F_WRITE != 0
	}

	pub fn is_readable(&self) -> bool {
		self.flags as u32 & VRING_DESC_F_WRITE == 0
	}
}

#[derive(Debug)]
pub struct Vring<T> {
	mem: AtomicPtr<u8>,
	_marker: PhantomData<AtomicPtr<T>>,
}

impl<T> Vring<T> {
	pub fn new(mem: *const u8) -> Self {
		Vring {
			mem: AtomicPtr::new(mem as *mut u8),
			_marker: PhantomData,
		}
	}

	pub fn flags(&self) -> u32 {
		unsafe { *(self.mem.load(Ordering::Acquire) as *const u32) }
	}

	//	TODO
	pub fn set_flag(&mut self, flag: u32) {
		unsafe { *(self.mem.load(Ordering::Acquire) as *mut u32) = flag }
	}

	//	TODO
	pub fn needs_notification(&self) -> bool {
		self.flags() != VRING_AVAIL_F_NO_INTERRUPT
	}

	// //	TODO
	// pub fn enable_notification(&mut self) {
	// 	self.set_flag(0)
	// }
	// //	TODO
	// pub fn disable_notification(&mut self) {
	// 	self.set_flag(VRING_AVAIL_F_NO_INTERRUPT)
	// }

	pub fn index(&self) -> u16 {
		unsafe { (self.mem.load(Ordering::Acquire).offset(2) as *const u16).read_volatile() }
	}

	pub fn advance_index(&mut self) {
		unsafe {
			let new_value = self.index() + 1;
			let write_ptr = self.mem.load(Ordering::Acquire).offset(2) as *mut u16;
			write_ptr.write_volatile(new_value);
		}
	}

	pub fn ring_elem(&mut self, index: u16) -> &mut T {
		let elem_size = mem::size_of::<T>() as u16;
		unsafe {
			&mut *(self
				.mem
				.load(Ordering::Acquire)
				.offset((4 + index * elem_size) as isize) as *mut T)
		}
	}
}

#[repr(C)]
#[derive(Debug)]
pub struct VringUsedElement {
	pub id: u32,
	pub len: u32,
}

pub type VringAvailable = Vring<u16>;
pub type VringUsed = Vring<VringUsedElement>;

#[derive(Debug)]
pub struct Virtqueue {
	pub descriptor_table: AtomicPtr<VringDescriptor>,
	pub available_ring: VringAvailable,
	pub used_ring: VringUsed,
	pub last_seen_available: u16,
	pub last_seen_used: u16,
	pub queue_size: u16,
}

pub struct AvailIter<'a> {
	available_ring: &'a VringAvailable,
	last_seen_available: &'a mut u16,
	queue_size: u16,
}

impl<'a> Iterator for AvailIter<'a> {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		if *self.last_seen_available == self.available_ring.index() {
			return None;
		}

		let index = *self.last_seen_available % self.queue_size;
		*self.last_seen_available += 1;
		Some(index)
	}
}

pub(crate) fn align(addr: usize, boundary: usize) -> usize {
	(addr + boundary - 1) & !(boundary - 1)
}

fn get_available_ring_offset() -> usize {
	size_of::<VringDescriptor>() * QUEUE_LIMIT
}

fn get_used_ring_offset() -> usize {
	align(
		get_available_ring_offset() + size_of::<u16>() * (QUEUE_LIMIT + 3),
		PAGE_SIZE,
	)
}

impl Virtqueue {
	pub unsafe fn new(mem: *mut u8, queue_size: usize) -> Self {
		#[allow(clippy::cast_ptr_alignment)]
		let descriptor_table = AtomicPtr::new(mem as *mut VringDescriptor); // mem as AtomicPtr<VringDescriptor>;
		let available_ring_ptr = mem.add(get_available_ring_offset());
		let used_ring_ptr = mem.add(get_used_ring_offset());
		let available_ring = VringAvailable::new(available_ring_ptr);
		let used_ring = VringUsed::new(used_ring_ptr);
		Virtqueue {
			descriptor_table,
			available_ring,
			used_ring,
			last_seen_available: 0,
			last_seen_used: 0,
			queue_size: queue_size as u16,
		}
	}

	/// Resets the Virtqueue with a dangling pointer.
	///
	/// SAFETY: this must be handled as if it was uninitialized, but so far it's
	/// being trusted!
	pub unsafe fn blank() -> Self {
		Self::new(std::ptr::NonNull::dangling().as_ptr(), 0)
	}

	pub unsafe fn get_descriptor(&mut self, index: u16) -> Option<&mut VringDescriptor> {
		let descriptor =
			&mut *(self.descriptor_table.load(Ordering::Acquire)).offset(index as isize);
		if descriptor.addr != 0 {
			return Some(descriptor);
		}
		None
	}

	pub fn avail_iter(&mut self) -> AvailIter<'_> {
		AvailIter {
			available_ring: &self.available_ring,
			last_seen_available: &mut self.last_seen_available,
			queue_size: self.queue_size,
		}
	}

	pub fn add_used(&mut self, desc_index: u32, len: u32) {
		let tgt_index = self.used_ring.index() % self.queue_size;
		let mut used_elem = self.used_ring.ring_elem(tgt_index);
		used_elem.id = desc_index;
		used_elem.len = len;
		self.used_ring.advance_index();
	}
}
