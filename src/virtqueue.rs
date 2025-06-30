#![cfg_attr(target_os = "macos", allow(dead_code))] // no virtio implementation for macos
use std::{marker::PhantomData, mem, mem::size_of};

use crate::consts::PAGE_SIZE;

pub const QUEUE_LIMIT: usize = 256;

#[repr(C)]
pub struct VringDescriptor {
	pub addr: u64,
	pub len: u32,
	pub flags: u16,
	pub next: u16,
}

pub struct Vring<T> {
	mem: *const u8,
	_marker: PhantomData<*const T>,
}

impl<T> Vring<T> {
	pub fn new(mem: *const u8) -> Self {
		Vring {
			mem,
			_marker: PhantomData,
		}
	}

	pub fn _flags(&self) -> u16 {
		unsafe {
			#[expect(clippy::cast_ptr_alignment)]
			*(self.mem as *const u16)
		}
	}

	pub fn index(&self) -> u16 {
		unsafe {
			#[expect(clippy::cast_ptr_alignment)]
			*(self.mem.offset(2) as *const u16)
		}
	}

	pub fn advance_index(&mut self) {
		unsafe {
			let new_value = self.index() + 1;
			#[expect(clippy::cast_ptr_alignment)]
			let write_ptr = self.mem.offset(2) as *mut u16;
			*write_ptr = new_value;
		}
	}

	pub fn ring_elem(&mut self, index: u16) -> &mut T {
		let elem_size = mem::size_of::<T>() as u16;
		unsafe { &mut *(self.mem.offset((4 + index * elem_size) as isize) as *mut T) }
	}
}

#[repr(C)]
pub struct VringUsedElement {
	pub id: u32,
	pub len: u32,
}

pub type VringAvailable = Vring<u16>;
pub type VringUsed = Vring<VringUsedElement>;

pub struct Virtqueue {
	pub descriptor_table: *mut VringDescriptor,
	pub available_ring: VringAvailable,
	pub used_ring: VringUsed,
	pub last_seen_available: u16,
	#[expect(dead_code)]
	pub last_seen_used: u16,
	pub queue_size: u16,
}

pub struct AvailIter<'a> {
	available_ring: &'a VringAvailable,
	last_seen_available: &'a mut u16,
	queue_size: u16,
}

impl Iterator for AvailIter<'_> {
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

fn align(addr: usize, boundary: usize) -> usize {
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
		#[expect(clippy::cast_ptr_alignment)]
		let descriptor_table = mem as *mut VringDescriptor;
		let available_ring_ptr = unsafe { mem.add(get_available_ring_offset()) };
		let used_ring_ptr = unsafe { mem.add(get_used_ring_offset()) };
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

	pub unsafe fn get_descriptor(&mut self, index: u16) -> &mut VringDescriptor {
		unsafe { &mut *self.descriptor_table.offset(index as isize) }
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
		let used_elem = self.used_ring.ring_elem(tgt_index);
		used_elem.id = desc_index;
		used_elem.len = len;
		self.used_ring.advance_index();
	}
}
