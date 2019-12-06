use std::mem;
use std::mem::size_of;
use std::marker::PhantomData;
use std::slice;
use consts::PAGE_SIZE;

const QUEUE_LIMIT: usize = 256;

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

    pub fn flags(&self) -> u16 {
        unsafe { *(self.mem as *const u16) }
    }

    pub fn index(&self) -> u16 {
        unsafe { *(self.mem.offset(2) as *const u16) }
    }

    pub fn advance_index(&mut self) {
        unsafe {
            let new_value = self.index() + 1;
            let write_ptr = self.mem.offset(2) as *mut u16;
            *write_ptr = new_value;
        }
    }

    pub fn ring_elem(&self, index: u16) -> &mut T {
        let elem_size = mem::size_of::<T>() as u16;
        unsafe { &mut *(self.mem.offset((4 + index * elem_size) as isize) as *mut T) }
    }
}

#[repr(C)]
pub struct VringUsedElement {
    pub id: u16,
    pub len: u16,
}

pub type VringAvailable = Vring<u16>;
pub type VringUsed = Vring<VringUsedElement>;

pub struct Virtqueue<'a> {
    pub descriptor_table: &'a[VringDescriptor],
    pub available_ring: VringAvailable,
    pub used_ring: VringUsed,
    pub last_seen_available: u16,
    pub last_seen_used: u16,
    pub queue_size: u16,
}

pub struct AvailIter<'a> {
    descriptor_table: &'a[VringDescriptor],
    available_ring: &'a VringAvailable,
    last_seen_available: &'a mut u16,
    queue_size: u16,
}

impl<'a> Iterator for AvailIter<'a> {
    type Item = &'a VringDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if *self.last_seen_available == self.available_ring.index() {
            return None
        }

        let index = (*self.last_seen_available % self.queue_size) as usize;
        let result = &self.descriptor_table[index];
        *self.last_seen_available += 1;
        Some(result)
    }
}

fn align(addr: usize, boundary: usize) -> usize {
    (addr + boundary - 1) & !(boundary - 1)
}

fn get_available_ring_offset() -> usize {
    size_of::<VringDescriptor>() * QUEUE_LIMIT
}

fn get_used_ring_offset() -> usize {
    align(get_available_ring_offset() + size_of::<u16>() * (QUEUE_LIMIT + 3), PAGE_SIZE)
}

impl Virtqueue<'_> {
    pub fn new(mem: *mut u8, queue_size: usize) -> Self {
        unsafe {
            let descriptor_table = slice::from_raw_parts(mem as *mut VringDescriptor, queue_size);
            let available_ring_ptr = mem.offset(get_available_ring_offset() as isize);
            let used_ring_ptr = mem.offset(get_used_ring_offset() as isize);
            let available_ring = VringAvailable::new(available_ring_ptr);
            let used_ring = VringUsed::new(used_ring_ptr);
            Virtqueue {
                descriptor_table,
                available_ring,
                used_ring,
                last_seen_available: 0,
                last_seen_used: 0,
                queue_size: queue_size as u16
            }
        }
    }

    pub fn avail_iter(&mut self) -> AvailIter {
        AvailIter {
            descriptor_table: self.descriptor_table,
            available_ring: &self.available_ring,
            last_seen_available: &mut self.last_seen_available,
            queue_size: self.queue_size
        }
    }

    pub fn add_used(&mut self, desc_index: u16, len: u16) {
        let tgt_index = self.used_ring.index() % self.queue_size;
        let mut used_elem = self.used_ring.ring_elem(tgt_index);
        used_elem.id = desc_index;
        used_elem.len = len;
        self.used_ring.advance_index();
    }
}
