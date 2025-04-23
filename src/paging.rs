//! General paging related code
use align_address::Align;
use thiserror::Error;
use uhyve_interface::GuestPhysAddr;

#[derive(Error, Debug)]
pub enum PagetableError {
	#[error("The accessed virtual address is not mapped")]
	InvalidAddress,
}

/// A simple bump allocator for initial boot paging frame allocations.
///
/// Only intended for the initial memory creation.
/// This can not cause UB in the host, but when the allocator is invoked with incorrect memory
/// bounds, the guest memory will (of course) likely be invalid.
pub(crate) struct BumpAllocator<const FRAMESIZE: u64> {
	start: GuestPhysAddr,
	length: u64,
	cnt: u64,
}
impl<const FRAMESIZE: u64> BumpAllocator<FRAMESIZE> {
	/// Create a new allocator at `start` with `length` *frames* as capacity
	///
	/// - `start` must be 4KiB aligned.
	/// - If `length` exceeds the intended memory region, this allocator will produce invalid
	///   allocations
	pub(crate) fn new(start: GuestPhysAddr, length: u64) -> Self {
		assert!(start.as_u64().is_aligned_to(FRAMESIZE));
		Self {
			start,
			length,
			cnt: 0,
		}
	}

	/// Allocate the next frame with this allocator.
	pub(crate) fn allocate(&mut self) -> Option<GuestPhysAddr> {
		if self.cnt < self.length {
			let f = self.start + self.cnt * FRAMESIZE;
			self.cnt += 1;
			Some(f)
		} else {
			None
		}
	}
}

#[cfg(test)]
mod tests {
	use uhyve_interface::GuestPhysAddr;

	use super::*;

	#[test]
	fn test_bump_frame_allocator() {
		let mut ba = BumpAllocator::<0x1000>::new(GuestPhysAddr::new(0x40_0000), 4);
		assert_eq!(ba.allocate(), Some(GuestPhysAddr::new(0x40_0000)));
		assert_eq!(ba.allocate(), Some(GuestPhysAddr::new(0x40_1000)));
		assert_eq!(ba.allocate(), Some(GuestPhysAddr::new(0x40_2000)));
		assert_eq!(ba.allocate(), Some(GuestPhysAddr::new(0x40_3000)));
		assert_eq!(ba.allocate(), None);
	}
}
