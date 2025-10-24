use std::{
	fmt,
	os::fd::{FromRawFd, OwnedFd, RawFd},
};

use slab::Slab;
use yoke::{Yoke, erased::ErasedArcCart};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestFd(pub i32);

impl fmt::Display for GuestFd {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "GuestFd({})", self.0)
	}
}

impl From<usize> for GuestFd {
	fn from(x: usize) -> Self {
		// The following should never panic unless someone allocates more than i32::MAX file descriptors
		Self(x.try_into().unwrap())
	}
}

impl GuestFd {
	fn is_standard(self) -> bool {
		self.0 < 3
	}

	fn get(self) -> usize {
		self.0.try_into().unwrap()
	}
}

/// Description of what this guest file descriptor wraps:
#[derive(Clone)]
pub enum FdData {
	/// A host file descriptor
	Raw(RawFd),

	#[allow(dead_code)]
	/// An in-memory slice (possibly mmap-ed)
	///
	/// SAFETY: It is not allowed for `data` to point into guest memory.
	Virtual {
		data: Yoke<&'static [u8], ErasedArcCart>,
		offset: u64,
	},
}

impl fmt::Debug for FdData {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			FdData::Raw(r) => write!(f, "Raw({})", r),
			FdData::Virtual { data, offset } => {
				let data = data.get();
				let data_snip = &data[..core::cmp::min(10, data.len())];
				write!(f, "Virtual({:?} @ {})", data_snip, offset)
			}
		}
	}
}

impl FromRawFd for FdData {
	#[inline(always)]
	unsafe fn from_raw_fd(fd: RawFd) -> Self {
		Self::Raw(fd)
	}
}

#[derive(Debug)]
pub struct UhyveFileDescriptorLayer {
	fds: Slab<FdData>,
}

impl Default for UhyveFileDescriptorLayer {
	fn default() -> Self {
		let mut fds = Slab::new();
		// fill the first 3 fds (0, 1, 2) = the standard streams to avoid weird effects
		fds.insert(FdData::Raw(0));
		fds.insert(FdData::Raw(1));
		fds.insert(FdData::Raw(2));
		Self { fds }
	}
}

impl UhyveFileDescriptorLayer {
	/// Inserts a file descriptor. Invoked by [crate::hypercall::open].
	///
	/// Only positive numbers (negative numbers are errors) above
	/// 2 (0, 1, 2 are standard streams) are accepted.
	pub fn insert(&mut self, data: FdData) -> Option<GuestFd> {
		// Don't insert standard streams (which "conflict" with Uhyve's).
		if let FdData::Raw(r) = data
			&& r < 3
		{
			warn!("Guest attempted to insert negative/standard stream {r}, ignoring...");
			return None;
		}

		debug!("Adding fd {data:?} to fdset: {self}");
		let ret = self.fds.insert(data).into();
		debug!("=> {}", ret);
		Some(ret)
	}

	/// Removes a file descriptor. Invoked by [crate::hypercall::close].
	///
	/// Only positive numbers (negative numbers are errors) above
	/// 2 (0, 1, 2 are standard streams) are accepted.
	///
	/// * `fd` - The file descriptor of the file being removed.
	pub fn remove(&mut self, fd: GuestFd) -> Option<FdData> {
		debug!("Trying to remove {fd} from fdset: {self}");
		// This is checked by [crate::hypercall::close].
		let ret = if fd.is_standard() {
			None
		} else {
			self.fds.try_remove(fd.get())
		};
		if ret.is_none() {
			warn!("Guest attempted to remove invalid {fd}, ignoring...")
		}
		ret
	}

	pub fn get_mut(&mut self, fd: GuestFd) -> Option<&mut FdData> {
		self.fds.get_mut(fd.get())
	}

	/// Checks whether an fd exists in this structure, i.e. whether the guest
	/// should be able to use the fd, as it has been previously opened by the
	/// guest (and not discarded). Standard streams (file descriptors 0, 1, 2)
	//// are always considered to be present and return `true`.
	///
	/// * `fd` - File descriptor of to-be-operated file.
	pub fn is_fd_present(&self, fd: GuestFd) -> bool {
		debug!("Check if {fd} in fdset: {self}");
		self.fds.contains(fd.get())
	}
}

impl Drop for UhyveFileDescriptorLayer {
	fn drop(&mut self) {
		for (fd, fdata) in self.fds.iter() {
			if !GuestFd::from(fd).is_standard()
				&& let FdData::Raw(rfd) = fdata
			{
				// This creates an OwnedFd instance, the RAII variant of RawFd.
				// We do this to close any files on the host that were not closed by the guest.
				unsafe { OwnedFd::from_raw_fd(*rfd) };
			}
		}
	}
}

impl fmt::Display for UhyveFileDescriptorLayer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_map().entries(self.fds.iter()).finish()
	}
}
