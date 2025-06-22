use std::{
	collections::HashSet,
	os::fd::{FromRawFd, OwnedFd, RawFd},
};

#[derive(Default, Debug)]
pub struct UhyveFileDescriptorLayer {
	fdset: HashSet<RawFd>,
}

impl UhyveFileDescriptorLayer {
	/// Returns all present file descriptors.
	pub(crate) fn get_fds(&self) -> Vec<&i32> {
		self.fdset.iter().collect::<Vec<_>>()
	}

	/// Inserts a file descriptor. Invoked by [crate::hypercall::open].
	///
	/// Only positive numbers (negative numbers are errors) above
	/// 2 (0, 1, 2 are standard streams) are accepted.
	///
	/// * `fd` - The opened guest path's file descriptor.
	pub fn insert_fd(&mut self, fd: RawFd) {
		// Don't insert standard streams (which "conflict" with Uhyve's).
		if fd > 2 {
			trace!("Adding fd {fd} to fdset...");
			self.fdset.insert(fd);
		} else {
			warn!("Guest attempted to insert negative/standard stream {fd}, ignoring...")
		}
	}

	/// Removes a file descriptor. Invoked by [crate::hypercall::close].
	///
	/// Only positive numbers (negative numbers are errors) above
	/// 2 (0, 1, 2 are standard streams) are accepted.
	///
	/// * `fd` - The file descriptor of the file being removed.
	pub fn remove_fd(&mut self, fd: RawFd) {
		trace!("remove_fd: {:#?}", &self.fdset);
		// This is checked by [crate::hypercall::close].
		if fd > 2 {
			self.fdset.remove(&fd);
		} else {
			warn!("Guest attempted to remove negative/standard stream {fd}, ignoring...")
		}
	}

	/// Checks whether an fd exists in this structure, i.e. whether the guest
	/// should be able to use the fd, as it has been previously opened by the
	/// guest (and not discarded). Standard streams (file descriptors 0, 1, 2)
	//// are always considered to be present and return `true`.
	///
	/// * `fd` - File descriptor of to-be-operated file.
	pub fn is_fd_present(&self, fd: RawFd) -> bool {
		trace!("is_fd_present: {:#?}", &self.fdset);
		if (fd >= 0 && self.fdset.contains(&fd)) || (0..=2).contains(&fd) {
			return true;
		}
		false
	}
}

impl Drop for UhyveFileDescriptorLayer {
	fn drop(&mut self) {
		for fd in self.get_fds() {
			// This creates an OwnedFd instance, the RAII variant of RawFd.
			// We do this to close any files on the host that were not closed by the guest.
			unsafe { OwnedFd::from_raw_fd(*fd) };
		}
	}
}
