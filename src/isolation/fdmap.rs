use std::{
	collections::HashSet,
	os::fd::{FromRawFd, OwnedFd, RawFd},
};

use bimap::BiHashMap;

/// Container for file descriptors of open and unlinked files.
#[derive(Default, Debug)]
pub struct UhyveFileDescriptorMap {
	fd_path_map: BiHashMap<RawFd, String>,
	unlinked_fds: HashSet<RawFd>,
}

impl UhyveFileDescriptorMap {
	/// Returns all present file descriptors.
	pub(crate) fn get_fds(&self) -> Vec<&i32> {
		self.fd_path_map
			.left_values()
			.into_iter()
			.chain(self.unlinked_fds.iter())
			.collect::<Vec<_>>()
	}

	/// Inserts a bidirectional file descriptor-path association.
	///
	/// * `fd` - The opened guest path's file descriptor.
	/// * `guest_path` - The guest path.
	///
	/// TODO: Add the fd to a HashSet.
	pub fn insert_fd_path(&mut self, fd: RawFd, guest_path: &str) {
		// Don't insert standard streams (which "conflict" with Uhyve's).
		if fd > 2 {
			self.fd_path_map.insert(fd, guest_path.into());
		} else {
			warn!("Guest attempted to insert negative/standard stream {fd}, ignoring...")
		}
	}

	/// Removes an fd. Invoked by [crate::hypercall::close].
	///
	/// It is expected that a new temporary file will be created
	/// if the guest attempts to open a file of the same path again.
	///
	/// TODO: Do not remove the path, remove only an instance of an fd.
	///
	/// * `fd` - The file descriptor of the file being removed.
	pub fn remove_fd(&mut self, fd: RawFd) {
		trace!("remove_fd: {:#?}", &self.fd_path_map);
		// Don't close Uhyve's standard streams.
		if fd > 2 {
			self.fd_path_map.remove_by_left(&fd);
		} else {
			warn!("Guest attempted to remove negative/standard stream {fd}, ignoring...")
		}
	}

	/// Removes a guest path. Invoked by [crate::hypercall::unlink].
	///
	/// TODO: Move multiple fd instances to unlinked_fds iteratively.
	///
	/// * `guest_path` - Guest path of the file being removed.
	pub fn remove_path(&mut self, guest_path: &str) {
		trace!("remove_path: {:#?}", &guest_path);
		if let Some(fd) = self.fd_path_map.get_by_right(guest_path) {
			self.unlinked_fds.insert(*fd);
			self.fd_path_map.remove_by_right(guest_path);
		}
	}

	/// Checks whether the fd belongs to any guest path, or used to
    /// belong to a path, which had a path that has been unlinked.
	///
	/// * `fd` - File descriptor of to-be-closed file (open or unlinked).
	pub fn is_fd_closable(&mut self, fd: RawFd) -> bool {
		trace!("is_fd_closable: {:#?}", &self.fd_path_map);
		self.is_fd_present(fd) || self.unlinked_fds.contains(&fd)
	}

	/// Checks whether the fd is mapped to a guest path.
	///
	/// * `fd` - File descriptor of to-be-operated file.
	pub fn is_fd_present(&mut self, fd: RawFd) -> bool {
		trace!("is_fd_present: {:#?}", &self.fd_path_map);
		// Although standard streams (0, 1, 2) are not "present", they should always be valid.
		// Therefore, we choose to "lie" to the guest OS instead. Other functions / hypercalls
		// will specifically handle those file descriptors on a case-by-case basis.
		if (fd >= 0 && self.fd_path_map.contains_left(&fd)) || (0..=2).contains(&fd) {
			return true;
		}
		false
	}

	/// Removes a file descriptor.
	///
	/// Invoked in [crate::hypercall::close]. Note that this function
	/// does not attempt to modify the paths present in the "super-class"
	/// [crate::isolation::filemap::UhyveFileMap], see
	/// [crate::isolation::filemap::UhyveFileMap::unlink_guest_path].
    /// 
    /// TODO: Move all file descriptors of a path to unlinked_fds.
	///
	/// * `fd` - The file descriptor of the file being removed.
	pub fn close_fd(&mut self, fd: RawFd) {
		trace!("close_fd: {:#?}", &self.fd_path_map);
		// The file descriptor in fdclosed is supposedly still alive.
		// It is safe to assume that the host OS will not assign the
		// same file descriptor to another opened file, until _after_
		// the file has been closed.
		if let Some(&fd) = self.unlinked_fds.get(&fd) {
			self.unlinked_fds.remove(&fd);
		} else {
			self.remove_fd(fd);
		}
	}
}

impl Drop for UhyveFileDescriptorMap {
	fn drop(&mut self) {
		for fd in self.get_fds() {
			// This creates an OwnedFd instance, the RAII variant of RawFd.
			// We do this to close any files on the host that were not closed by the guest.
			unsafe { OwnedFd::from_raw_fd(*fd) };
		}
	}
}
