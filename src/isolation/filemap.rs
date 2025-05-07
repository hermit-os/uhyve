use std::{
	collections::{HashMap, HashSet},
	ffi::{CString, OsString},
	fs::canonicalize,
	os::{
		fd::{FromRawFd, RawFd},
		unix::ffi::OsStrExt,
	},
	path::PathBuf,
};

use bimap::BiHashMap;
use clean_path::clean;
use tempfile::TempDir;
use uuid::Uuid;

use crate::isolation::{split_guest_and_host_path, tempdir::create_temp_dir};

/// Wrapper around a `HashMap` to map guest paths to arbitrary host paths.
#[derive(Debug)]
pub struct UhyveFileMap {
	files: HashMap<String, OsString>,
	tempdir: TempDir,
	fdmap: BiHashMap<RawFd, String>,
	unlinkedfd: HashSet<RawFd>,
}

impl UhyveFileMap {
	/// Creates a UhyveFileMap.
	///
	/// * `mappings` - A list of host->guest path mappings with the format "./host_path.txt:guest.txt"
	/// * `tempdir` - Path to create temporary directory on
	pub fn new(mappings: &[String], tempdir: &Option<String>) -> UhyveFileMap {
		UhyveFileMap {
			files: mappings
				.iter()
				.map(String::as_str)
				.map(split_guest_and_host_path)
				.map(Result::unwrap)
				.collect(),
			tempdir: create_temp_dir(tempdir),
			fdmap: BiHashMap::new(),
			unlinkedfd: HashSet::new(),
		}
	}

	/// Returns the host_path on the host filesystem given a requested guest_path, if it exists.
	///
	/// * `guest_path` - The guest path that is to be looked up in the map.
	pub fn get_host_path(&mut self, guest_path: &str) -> Option<OsString> {
		// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
		// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
		let requested_guest_pathbuf = clean(guest_path);
		let host_path = self
			.files
			.get(&requested_guest_pathbuf.display().to_string())
			.map(OsString::from);
		debug!("get_host_path (host_path): {host_path:#?}");
		if host_path.is_some() {
			host_path
		} else {
			debug!("Guest requested to open a path that was not mapped.");
			if self.files.is_empty() {
				debug!("UhyveFileMap is empty, returning None...");
				return None;
			}

			if let Some(parent_of_guest_path) = requested_guest_pathbuf.parent() {
				debug!("The file is in a child directory, searching for a parent directory...");
				for searched_parent_guest in parent_of_guest_path.ancestors() {
					// If one of the guest paths' parent directories (parent_host) is mapped,
					// use the mapped host path and push the "remainder" (the path's components
					// that come after the mapped guest path) onto the host path.
					if let Some(parent_host) =
						self.files.get(searched_parent_guest.to_str().unwrap())
					{
						let mut host_path = PathBuf::from(parent_host);
						let guest_path_remainder = requested_guest_pathbuf
							.strip_prefix(searched_parent_guest)
							.unwrap();
						host_path.push(guest_path_remainder);

						// Handles symbolic links.
						return canonicalize(&host_path)
							.map_or(host_path.into_os_string(), PathBuf::into_os_string)
							.into();
					}
				}
			}
			debug!("The file is not in a child directory, returning None...");
			None
		}
	}

	/// Returns an array of all host paths (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_all_host_paths(&self) -> Vec<OsString> {
		self.files.clone().into_values().collect::<Vec<_>>()
	}

	/// Returns all present file descriptors (for Drop trait in UhyveVm)
	pub(crate) fn get_fds(&self) -> Vec<&i32> {
		self.fdmap
			.left_values()
			.into_iter()
			.chain(self.unlinkedfd.iter())
			.collect::<Vec<_>>()
	}

	/// Returns the path to the temporary directory (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_temp_dir(&self) -> Option<String> {
		self.tempdir.path().to_str().map(String::from)
	}

	/// Inserts an opened temporary file into the file map. Returns a CString so that
	/// the file can be directly used by [crate::hypercall::open].
	///
	/// * `guest_path` - The requested guest path.
	pub fn create_temporary_file(&mut self, guest_path: &str) -> CString {
		let host_path = self
			.tempdir
			.path()
			.join(Uuid::new_v4().to_string())
			.into_os_string();
		debug!("create_temporary_file (host_path): {host_path:#?}");
		let ret = CString::new(host_path.as_bytes()).unwrap();
		self.files.insert(String::from(guest_path), host_path);
		ret
	}

	/// Checks whether the fd is mapped to a guest path or belongs
	/// to an unlinked file.
	///
	/// * `fd` - The opened guest path's file descriptor.
	pub fn is_fd_closable(&mut self, fd: RawFd) -> bool {
		trace!("is_fd_closable: {:#?}", &self.fdmap);
		self.is_fd_present(fd) || self.unlinkedfd.contains(&fd)
	}

	/// Checks whether the fd is mapped to a guest path.
	///
	/// * `fd` - The opened guest path's file descriptor.
	pub fn is_fd_present(&mut self, fd: RawFd) -> bool {
		trace!("is_fd_present: {:#?}", &self.fdmap);
		// Although standard streams (0, 1, 2) are not "present", they should always be valid.
		// Therefore, we choose to "lie" to the guest OS instead. Other functions / hypercalls
		// will specifically handle those file descriptors on a case-by-case basis.
		if (fd >= 0 && self.fdmap.contains_left(&fd)) || (0..=2).contains(&fd) {
			return true;
		}
		false
	}

	/// Inserts a bidirectional file descriptor-path association.
	///
	/// * `fd` - The opened guest path's file descriptor.
	/// * `guest_path` - The guest path.
	pub fn insert_fd_path(&mut self, fd: RawFd, guest_path: &str) {
		// Don't insert standard streams (which "conflict" with Uhyve's).
		if fd > 2 {
			self.fdmap.insert(fd, guest_path.into());
		} else {
			warn!("Guest attempted to insert negative/standard stream {fd}, ignoring...")
		}
	}

	/// Removes an fd from UhyveFileMap. This is only used by [crate::hypercall::close],
	/// under the expectation that a new temporary file will be created if the guest
	/// attempts to open a file of the same path again.
	///
	/// * `fd` - The file descriptor of the file being removed.
	pub fn close_fd(&mut self, fd: RawFd) {
		trace!("close_fd: {:#?}", &self.fdmap);
		// The file descriptor in fdclosed is supposedly still alive.
		// It is safe to assume that the host OS will not assign the
		// same file descriptor to another opened file, until _after_
		// the file has been closed.
		if let Some(&fd) = self.unlinkedfd.get(&fd) {
			self.unlinkedfd.remove(&fd);
		} else {
			self.remove_fd(fd);
		}
	}

	/// Removes an fd from UhyveFileMap. This is only used by [crate::hypercall::close],
	/// under the expectation that a new temporary file will be created if the guest
	/// attempts to open a file of the same path again.
	///
	/// * `fd` - The file descriptor of the file being removed.
	pub fn remove_fd(&mut self, fd: RawFd) {
		trace!("remove_fd: {:#?}", &self.fdmap);
		// Don't close Uhyve's standard streams.
		if fd > 2 {
			self.fdmap.remove_by_left(&fd);
		} else {
			warn!("Guest attempted to remove negative/standard stream {fd}, ignoring...")
		}
	}

	/// Removes an entry (and its corresponding file descriptor) from UhyveFileMap.
	///
	/// Exclusively used by [crate::hypercall::unlink] for the event that
	/// a file, which is mapped, is removed together with its corresponding
	/// inode object. The intention is for Uhyve to create a new temporary
	/// file, should the guest OS request to access the same guest path after
	/// its corresponding host path has been unlinked. Otherwise, this would
	/// prompt security mechanisms like Landlock to kill Uhyve.
	///
	/// * `guest_path` - The path of the file being removed.
	pub fn unlink_guest_path(&mut self, guest_path: &str) {
		trace!("unlink_guest_path: {:#?}", &guest_path);
		if let Some(fd) = self.fdmap.get_by_right(guest_path) {
			self.unlinkedfd.insert(*fd);
			self.fdmap.remove_by_right(guest_path);
		}
		self.files.remove(guest_path);
	}
}

impl Drop for UhyveFileMap {
	fn drop(&mut self) {
		for fd in self.get_fds() {
			// This creates a File instance from a non-closed fd.
			// Rust "will then close" the file at the end of the unsafe block.
			unsafe { std::fs::File::from_raw_fd(*fd) };
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_uhyvefilemap() {
		// Our files are in `$CARGO_MANIFEST_DIR/data/fixtures/fs`.
		let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		fixture_path.push("tests/data/fixtures/fs");
		assert!(fixture_path.is_dir());
		let path_prefix = fixture_path.to_str().unwrap().to_owned();

		let map_results = [
			path_prefix.clone() + "/README.md",
			path_prefix.clone() + "/this_folder_exists",
			path_prefix.clone() + "/this_symlink_exists",
			path_prefix.clone() + "/this_symlink_is_dangling",
			path_prefix.clone() + "/this_file_does_not_exist",
			// Special case: the file's corresponding parameter uses a symlink,
			// which should be successfully resolved first.
			path_prefix.clone() + "/this_folder_exists/file_in_folder.txt",
		];

		let map_parameters = [
			map_results[0].clone() + ":readme_file.md",
			map_results[1].clone() + ":guest_folder",
			map_results[2].clone() + ":guest_symlink",
			map_results[3].clone() + ":guest_dangling_symlink",
			map_results[4].clone() + ":guest_file",
			path_prefix.clone() + "/this_symlink_leads_to_a_file" + ":guest_file_symlink",
		];

		let mut map = UhyveFileMap::new(&map_parameters, &None);

		assert_eq!(
			map.get_host_path("readme_file.md").unwrap(),
			OsString::from(&map_results[0])
		);
		assert_eq!(
			map.get_host_path("guest_folder").unwrap(),
			OsString::from(&map_results[1])
		);
		assert_eq!(
			map.get_host_path("guest_symlink").unwrap(),
			OsString::from(&map_results[2])
		);
		assert_eq!(
			map.get_host_path("guest_dangling_symlink").unwrap(),
			OsString::from(&map_results[3])
		);
		assert_eq!(
			map.get_host_path("guest_file").unwrap(),
			OsString::from(&map_results[4])
		);
		assert_eq!(
			map.get_host_path("guest_file_symlink").unwrap(),
			OsString::from(&map_results[5])
		);

		assert!(map.get_host_path("this_file_is_not_mapped").is_none());
	}

	#[test]
	fn test_uhyvefilemap_directory() {
		let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		fixture_path.push("tests/data/fixtures/fs");
		assert!(fixture_path.is_dir());

		// Tests successful directory traversal starting from file in child
		// directory of a mapped directory.
		let mut guest_path_map = PathBuf::from("this_folder_exists");
		let mut host_path_map = fixture_path.clone();
		host_path_map.push("this_folder_exists");

		let mut target_guest_path =
			PathBuf::from("this_folder_exists/folder_in_folder/file_in_second_folder.txt");
		let mut target_host_path = fixture_path.clone();
		target_host_path.push(target_guest_path.clone());

		let mut uhyvefilemap_params = [format!(
			"{}:{}",
			host_path_map.to_str().unwrap(),
			guest_path_map.to_str().unwrap()
		)];
		let mut map = UhyveFileMap::new(&uhyvefilemap_params, &None);

		let mut found_host_path = map.get_host_path(target_guest_path.clone().to_str().unwrap());

		assert_eq!(
			found_host_path.unwrap(),
			target_host_path.as_os_str().to_str().unwrap()
		);

		// Tests successful directory traversal of the child directory.
		// The pop() just removes the text file.
		// guest_path.pop();
		target_host_path.pop();
		target_guest_path.pop();

		found_host_path = map.get_host_path(target_guest_path.to_str().unwrap());
		assert_eq!(
			found_host_path.unwrap(),
			target_host_path.as_os_str().to_str().unwrap()
		);

		// Tests directory traversal leading to valid symbolic link with an
		// empty guest_path_map.
		host_path_map = fixture_path.clone();
		guest_path_map = PathBuf::from("/root");
		uhyvefilemap_params = [format!(
			"{}:{}",
			host_path_map.to_str().unwrap(),
			guest_path_map.to_str().unwrap()
		)];

		map = UhyveFileMap::new(&uhyvefilemap_params, &None);

		target_guest_path = PathBuf::from("/root/this_symlink_leads_to_a_file");
		target_host_path = fixture_path.clone();
		target_host_path.push("this_folder_exists/file_in_folder.txt");
		found_host_path = map.get_host_path(target_guest_path.to_str().unwrap());
		assert_eq!(
			found_host_path.unwrap(),
			target_host_path.as_os_str().to_str().unwrap()
		);

		// Tests directory traversal with no maps
		let empty_array: [String; 0] = [];
		map = UhyveFileMap::new(&empty_array, &None);
		found_host_path = map.get_host_path(target_guest_path.to_str().unwrap());
		assert!(found_host_path.is_none());
	}
}
