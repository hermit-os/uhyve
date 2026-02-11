use std::{
	ffi::{CStr, CString, OsString},
	os::unix::ffi::OsStrExt,
	path::PathBuf,
};

#[cfg(target_os = "linux")]
use libc::{O_DIRECT, O_SYNC};
use tempfile::TempDir;
use uuid::Uuid;

use crate::isolation::{
	fd::UhyveFileDescriptorLayer, split_guest_and_host_path, tempdir::create_temp_dir,
};

mod tests;
mod tree;

pub use tree::Leaf as UhyveMapLeaf;

/// Defines cache-related behaviors that will be forced upon [`crate::hypercall::open`],
/// primarily useful for e.g. I/O benchmarking.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct UhyveIoMode {
	/// Append the O_DIRECT flag to bypass the host's page cache.
	direct: bool,
	/// Append the O_DIRECT flag to bypass the host's page cache and block until writes are finished on the host.
	sync: bool,
}

#[cfg(target_os = "linux")]
impl From<Option<String>> for UhyveIoMode {
	fn from(s: Option<String>) -> Self {
		let (prefix, flags) = s
			.unwrap_or_default()
			.to_lowercase()
			.split_once("=")
			.map(|(prefix, flags)| (prefix.to_string(), flags.to_string()))
			.unwrap_or_default();
		let flags: Vec<_> = flags.split(',').collect();
		match prefix.as_str() {
			"host" => {
				let direct = flags.contains(&"direct");
				let sync = flags.contains(&"sync");
				UhyveIoMode { direct, sync }
			}
			"" => UhyveIoMode {
				direct: false,
				sync: false,
			},
			_ => unimplemented!(),
		}
	}
}

/// Wrapper around a `HashMap` to map guest paths to arbitrary host paths and track file descriptors.
#[derive(Debug)]
pub struct UhyveFileMap {
	root: tree::Directory,
	tempdir: TempDir,
	pub fdmap: UhyveFileDescriptorLayer,
	#[cfg(target_os = "linux")]
	iomode: UhyveIoMode,
}

impl UhyveFileMap {
	/// Creates a UhyveFileMap.
	///
	/// * `mappings` - A list of host->guest path mappings with the format "./host_path.txt:guest.txt"
	/// * `tempdir` - Path to create temporary directory on
	pub fn new(
		mappings: &[String],
		tempdir: Option<PathBuf>,
		#[cfg(target_os = "linux")] iomode: UhyveIoMode,
	) -> UhyveFileMap {
		let mut fm = UhyveFileMap {
			root: tree::Directory::new(),
			tempdir: create_temp_dir(tempdir),
			fdmap: UhyveFileDescriptorLayer::default(),
			#[cfg(target_os = "linux")]
			iomode,
		};
		for i in mappings {
			let (guest_path, host_path) = split_guest_and_host_path(i.as_str()).unwrap();
			if !tree::create_leaf(
				&mut fm.root,
				guest_path.as_os_str().as_bytes(),
				UhyveMapLeaf::OnHost(host_path),
			) {
				panic!(
					"Error when creating filemap @ guest_path = {guest_path:?}; Are duplicate paths present?"
				);
			}
		}
		fm
	}

	/// Returns the host_path on the host filesystem given a requested guest_path, if it exists.
	///
	/// * `guest_path` - The guest path that is to be looked up in the map.
	pub fn get_host_path(&self, guest_path: &CStr) -> Option<UhyveMapLeaf> {
		tree::resolve_guest_path(&self.root, guest_path.to_bytes())
	}

	/// Returns an array of all host paths (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_all_host_paths(&self) -> impl Iterator<Item = &std::ffi::OsStr> {
		tree::get_all_host_paths(&self.root).map(|i| i.as_os_str())
	}

	/// Returns an iterator (non-unique) over all mountable guest directories.
	pub(crate) fn get_all_guest_dirs(&self) -> impl Iterator<Item = String> {
		tree::get_all_guest_dirs(&self.root)
	}

	/// Get flags that should be appended to [`crate::hypercall::open`]
	/// as per the structure's defined I/O mode.
	#[inline]
	#[cfg(target_os = "linux")]
	pub(crate) fn get_io_mode_flags(&self) -> i32 {
		let mut flags: i32 = 0;
		if self.iomode.sync {
			flags |= O_SYNC;
		}
		if self.iomode.direct {
			flags |= O_DIRECT;
		}
		flags
	}

	/// Returns the path to the temporary directory (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_temp_dir(&self) -> &std::path::Path {
		self.tempdir.path()
	}

	/// Inserts a file into the file map.
	///
	/// Note that this is also used for the entire setup of the uhyve file tree,
	/// and this also called for the entire initial mapping.
	pub fn create_leaf(&mut self, guest_path: &CStr, leaf: UhyveMapLeaf) -> bool {
		tree::create_leaf(&mut self.root, guest_path.to_bytes(), leaf)
	}

	/// Inserts an opened temporary file into the file map. Returns a CString so that
	/// the file can be directly used by [crate::hypercall::open].
	///
	/// * `guest_path` - The requested guest path.
	pub fn create_temporary_file(&mut self, guest_path: &CStr) -> Option<CString> {
		let host_path = self.tempdir.path().join(Uuid::new_v4().to_string());
		trace!("create_temporary_file (host_path): {host_path:#?}");
		let ret = CString::new(host_path.as_os_str().as_bytes()).unwrap();
		if self.create_leaf(guest_path, UhyveMapLeaf::OnHost(host_path)) {
			Some(ret)
		} else {
			None
		}
	}

	/// Attempt to remove a file. Note that this will fail on non-empty directories.
	pub fn unlink(&mut self, guest_path: &CStr) -> Result<Option<OsString>, ()> {
		tree::unlink(&mut self.root, guest_path.to_bytes()).map(|i| i.map(|j| j.into_os_string()))
	}
}
