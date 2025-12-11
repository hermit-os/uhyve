use std::{
	collections::HashMap,
	ffi::{CStr, CString, OsStr, OsString},
	fs::{canonicalize, metadata},
	os::unix::ffi::OsStrExt,
	path::{Path, PathBuf},
};

use clean_path::clean;
#[cfg(target_os = "linux")]
use libc::{O_DIRECT, O_SYNC};
use tempfile::TempDir;
use uuid::Uuid;

use crate::isolation::{
	fd::UhyveFileDescriptorLayer, split_guest_and_host_path, tempdir::create_temp_dir,
};

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
	files: HashMap<PathBuf, PathBuf>,
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
		let fm = UhyveFileMap {
			files: mappings
				.iter()
				.map(String::as_str)
				.map(split_guest_and_host_path)
				.map(Result::unwrap)
				.collect(),
			tempdir: create_temp_dir(tempdir),
			fdmap: UhyveFileDescriptorLayer::default(),
			#[cfg(target_os = "linux")]
			iomode,
		};
		assert_eq!(
			fm.files.len(),
			mappings.len(),
			"Error when creating filemap. Are duplicate paths present?"
		);
		fm
	}

	/// Returns the host_path on the host filesystem given a requested guest_path, if it exists.
	///
	/// * `guest_path` - The guest path that is to be looked up in the map.
	pub fn get_host_path(&self, guest_path: &CStr) -> Option<OsString> {
		// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
		// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
		let guest_pathbuf = clean(OsStr::from_bytes(guest_path.to_bytes()));
		if let Some(host_path) = self.files.get(&guest_pathbuf) {
			let host_path = OsString::from(host_path);
			trace!("get_host_path (host_path): {host_path:#?}");
			Some(host_path)
		} else {
			debug!("Guest requested to open a path that was not mapped.");
			if self.files.is_empty() {
				debug!("UhyveFileMap is empty, returning None...");
				return None;
			}

			if let Some(parent_of_guest_path) = guest_pathbuf.parent() {
				debug!("The file is in a child directory, searching for a parent directory...");
				for searched_parent_guest in parent_of_guest_path.ancestors() {
					// If one of the guest paths' parent directories (parent_host) is mapped,
					// use the mapped host path and push the "remainder" (the path's components
					// that come after the mapped guest path) onto the host path.
					if let Some(parent_host) = self.files.get(searched_parent_guest) {
						let mut host_path = PathBuf::from(parent_host);
						let guest_path_remainder =
							guest_pathbuf.strip_prefix(searched_parent_guest).unwrap();
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
	pub(crate) fn get_all_host_paths(&self) -> impl Iterator<Item = &std::ffi::OsStr> {
		self.files.values().map(|i| i.as_os_str())
	}

	/// Returns an iterator (non-unique) over all mountable guest directories.
	pub(crate) fn get_all_guest_dirs(&self) -> impl Iterator<Item = &Path> {
		self.files.iter().filter_map(|(gp, hp)| {
			// We check the host_path filetype, and return the parent directory for everything non-file.
			if let Ok(hp_metadata) = metadata(hp) {
				if hp_metadata.is_dir() {
					Some(gp.as_path())
				} else if hp_metadata.is_file() {
					Some(gp.as_path().parent().unwrap())
				} else if hp_metadata.is_symlink() {
					error!(
						"{} is a symlink. This is not supported (yet?)",
						hp.display()
					);
					None
				} else {
					Some(gp.as_path().parent().unwrap())
				}
			} else if let Some(parent_path) = hp.parent()
				&& let Ok(parent_metadata) = metadata(parent_path)
				&& parent_metadata.is_dir()
			{
				// Parent directory exists, so this is a mounted file
				Some(gp.as_path().parent().unwrap())
			} else {
				error!("{} isn't a valid host path", hp.display());
				// return Err(ErrorKind::InvalidFilename);
				None
			}
		})
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
	pub(crate) fn get_temp_dir(&self) -> &Path {
		self.tempdir.path()
	}

	/// Inserts an opened temporary file into the file map. Returns a CString so that
	/// the file can be directly used by [crate::hypercall::open].
	///
	/// * `guest_path` - The requested guest path.
	pub fn create_temporary_file(&mut self, guest_path: &CStr) -> CString {
		let host_path = self.tempdir.path().join(Uuid::new_v4().to_string());
		trace!("create_temporary_file (host_path): {host_path:#?}");
		let ret = CString::new(host_path.as_os_str().as_bytes()).unwrap();
		self.files.insert(
			PathBuf::from(OsStr::from_bytes(guest_path.to_bytes())),
			host_path,
		);
		ret
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

		let map = UhyveFileMap::new(
			&map_parameters,
			None,
			#[cfg(target_os = "linux")]
			UhyveIoMode {
				direct: false,
				sync: false,
			},
		);

		assert_eq!(
			map.get_host_path(c"readme_file.md").unwrap(),
			OsString::from(&map_results[0])
		);
		assert_eq!(
			map.get_host_path(c"guest_folder").unwrap(),
			OsString::from(&map_results[1])
		);
		assert_eq!(
			map.get_host_path(c"guest_symlink").unwrap(),
			OsString::from(&map_results[2])
		);
		assert_eq!(
			map.get_host_path(c"guest_dangling_symlink").unwrap(),
			OsString::from(&map_results[3])
		);
		assert_eq!(
			map.get_host_path(c"guest_file").unwrap(),
			OsString::from(&map_results[4])
		);
		assert_eq!(
			map.get_host_path(c"guest_file_symlink").unwrap(),
			OsString::from(&map_results[5])
		);

		assert!(map.get_host_path(c"this_file_is_not_mapped").is_none());
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
		let mut map = UhyveFileMap::new(
			&uhyvefilemap_params,
			None,
			#[cfg(target_os = "linux")]
			UhyveIoMode {
				direct: false,
				sync: false,
			},
		);

		let mut found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);

		assert_eq!(
			found_host_path.unwrap(),
			target_host_path.as_os_str().to_str().unwrap()
		);

		// Tests successful directory traversal of the child directory.
		// The pop() just removes the text file.
		// guest_path.pop();
		target_host_path.pop();
		target_guest_path.pop();

		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
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

		map = UhyveFileMap::new(
			&uhyvefilemap_params,
			None,
			#[cfg(target_os = "linux")]
			UhyveIoMode {
				direct: false,
				sync: false,
			},
		);

		target_guest_path = PathBuf::from("/root/this_symlink_leads_to_a_file");
		target_host_path = fixture_path.clone();
		target_host_path.push("this_folder_exists/file_in_folder.txt");
		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert_eq!(
			found_host_path.unwrap(),
			target_host_path.as_os_str().to_str().unwrap()
		);

		// Tests directory traversal with no maps
		let empty_array: [String; 0] = [];
		map = UhyveFileMap::new(
			&empty_array,
			None,
			#[cfg(target_os = "linux")]
			UhyveIoMode {
				direct: false,
				sync: false,
			},
		);
		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert!(found_host_path.is_none());
	}

	#[test]
	#[cfg(target_os = "linux")]
	fn test_uhyveiomode_input() {
		let io_mode_str = |x: &str| UhyveIoMode::from(Some(String::from(x)));
		assert_eq!(
			io_mode_str(""),
			UhyveIoMode {
				direct: false,
				sync: false
			}
		);
		assert_eq!(
			io_mode_str("host=direct"),
			UhyveIoMode {
				direct: true,
				sync: false
			}
		);
		assert_eq!(
			io_mode_str("host=direct"),
			UhyveIoMode {
				direct: true,
				sync: false
			}
		);
		assert_eq!(
			io_mode_str("host=direct"),
			UhyveIoMode {
				direct: true,
				sync: false
			}
		);
		assert_eq!(
			io_mode_str("host=direct,sync"),
			UhyveIoMode {
				direct: true,
				sync: true
			}
		);
		assert_eq!(
			io_mode_str("host=sync,direct"),
			UhyveIoMode {
				direct: true,
				sync: true
			}
		);
	}
}
