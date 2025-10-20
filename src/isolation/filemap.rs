use std::{
	collections::HashMap,
	ffi::{CStr, CString, OsStr},
	fs::metadata,
	os::unix::ffi::OsStrExt,
	path::{Path, PathBuf},
};

use clean_path::clean;
use tempfile::TempDir;
use uuid::Uuid;

use crate::isolation::{
	fd::UhyveFileDescriptorLayer,
	image::{Cache, MappedFile},
	split_guest_and_host_path,
	tempdir::create_temp_dir,
};

/// Wrapper around a `HashMap` to map guest paths to arbitrary host paths and track file descriptors.
#[derive(Debug)]
pub struct UhyveFileMap {
	files: HashMap<PathBuf, MappedFile>,
	tempdir: TempDir,
	pub fdmap: UhyveFileDescriptorLayer,
}

impl UhyveFileMap {
	/// Creates a UhyveFileMap.
	///
	/// * `mappings` - A list of host->guest path mappings with the format
	///   "./host_path.txt:guest.txt" or "./hermit_image.hermit:contained.txt:guest.txt"
	/// * `tempdir` - Path to create temporary directory on
	pub fn new(
		mappings: &[String],
		tempdir: Option<PathBuf>,
		hermit_image_cache: &mut Cache,
	) -> Self {
		let tempdir = create_temp_dir(tempdir);
		let mut files = HashMap::new();

		for i in mappings {
			let (guest_path, maybe_in_image_str, host_path) = split_guest_and_host_path(i).unwrap();
			if let Some(mut x) = maybe_in_image_str {
				let image = hermit_image_cache.register(&host_path);
				if x == "." || x == "/" {
					x = "".to_string();
				}

				// resolve file
				if let Ok(resolved) = image.try_map_project_cloned(|yoked, _| {
					let ret: Result<hermit_entry::ThinTree<'_>, ()> =
						yoked.resolve((&*x).into()).ok_or(()).cloned();
					ret
				}) {
					files.insert(guest_path, MappedFile::InImage(resolved));
				} else {
					warn!(
						"In hermit image {}: unable to find file {:?} -> {}",
						host_path.display(),
						x,
						guest_path.display()
					);
				}
			} else {
				files.insert(guest_path, MappedFile::OnHost(host_path));
			}
		}

		assert_eq!(
			files.len(),
			mappings.len(),
			"Error when creating filemap. Are duplicate paths present?"
		);

		Self {
			files,
			tempdir,
			fdmap: UhyveFileDescriptorLayer::default(),
		}
	}

	/// Returns the host_path on the host filesystem given a requested guest_path, if it exists.
	///
	/// * `guest_path` - The guest path that is to be looked up in the map.
	pub fn get_host_path(&self, guest_path: &CStr) -> Option<MappedFile> {
		if self.files.is_empty() {
			debug!("UhyveFileMap is empty, returning None...");
			return None;
		}

		// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
		// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
		let guest_pathbuf = clean(OsStr::from_bytes(guest_path.to_bytes()));

		for searched_parent_guest in guest_pathbuf.ancestors() {
			// If one of the guest paths' parent directories (parent_host) is mapped,
			// use the mapped host path and push the "remainder" (the path's components
			// that come after the mapped guest path) onto the host path.
			if let Some(parent_host) = self.files.get(searched_parent_guest) {
				let guest_path_remainder =
					guest_pathbuf.strip_prefix(searched_parent_guest).unwrap();
				return parent_host.resolve(guest_path_remainder);
			}
		}
		debug!("The file is not in a child directory, returning None...");
		None
	}

	/// Returns an array of all host paths (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_all_host_paths(&self) -> impl Iterator<Item = &std::ffi::OsStr> {
		self.files.values().filter_map(|i| match i {
			MappedFile::OnHost(f) => Some(f.as_os_str()),
			_ => None,
		})
	}

	/// Returns an iterator (non-unique) over all mountable guest directories.
	pub(crate) fn get_all_guest_dirs(&self) -> impl Iterator<Item = &Path> {
		self.files.iter().filter_map(|(gp, hp)| {
			match hp {
				MappedFile::OnHost(hp) => {
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
				}
				MappedFile::InImage(ii) => Some(match ii.get() {
					hermit_entry::ThinTree::Directory(_) => gp.as_path(),
					_ => gp.as_path().parent().unwrap(),
				}),
			}
		})
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
			MappedFile::OnHost(host_path),
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

		let map = UhyveFileMap::new(&map_parameters, None, &mut Cache::default());

		assert_eq!(
			map.get_host_path(c"readme_file.md")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[0])
		);
		assert_eq!(
			map.get_host_path(c"guest_folder").unwrap().unwrap_on_host(),
			PathBuf::from(&map_results[1])
		);
		assert_eq!(
			map.get_host_path(c"guest_symlink")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[2])
		);
		assert_eq!(
			map.get_host_path(c"guest_dangling_symlink")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[3])
		);
		assert_eq!(
			map.get_host_path(c"guest_file").unwrap().unwrap_on_host(),
			PathBuf::from(&map_results[4])
		);
		assert_eq!(
			map.get_host_path(c"guest_file_symlink")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[5])
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
		let mut map = UhyveFileMap::new(&uhyvefilemap_params, None, &mut Cache::default());

		let mut found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);

		assert_eq!(
			found_host_path.unwrap().unwrap_on_host(),
			target_host_path.as_os_str()
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
			found_host_path.unwrap().unwrap_on_host(),
			target_host_path.as_os_str()
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

		map = UhyveFileMap::new(&uhyvefilemap_params, None, &mut Cache::default());

		target_guest_path = PathBuf::from("/root/this_symlink_leads_to_a_file");
		target_host_path = fixture_path.clone();
		target_host_path.push("this_folder_exists/file_in_folder.txt");
		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert_eq!(
			found_host_path.unwrap().unwrap_on_host(),
			target_host_path.as_os_str()
		);

		// Tests directory traversal with no maps
		map = UhyveFileMap::new(&[], None, &mut Cache::default());
		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert!(found_host_path.is_none());
	}
}
