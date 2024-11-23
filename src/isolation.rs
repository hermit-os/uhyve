use std::{
	collections::HashMap,
	ffi::{CString, OsString},
	fs,
	fs::Permissions,
	os::unix::{ffi::OsStrExt, fs::PermissionsExt},
	path::PathBuf,
};

use tempfile::{Builder, TempDir};
use uuid::Uuid;

/// Creates a temporary directory.
pub fn create_temp_dir() -> TempDir {
	let dir = Builder::new()
		.permissions(Permissions::from_mode(0o700))
		.prefix("uhyve-")
		.suffix(&Uuid::new_v4().to_string())
		.tempdir()
		.ok()
		.unwrap_or_else(|| panic!("The temporary directory could not be created."));

	let dir_permissions = dir.path().metadata().unwrap().permissions();
	assert!(!dir_permissions.readonly());

	dir
}

/// Wrapper around a `HashMap` to map guest paths to arbitrary host paths.
#[derive(Debug, Clone)]
pub struct UhyveFileMap {
	files: HashMap<String, OsString>,
}

impl UhyveFileMap {
	/// Creates a UhyveFileMap.
	///
	/// * `mappings` - A list of host->guest path mappings with the format "./host_path.txt:guest.txt"
	pub fn new(mappings: &Option<Vec<String>>) -> UhyveFileMap {
		if let Some(mappings) = mappings {
			UhyveFileMap {
				files: mappings
					.iter()
					.map(String::as_str)
					.map(Self::split_guest_and_host_path)
					.map(|(guest_path, host_path)| {
						(
							guest_path,
							fs::canonicalize(&host_path).map_or(host_path, PathBuf::into_os_string),
						)
					})
					.collect(),
			}
		} else {
			UhyveFileMap {
				files: Default::default(),
			}
		}
	}

	/// Separates a string of the format "./host_dir/host_path.txt:guest_path.txt"
	/// into a guest_path (String) and host_path (OsString) respectively.
	///
	/// * `mapping` - A mapping of the format `./host_path.txt:guest.txt`.
	fn split_guest_and_host_path(mapping: &str) -> (String, OsString) {
		let mut mappingiter = mapping.split(":");
		let host_path = OsString::from(mappingiter.next().unwrap());
		let guest_path = mappingiter.next().unwrap().to_owned();

		(guest_path, host_path)
	}

	/// Returns the host_path on the host filesystem given a requested guest_path, if it exists.
	///
	/// * `guest_path` - The guest path that is to be looked up in the map.
	pub fn get_host_path(&mut self, guest_path: &str) -> Option<OsString> {
		self.files.get(guest_path).map(OsString::from)
	}

	/// Inserts an opened temporary file into the file map. Returns a CString so that
	/// the file can be directly used by [crate::hypercall::open].
	///
	/// * `guest_path` - The requested guest path.
	/// * `host_path` - The corresponding host path. Here, this is a temporary file.
	pub fn insert_temporary_file(&mut self, guest_path: &str, host_path: OsString) -> CString {
		// TODO: Do we need to canonicalize the host_path?
		let ret = CString::new(host_path.as_bytes()).unwrap();
		self.files.insert(String::from(guest_path), host_path);
		ret
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_split_guest_and_host_path() {
		let host_guest_strings = vec![
			"./host_string.txt:guest_string.txt",
			"/home/user/host_string.txt:guest_string.md.txt",
			":guest_string.conf",
			":",
			"exists.txt:also_exists.txt:should_not_exist.txt",
		];

		// Mind the inverted order.
		let results = vec![
			(
				String::from("guest_string.txt"),
				OsString::from("./host_string.txt"),
			),
			(
				String::from("guest_string.md.txt"),
				OsString::from("/home/user/host_string.txt"),
			),
			(String::from("guest_string.conf"), OsString::from("")),
			(String::from(""), OsString::from("")),
			(
				String::from("also_exists.txt"),
				OsString::from("exists.txt"),
			),
		];

		for (i, host_and_guest_string) in host_guest_strings
			.into_iter()
			.map(UhyveFileMap::split_guest_and_host_path)
			.enumerate()
		{
			assert_eq!(host_and_guest_string, results[i]);
		}
	}

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

		let map_parameters = Some(vec![
			map_results[0].clone() + ":readme_file.md",
			map_results[1].clone() + ":guest_folder",
			map_results[2].clone() + ":guest_symlink",
			map_results[3].clone() + ":guest_dangling_symlink",
			map_results[4].clone() + ":guest_file",
			path_prefix.clone() + "/this_symlink_leads_to_a_file" + ":guest_file_symlink",
		]);

		let mut map = UhyveFileMap::new(&map_parameters);

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
}
