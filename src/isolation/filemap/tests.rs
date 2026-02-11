#![cfg(test)]

use std::ffi::OsString;

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
		map.get_host_path(c"readme_file.md")
			.unwrap()
			.unwrap_on_host(),
		OsString::from(&map_results[0])
	);
	assert_eq!(
		map.get_host_path(c"guest_folder").unwrap().unwrap_on_host(),
		OsString::from(&map_results[1])
	);
	assert_eq!(
		map.get_host_path(c"guest_symlink")
			.unwrap()
			.unwrap_on_host(),
		OsString::from(&map_results[2])
	);
	assert_eq!(
		map.get_host_path(c"guest_dangling_symlink")
			.unwrap()
			.unwrap_on_host(),
		OsString::from(&map_results[3])
	);
	assert_eq!(
		map.get_host_path(c"guest_file").unwrap().unwrap_on_host(),
		OsString::from(&map_results[4])
	);
	assert_eq!(
		map.get_host_path(c"guest_file_symlink")
			.unwrap()
			.unwrap_on_host(),
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

	assert_eq!(found_host_path.unwrap().unwrap_on_host(), target_host_path);

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
	assert_eq!(found_host_path.unwrap().unwrap_on_host(), target_host_path);

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
	assert_eq!(found_host_path.unwrap().unwrap_on_host(), target_host_path);

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
