pub mod filemap;
pub mod landlock;
pub mod tempdir;

use std::ffi::OsString;

/// Separates a string of the format "./host_dir/host_path.txt:guest_path.txt"
/// into a guest_path (String) and host_path (OsString) respectively.
///
/// * `mapping` - A mapping of the format `./host_path.txt:guest.txt`.
pub fn split_guest_and_host_path(mapping: &str) -> (String, OsString) {
	let mut mappingiter = mapping.split(":");
	let host_path = OsString::from(mappingiter.next().unwrap());
	let guest_path = mappingiter.next().unwrap().to_owned();

	(guest_path, host_path)
}

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
		.map(split_guest_and_host_path)
		.enumerate()
	{
		assert_eq!(host_and_guest_string, results[i]);
	}
}
