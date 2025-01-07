pub mod fd;
pub mod filemap;
#[cfg(target_os = "linux")]
pub mod landlock;
pub mod tempdir;

use std::{ffi::OsString, fs::canonicalize, io::ErrorKind, path::absolute};

use clean_path::clean;

/// Separates a string of the format "./host_dir/host_path.txt:guest_path.txt"
/// into a guest_path (String) and host_path (OsString) respectively.
///
/// * `mapping` - A mapping of the format `./host_path.txt:guest.txt`.
fn split_guest_and_host_path(mapping: &str) -> Result<(String, OsString), ErrorKind> {
	let mut mappingiter: std::str::Split<'_, &str> = mapping.split(":");
	let host_str = mappingiter.next().ok_or(ErrorKind::InvalidInput)?;
	let guest_str = mappingiter.next().ok_or(ErrorKind::InvalidInput)?;

	// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
	// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
	let host_path = canonicalize(host_str)
		.map_or_else(|_| clean(absolute(host_str).unwrap()), clean)
		.into();
	let guest_path: String = clean(guest_str).display().to_string();

	Ok((guest_path, host_path))
}

#[test]
fn test_split_guest_and_host_path() {
	use std::path::PathBuf;

	let host_guest_strings = [
		"./host_string.txt:guest_string.txt",
		"/home/user/host_string.txt:guest_string.md.txt",
		"host_string.txt:this_does_exist.txt:should_not_exist.txt",
		"host_string.txt:test/..//guest_string.txt",
	];

	// We will use `host_string.txt` for all tests checking canonicalization.
	let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	fixture_path.push("host_string.txt");

	// Mind the inverted order.
	let results = [
		(
			String::from("guest_string.txt"),
			fixture_path.clone().into(),
		),
		(
			String::from("guest_string.md.txt"),
			OsString::from("/home/user/host_string.txt"),
		),
		(
			String::from("this_does_exist.txt"),
			fixture_path.clone().into(),
		),
		(String::from("guest_string.txt"), fixture_path.into()),
	];

	for (i, host_and_guest_string) in host_guest_strings
		.into_iter()
		.map(split_guest_and_host_path)
		.enumerate()
	{
		assert_eq!(
			host_and_guest_string.expect("Result is an error!"),
			results[i]
		);
	}
}
