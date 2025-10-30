pub mod fd;
pub mod filemap;
pub mod image;

#[cfg(target_os = "linux")]
pub mod landlock;

pub mod tempdir;

use std::{
	fs::canonicalize,
	io::ErrorKind,
	path::{PathBuf, absolute},
};

use clean_path::clean;

/// Separates a string of the format "./host_dir/host_path.txt:guest_path.txt"
/// into a guest_path (String) and host_path (OsString) respectively.
///
/// * `mapping` - A mapping of the format `./host_path.txt:guest.txt` or `./hermit_image.hermit:contained.txt:guest.txt.
fn split_guest_and_host_path(
	mapping: &str,
) -> Result<(PathBuf, Option<String>, PathBuf), ErrorKind> {
	let mut mappingiter = mapping.split(':');

	let host_str = mappingiter.next().ok_or(ErrorKind::InvalidInput)?;

	let (inside_archive_str, guest_str) = {
		let tmp2 = mappingiter.next().ok_or(ErrorKind::InvalidInput)?;
		if let Some(tmp3) = mappingiter.next() {
			(Some(clean(tmp2).to_str().unwrap().to_string()), tmp3)
		} else {
			(None, tmp2)
		}
	};

	// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
	// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
	let host_path = clean(canonicalize(host_str).unwrap_or_else(|_| absolute(host_str).unwrap()));

	let guest_path = clean(guest_str);

	Ok((guest_path, inside_archive_str, host_path))
}

#[test]
fn test_split_guest_and_host_path() {
	let host_guest_strings = [
		"./host_string.txt:guest_string.txt",
		"/home/user/host_string.txt:guest_string.md.txt",
		"host_string.txt:this_does_exist_in_archive.txt:this_does_exist.txt",
		"host_string.txt:this_does_exist_in_archive.txt:this_does_exist.txt:this_is_ignored.txt",
		"host_string.txt:test/..//guest_string.txt",
	];

	// We will use `host_string.txt` for all tests checking canonicalization.
	let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	fixture_path.push("host_string.txt");

	// Mind the inverted order.
	let results = [
		(
			PathBuf::from("guest_string.txt"),
			None,
			fixture_path.clone(),
		),
		(
			PathBuf::from("guest_string.md.txt"),
			None,
			PathBuf::from("/home/user/host_string.txt"),
		),
		(
			PathBuf::from("this_does_exist.txt"),
			Some("this_does_exist_in_archive.txt".to_string()),
			fixture_path.clone(),
		),
		(
			PathBuf::from("this_does_exist.txt"),
			Some("this_does_exist_in_archive.txt".to_string()),
			fixture_path.clone(),
		),
		(PathBuf::from("guest_string.txt"), None, fixture_path),
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
