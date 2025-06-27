pub mod fd;
pub mod filemap;
#[cfg(target_os = "linux")]
pub mod landlock;
pub mod tempdir;

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
			PathBuf::from("guest_string.txt"),
			fixture_path.clone().into(),
		),
		(
			PathBuf::from("guest_string.md.txt"),
			PathBuf::from("/home/user/host_string.txt"),
		),
		(
			PathBuf::from("this_does_exist.txt"),
			fixture_path.clone().into(),
		),
		(PathBuf::from("guest_string.txt"), fixture_path.into()),
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
