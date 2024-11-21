mod common;

use std::{
	fs::{read_to_string, remove_file},
	path::PathBuf,
};

use common::{build_hermit_bin, remove_file_if_exists, run_simple_vm};

/// Verifies successful file creation on the host OS and its contents.
pub fn verify_file_equals(testfile: &PathBuf, contents: &str) {
	assert!(testfile.exists());
	let file_content = read_to_string(testfile).unwrap();
	assert_eq!(file_content, contents.to_string());
}

#[test]
fn new_file_test() {
	let output_path = PathBuf::from("foo.txt");
	remove_file_if_exists(&output_path);
	let bin_path = build_hermit_bin("create_file");
	run_simple_vm(bin_path);

	verify_file_equals(&output_path, "Hello, world!");
	remove_file(&output_path).unwrap_or_else(|_| panic!("Can't remove {}", output_path.display()));
}
