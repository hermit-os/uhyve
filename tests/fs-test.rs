mod common;

use common::{build_hermit_bin, run_simple_vm};
use std::{
	fs::{read, remove_file},
	path::PathBuf,
};

#[test]
fn new_file_test() {
	let testfile = PathBuf::from("foo.txt");
	if testfile.exists() {
		println!("Removing existing file {}", testfile.display());
		remove_file(&testfile).expect(&std::format!("Can't remove {}", testfile.display()));
	}
	let bin_path = build_hermit_bin("create_file");
	run_simple_vm(bin_path);

	assert!(testfile.exists());
	let file_content = read("foo.txt").unwrap();
	assert_eq!(file_content, "Hello, world!".as_bytes());
	remove_file(&testfile).expect(&std::format!("Can't remove {}", testfile.display()));
}
