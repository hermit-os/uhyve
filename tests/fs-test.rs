mod common;

use std::{fs::read_to_string, path::PathBuf};

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, remove_file_if_exists};
use log::error;
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

/// Verifies successful file creation on the host OS and its contents.
pub fn verify_file_equals(testfile: &PathBuf, contents: &str) {
	assert!(testfile.exists());
	let file_content = read_to_string(testfile).unwrap();
	assert_eq!(file_content, contents.to_string());
}

#[test]
fn new_file_test() {
	let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	fixture_path.push("tests/data/fixtures/fs");
	assert!(fixture_path.is_dir());

	// Tests successful directory traversal starting from file in child
	// directory of a mapped directory.
	let guest_path = PathBuf::from("/root/");
	let mut host_path = fixture_path.clone();
	host_path.push("this_folder_exists");

	// todo: also test this with "/root/foo.txt", currently not possible
	// because of landlock. we should this both with landlock (which requires
	// using a mapped directory and not
	let uhyvefilemap_params = [format!(
		"{}:{}",
		host_path.to_str().unwrap(),
		guest_path.to_str().unwrap()
	)]
	.to_vec();

	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params.clone(),
		..Default::default()
	};

	let bin_path = build_hermit_bin("open_close_file");
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	assert_eq!(res.code, 0);
	let mut foo_txt = host_path.clone();
	foo_txt.push("foo.txt");
	verify_file_equals(&foo_txt, "Hello, world!");
	remove_file_if_exists(&foo_txt);
}

#[test]
fn uhyvefilemap_test() {
	let output_path = PathBuf::from("foo.txt");
	remove_file_if_exists(&output_path);
	let bin_path = build_hermit_bin("create_file");

	let mut params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: vec!["./foo.txt:/root/dir/wrong.txt".to_string()],
		..Default::default()
	};

	// The file should not exist on the host OS.
	params.file_mapping = vec!["./foo.txt:/root/foo.txt".to_string()];
	//let mut res: uhyvelib::vm::VmResult = vm.run(None);
	//assert_eq!(res.code, 0);
	//assert!(!output_path.exists());

	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	assert_eq!(res.code, 0);
	verify_file_equals(&output_path, "Hello, world!");
}
