mod common;

use std::{fs::read_to_string, path::PathBuf};

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, check_result, remove_file_if_exists};
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
	env_logger::try_init().ok();
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		..Default::default()
	};

	let bin_path = build_hermit_bin("open_close_file");
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	check_result(&res);
}

#[test]
fn uhyvefilemap_test() {
	env_logger::try_init().ok();
	let output_path = PathBuf::from("foo.txt");
	remove_file_if_exists(&output_path);
	let bin_path = build_hermit_bin("create_file");

	let mut params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: vec!["/root/foo.txt:wrong.txt".to_string()],
		output: Output::Buffer,
		stats: true,
		..Default::default()
	};

	// The file should not exist on the host OS.
	let mut vm = UhyveVm::new(bin_path.clone(), params.clone()).unwrap();
	let mut res = vm.run(None);
	check_result(&res);
	assert!(!output_path.exists());

	params.file_mapping = vec!["foo.txt:/root/foo.txt".to_string()];
	vm = UhyveVm::new(bin_path, params).unwrap();
	res = vm.run(None);
	check_result(&res);
	verify_file_equals(&output_path, "Hello, world!");
}
