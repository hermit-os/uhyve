mod common;

use std::{fs::read_to_string, path::PathBuf};

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, remove_file_if_exists};
use uhyvelib::{params::Params, vm::UhyveVm};

/// Verifies successful file creation on the host OS and its contents.
pub fn verify_file_equals(testfile: &PathBuf, contents: &str) {
	assert!(testfile.exists());
	let file_content = read_to_string(testfile).unwrap();
	assert_eq!(file_content, contents.to_string());
}

#[test]
fn new_file_test() {
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		..Default::default()
	};

	let bin_path = build_hermit_bin("open_close_file");
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	assert_eq!(res.code, 0);
}

#[test]
fn uhyvefilemap_test() {
	let output_path = PathBuf::from("foo.txt");
	remove_file_if_exists(&output_path);
	let bin_path = build_hermit_bin("create_file");

	let mut params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		mount: vec!["foo.txt:wrong.txt".to_string()],
		..Default::default()
	};

	// The file should not exist on the host OS.
	let mut vm = UhyveVm::new(bin_path.clone(), params.clone()).unwrap();
	let mut res: uhyvelib::vm::VmResult = vm.run(None);
	assert_eq!(res.code, 0);
	assert!(!output_path.exists());

	params.mount = vec!["foo.txt:foo.txt".to_string()];
	vm = UhyveVm::new(bin_path, params).unwrap();
	res = vm.run(None);
	assert_eq!(res.code, 0);
	verify_file_equals(&output_path, "Hello, world!");
}
