mod common;

use std::fs::read_to_string;

use byte_unit::{Byte, Unit};
use common::{
	build_hermit_bin, check_result, get_fs_fixture_path, remove_file_if_exists, run_simple_vm,
};
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

#[test]
fn serial_buffer_test() {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("serial");
	let res = run_simple_vm(bin_path);
	println!("Kernel output: {:?}", res);
	assert_eq!(res.code, 0);
	assert!(
		res.output
			.as_ref()
			.unwrap()
			.contains("Hello from serial!\nABCD\n1234ASDF!@#$\n")
	);
}

#[test]
fn serial_file_output_test() {
	env_logger::try_init().ok();

	let fixture_path = get_fs_fixture_path();

	// Tests successful directory traversal starting from file in child
	// directory of a mapped directory.
	let mut output_path = fixture_path.clone();
	output_path.push("ignore_everything_here");
	output_path.push("testserialout.txt");
	remove_file_if_exists(&output_path);

	let bin_path = build_hermit_bin("serial");
	println!("Launching kernel {}", bin_path.display());
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::File(output_path.clone()),
		..Default::default()
	};
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	check_result(&res);

	assert!(output_path.exists());
	let file_content = read_to_string(&output_path).unwrap();
	assert!(file_content.contains("Hello from serial!\nABCD\n1234ASDF!@#$\n"));
}
