mod common;

use std::{
	fs::{read_to_string, remove_file},
	path::PathBuf,
};

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, run_simple_vm};
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

#[test]
fn serial_buffer_test() {
	let bin_path = build_hermit_bin("serial");
	let res = run_simple_vm(bin_path);
	assert_eq!(res.code, 0);
	println!("Kernel output: {:?}", res);
	assert!(res
		.output
		.as_ref()
		.unwrap()
		.contains("Hello from serial!\nABCD\n1234ASDF!@#$\n"));
}

#[test]
fn serial_file_output_test() {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("serial");
	let output_path: PathBuf = "testserialout.txt".into();
	if output_path.exists() {
		println!("Removing existing file {}", output_path.display());
		remove_file(&output_path)
			.unwrap_or_else(|_| panic!("Can't remove {}", output_path.display()));
	}

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
	println!("Kernel output: {:?}", res);
	assert_eq!(res.code, 0);

	assert!(output_path.exists());
	let file_content = read_to_string(&output_path).unwrap();
	assert!(file_content.contains("Hello from serial!\nABCD\n1234ASDF!@#$\n"));

	remove_file(&output_path).unwrap_or_else(|_| panic!("Can't remove {}", output_path.display()));
}
