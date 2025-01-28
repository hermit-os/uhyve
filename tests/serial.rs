mod common;

use std::{fs::read_to_string, path::PathBuf};

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, remove_file_if_exists, run_simple_vm};
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

#[test]
fn serial_buffer_test() {
	let bin_path = build_hermit_bin("serial");
	let res = run_simple_vm(bin_path);
	println!("Kernel output: {:?}", res);
	assert_eq!(res.code, 0);
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
	remove_file_if_exists(&output_path);

	println!("Launching kernel {}", bin_path.display());
	// The file mapping is a workaround, as the Landlock restriction imposed within UhyveVm
	// is applied process-wide. This includes the test itself. Although testserialout.txt
	// can be accessed by the UhyveVm and by the test, it cannot be removed without its
	// parent directory being explicitly whitelisted (with read-write permission access).
	// Our file map does exactly that.
	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::File(output_path.clone()),
		file_mapping: vec!["./:/root/".to_string()],
		..Default::default()
	};
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	println!("Kernel output: {:?}", res);
	assert_eq!(res.code, 0);

	assert!(output_path.exists());
	let file_content = read_to_string(&output_path).unwrap();
	assert!(file_content.contains("Hello from serial!\nABCD\n1234ASDF!@#$\n"));

	remove_file_if_exists(&output_path);
}
