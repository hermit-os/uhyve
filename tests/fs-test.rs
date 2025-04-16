mod common;

use std::{
	fs::{File, read_to_string},
	path::PathBuf,
};

use byte_unit::{Byte, Unit};
#[cfg(target_os = "linux")]
use common::strict_sandbox;
use common::{
	build_hermit_bin, check_result, get_fs_fixture_path, remove_file_if_exists, run_simple_vm,
};
use serial_test::serial;
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

/// This checks whether a VM can create and write to a file on the host.
#[test]
#[serial]
fn create_mapped_parent_nonpresent_file() {
	env_logger::try_init().ok();
	// Tests successful directory traversal starting from file in child
	// directory of a mapped directory.
	let guest_path = PathBuf::from("/root/");
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	let mut file_path = host_path.clone();
	file_path.push("foo.txt");
	remove_file_if_exists(&file_path);

	let uhyvefilemap_params = [format!(
		"{}:{}",
		host_path.to_str().unwrap(),
		guest_path.to_str().unwrap()
	)]
	.to_vec();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params.clone(),
		..Default::default()
	};

	let bin_path = build_hermit_bin("open_close_file");
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	check_result(&res);
}

/// This is expected to fail.
#[test]
#[serial]
fn create_write_unmapped_nonpresent_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	host_path.push("file_to_write.txt");
	remove_file_if_exists(&host_path);

	let uhyvefilemap_params = [format!(
		"{}:{}",
		host_path.to_str().unwrap(),
		"/root/dir/wrong.txt"
	)]
	.to_vec();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		output: Output::Buffer,
		stats: true,
		..Default::default()
	};

	// The file should not exist on the host OS.
	let bin_path = build_hermit_bin("create_file");
	let vm = UhyveVm::new(bin_path.clone(), params.clone()).unwrap();
	let res = vm.run(None);
	check_result(&res);
	assert!(!host_path.exists());
}

#[test]
#[serial]
fn create_write_mapped_nonpresent_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	host_path.push("foo.txt");
	remove_file_if_exists(&host_path);

	let uhyvefilemap_params = [format!(
		"{}:{}",
		host_path.to_str().unwrap(),
		"/root/foo.txt"
	)]
	.to_vec();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		output: Output::Buffer,
		stats: true,
		..Default::default()
	};

	let bin_path = build_hermit_bin("create_file");
	let vm = UhyveVm::new(bin_path.clone(), params.clone()).unwrap();
	let res = vm.run(None);

	check_result(&res);
	verify_file_equals(&host_path, "Hello, world!");
}

/// This might break because of a misconfiguration in Landlock.
#[test]
#[serial]
fn remove_mapped_present_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	host_path.push("file_to_remove.txt");
	remove_file_if_exists(&host_path);
	File::create(&host_path).unwrap();

	let bin_path = build_hermit_bin("remove_file");

	let uhyvefilemap_params = [format!(
		"{}:{}",
		host_path.to_str().unwrap(),
		"/root/file_to_remove.txt"
	)]
	.to_vec();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		output: Output::Buffer,
		stats: true,
		..Default::default()
	};

	assert!(host_path.exists());
	let vm = UhyveVm::new(bin_path.clone(), params.clone()).unwrap();
	let res = vm.run(None);

	check_result(&res);
	assert!(!host_path.exists());
}

/// This might break because of a misconfiguration in Landlock or a UhyveFileMap regression.
#[test]
#[serial]
fn remove_mapped_parent_present_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	let mut file_to_remove = host_path.clone();
	file_to_remove.push("file_to_remove.txt");
	remove_file_if_exists(&file_to_remove);
	File::create(&file_to_remove).unwrap();

	let bin_path = build_hermit_bin("remove_file");

	let uhyvefilemap_params = [format!("{}:{}", host_path.to_str().unwrap(), "/root/")].to_vec();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		output: Output::Buffer,
		stats: true,
		..Default::default()
	};

	assert!(file_to_remove.exists());
	let vm = UhyveVm::new(bin_path.clone(), params.clone()).unwrap();
	let res = vm.run(None);
	check_result(&res);
	assert!(!file_to_remove.exists());
}

/// This checks whether UhyveFileMap rejects unlink calls to unmapped files that do not exist.
/// This is expected to fail.
#[test]
#[serial]
fn remove_nonpresent_file_test() {
	// kernel tries to open a non-present file, so uhyve will reject the hypercall and the kernel
	// will panic.
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("remove_file");
	let res = run_simple_vm(bin_path);
	assert_ne!(res.code, 0);
}

/// Checks whether an unmapped file written from the VM itself can be removed by the VM.
/// This might break if the temporary directory, the hypercall or Landlock do not function properly.
#[test]
#[serial]
fn create_and_remove_unmapped_file_test() {
	env_logger::try_init().ok();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		..Default::default()
	};

	let bin_path = build_hermit_bin("open_close_remove_file");
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	check_result(&res);
}
