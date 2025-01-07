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
	run_vm_in_thread,
};
use serial_test::serial;
use uhyvelib::params::{Output, Params};

/// Verifies successful file creation on the host OS and its contents.
pub fn verify_file_equals(testfile: &PathBuf, contents: &str) {
	assert!(testfile.exists());
	let file_content = read_to_string(testfile).unwrap();
	assert_eq!(file_content, contents.to_string());
}

trait AsStr {
	fn as_str(&self) -> &str;
}

impl AsStr for &PathBuf {
	fn as_str(&self) -> &str {
		self.to_str().unwrap()
	}
}

impl AsStr for &str {
	fn as_str(&self) -> &str {
		self
	}
}

fn create_uhyvefilemap_params<T: AsStr, U: AsStr>(host_path: T, guest_path: U) -> Vec<String> {
	[format!("{}:{}", host_path.as_str(), guest_path.as_str())].to_vec()
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

	let uhyvefilemap_params = create_uhyvefilemap_params(&host_path, &guest_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("open_close_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
}

/// This checks whether UhyveFileMap's temporary directory functionality works.
#[test]
#[serial]
fn create_write_unmapped_nonpresent_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	host_path.push("file_to_write.txt");
	remove_file_if_exists(&host_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: create_uhyvefilemap_params(&host_path, "/root/dir/wrong.txt"),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	// The file should not exist on the host OS.
	let bin_path: PathBuf = build_hermit_bin("create_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
	assert!(!host_path.exists());
}

/// This checks whether it is possible to create and use a new file on the host.
#[test]
#[serial]
fn create_write_mapped_nonpresent_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	host_path.push("foo.txt");
	remove_file_if_exists(&host_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: create_uhyvefilemap_params(&host_path, "/root/foo.txt"),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("create_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
	verify_file_equals(&host_path, "Hello, world!");
}

/// Should this test ever fail, it is probably because of a regression
/// involving a misconfiguration in Landlock.
#[test]
#[serial]
fn remove_mapped_present_file() {
	env_logger::try_init().ok();
	let mut host_path = get_fs_fixture_path();
	host_path.push("ignore_everything_here");
	host_path.push("file_to_remove.txt");
	remove_file_if_exists(&host_path);
	File::create(&host_path).unwrap();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: create_uhyvefilemap_params(&host_path, "/root/file_to_remove.txt"),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	assert!(host_path.exists());
	let bin_path: PathBuf = build_hermit_bin("remove_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
	assert!(!host_path.exists());
}

/// Should this test ever fail, it is probably either because of a misconfiguration in Landlock
/// or because of a UhyveFileMap regression.
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

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: create_uhyvefilemap_params(&host_path, "/root"),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	assert!(file_to_remove.exists());
	let bin_path: PathBuf = build_hermit_bin("remove_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
	assert!(!file_to_remove.exists());
}

/// This checks whether UhyveFileMap rejects unlink calls to unmapped files that do not exist.
/// Unlike other tests, the VM should not return a success code (0).
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
/// This test might break if a regression, which affects the tempdir, hypercall or Landlock components,
/// appears.
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
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("open_close_remove_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
}

/// Tests whether the file descriptor sandbox works correctly, by unlinking an open
/// file on the host before the file descriptor of that said file is closed.
#[test]
#[serial]
fn test_fd_open_remove_close() {
	env_logger::try_init().ok();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("open_remove_close_file");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
}

/// Tests whether the file descriptor sandbox works correctly, by unlinking an open
/// file on the host before the file descriptor of that said file is closed.
#[test]
#[serial]
fn test_fd_open_remove_close_remove() {
	env_logger::try_init().ok();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("open_remove_close_remove_file");
	let res = run_vm_in_thread(bin_path, params);
	assert_ne!(res.code, 0);
}

/// Tests whether the file descriptor sandbox works correctly, by unlinking an open
/// file on the host before the file descriptor of that said file is closed.
#[test]
#[serial]
fn test_fd_open_remove_remove_close_file() {
	env_logger::try_init().ok();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("open_remove_remove_close_file");
	let res = run_vm_in_thread(bin_path, params);
	assert_ne!(res.code, 0);
}

/// Tests file descriptor sandbox, particularly whether...
/// - the guest can make a File out of fd 1 (stdout) and write to it.
/// - the guest can make a File out of fd 2 (stderr) and write to it.
/// - the guest can make a File out of an arbitrary fd and write to it.
///   (It shouldn't be able to do so!)
/// - the guest can write to a leaked, yet valid file descriptor.
#[test]
#[serial]
fn test_fd_write_to_fd() {
	env_logger::try_init().ok();

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("write_to_fd");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
}
