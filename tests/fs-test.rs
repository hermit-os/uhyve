mod common;

use std::{
	collections::HashMap,
	fs::{File, read_to_string},
	path::PathBuf,
};

use byte_unit::{Byte, Unit};
#[cfg(target_os = "linux")]
use common::strict_sandbox;
use common::{
	build_hermit_bin, check_result, get_fs_fixture_path, remove_file_if_exists, run_vm_in_thread,
};
use rand::{Rng, distr::Alphanumeric};
use uhyvelib::params::{EnvVars, Output, Params};

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

// Creates a vector out of a given host path and guest path for UhyveFileMap.
fn create_filemap_params<T: AsStr, U: AsStr>(host_path: T, guest_path: U) -> Vec<String> {
	[format!("{}:{}", host_path.as_str(), guest_path.as_str())].to_vec()
}

fn create_envvars<T: AsStr, U: AsStr>(testname: T, filepath: U) -> EnvVars {
	EnvVars::Set(HashMap::from([
		("TESTNAME".to_owned(), testname.as_str().to_owned()),
		("FILEPATH".to_owned(), filepath.as_str().to_owned()),
	]))
}

/// Generates a filename in the format of prefixab1cD23.txt
fn generate_filename(prefix: &str) -> String {
	let mut filename = prefix.to_owned();
	let randomchar: String = rand::rng()
		.sample_iter(&Alphanumeric)
		.take(7)
		.map(char::from)
		.collect();
	filename.push_str(&randomchar);
	filename.push_str(".txt");
	filename
}

/// Checks whether guests can create, then use files on the host.
/// (The file is present in a mapped parent directory.)
#[test]
fn create_mapped_parent_nonpresent_file() {
	env_logger::try_init().ok();

	let testname: &'static str = "create_mapped_parent_nonpresent_file";
	let filename = generate_filename(testname);

	// Tests successful directory traversal starting from file in child
	// directory of a mapped directory.
	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut host_dir_path = get_fs_fixture_path();
	host_dir_path.push("ignore_everything_here");

	let mut host_file_path = host_dir_path.clone();
	host_file_path.push(&filename);
	let mut guest_file_path = guest_dir_path.clone();
	guest_file_path.push(&filename);

	let uhyvefilemap_params = create_filemap_params(&host_dir_path, &guest_dir_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	remove_file_if_exists(&host_file_path);
	check_result(&res);
}

/// Checks whether guests can create, then use files on the host.
/// (File directly mapped.)
#[test]
fn create_write_mapped_nonpresent_file() {
	env_logger::try_init().ok();

	let testname: &'static str = "create_write_mapped_nonpresent_file";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut host_dir_path = get_fs_fixture_path();
	host_dir_path.push("ignore_everything_here");

	let mut guest_file_path = guest_dir_path;
	guest_file_path.push(&filename);
	let mut host_file_path = host_dir_path;
	host_file_path.push(&filename);

	let uhyvefilemap_params = create_filemap_params(&host_file_path, &guest_file_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		file_mapping: uhyvefilemap_params,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	verify_file_equals(&host_file_path, "Hello, world!");
	remove_file_if_exists(&host_file_path);
	check_result(&res);
}

/// Checks UhyveFileMap temporary directory functionality.
/// (No mappings present.)
#[test]
fn create_write_unmapped_nonpresent_file() {
	env_logger::try_init().ok();

	let testname: &'static str = "create_write_unmapped_nonpresent_file";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut guest_file_path = guest_dir_path.clone();
	guest_file_path.push(&filename);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
}

/// Guest attempts to remove file created by host.
/// (File directly mapped.)
///
/// Should this test ever fail, it is probably because of a regression
/// involving a misconfiguration in Landlock.
#[test]
fn remove_mapped_present_file() {
	env_logger::try_init().ok();

	let testname: &'static str = "remove_mapped_present_file";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut host_dir_path = get_fs_fixture_path();
	host_dir_path.push("ignore_everything_here");

	let mut guest_file_path = guest_dir_path;
	guest_file_path.push(&filename);
	let mut host_file_path = host_dir_path;
	host_file_path.push(&filename);

	// The file is created on the host, and passed to UhyveFileMap.
	File::create(&host_file_path).unwrap();

	let uhyvefilemap_params = create_filemap_params(&host_file_path, &guest_file_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	assert!(host_file_path.exists());
	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
	assert!(!host_file_path.exists());
}

/// Guest attempts to remove file created by host.
/// (The file is present in a mapped parent directory.)
///
/// Should this test ever fail, it is probably either because of a misconfiguration in Landlock
/// or because of a UhyveFileMap regression.
#[test]
fn remove_mapped_parent_present_file() {
	env_logger::try_init().ok();

	let testname: &'static str = "remove_mapped_parent_present_file";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut host_dir_path = get_fs_fixture_path();
	host_dir_path.push("ignore_everything_here");

	let mut guest_file_path = guest_dir_path.clone();
	guest_file_path.push(&filename);
	let mut host_file_path = host_dir_path.clone();
	host_file_path.push(&filename);

	// The file is created on the host, and passed to UhyveFileMap.
	File::create(&host_file_path).unwrap();

	let uhyvefilemap_params = create_filemap_params(&host_dir_path, &guest_dir_path);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: uhyvefilemap_params,
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	assert!(host_file_path.exists());
	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
	assert!(!host_file_path.exists());
}

/// This checks whether UhyveFileMap rejects unlink calls to unmapped files that do not exist.
/// Unlike other tests, the VM should not return a success code (0).
#[test]
fn remove_nonpresent_file_test() {
	// kernel tries to open a non-present file, so uhyve will reject the hypercall and the kernel
	// will panic.
	env_logger::try_init().ok();

	let testname: &'static str = "remove_nonpresent_file_test";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut guest_file_path = guest_dir_path;
	guest_file_path.push(&filename);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	assert_ne!(res.code, 0);
}

/// Tests whether the file descriptor sandbox works correctly, by unlinking an open
/// file on the host before the file descriptor of that said file is closed.
#[test]
fn fd_open_remove_close() {
	env_logger::try_init().ok();

	let testname: &'static str = "fd_open_remove_close";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut guest_file_path = guest_dir_path;
	guest_file_path.push(&filename);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	check_result(&res);
}

/// fd sandbox test: Unlinks a file with a still-open file descriptor.
/// Then unlinks again, after the file descriptor is closed.
#[test]
fn fd_open_remove_before_and_after_closing() {
	env_logger::try_init().ok();

	let testname: &'static str = "fd_open_remove_before_and_after_closing";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut guest_file_path = guest_dir_path;
	guest_file_path.push(&filename);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
	let res = run_vm_in_thread(bin_path, params);
	assert_ne!(res.code, 0);
}

/// fd sandbox test: Unlinks an open file on the host twice, before the
/// file descriptor of that said file is closed.
#[test]
fn fd_remove_twice_before_closing() {
	env_logger::try_init().ok();

	let testname: &'static str = "fd_remove_twice_before_closing";
	let filename = generate_filename(testname);

	let guest_dir_path: PathBuf = PathBuf::from("/root/");
	let mut guest_file_path = guest_dir_path;
	guest_file_path.push(&filename);

	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(32, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		env: create_envvars(testname, &guest_file_path),
		..Default::default()
	};

	let bin_path: PathBuf = build_hermit_bin("fs_test");
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
fn fd_write_to_fd() {
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
