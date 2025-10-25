mod common;

use std::{path::PathBuf, sync::Arc, thread};

use byte_unit::{Byte, Unit};
#[cfg(target_os = "linux")]
use common::strict_sandbox;
use common::{build_hermit_bin, check_result};
use rand::{Rng, distr::Alphanumeric};
use uhyvelib::{isolation::fd::FdData, params::Params, vm::UhyveVm};

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

/// Gets a guest path using a test name.
///
/// * `test_name` - Name of the test.
fn get_testname_derived_guest_path(test_name: &str) -> PathBuf {
	// Starting off with the "guest_dir_path".
	let mut guest_file_path = PathBuf::from("/root/");
	guest_file_path.push(generate_filename(test_name));
	guest_file_path
}

// Creates a vector out of a given host path and guest path for UhyveFileMap.
fn create_filemap_params<T: AsStr, U: AsStr>(host_path: T, guest_path: U) -> Vec<String> {
	vec![format!("{}:{}", host_path.as_str(), guest_path.as_str())]
}

/// Creates kernel arguments for fs-tests.
///
/// * `test_name` - Name of the test.
/// * `fd` - This parameter defines the file descriptor the guest will use.
/// * `data` - Additional test data
fn create_kernel_args<T: AsStr>(test_name: T, fd: i32, data: &str) -> Vec<String> {
	vec![
		"--".to_owned(),
		"testname=".to_owned() + test_name.as_str(),
		"fd=".to_owned() + &fd.to_string(),
		data.to_owned(),
	]
}

/// Generates a set of parameters to boot the VM with.
///
/// * `filemap_params` - Vector containing guest-host paths for UhyveFileMap.
/// * `test_name` - Name of the test.
/// * `fd` - Guest fd.
/// * `data` ...
fn generate_params(
	filemap_params: Option<Vec<String>>,
	test_name: &'static str,
	fd: i32,
	data: &str,
) -> Params {
	Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		file_mapping: filemap_params.unwrap_or_default(),
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		kernel_args: create_kernel_args(test_name, fd, data),
		..Default::default()
	}
}

/// Checks whether guests can create, then use files on the host.
/// (The file is present in a mapped parent directory.)
#[test]
fn read_expect() {
	env_logger::try_init().ok();

	let test_name: &'static str = "read_expect";
	let file_name = generate_filename(test_name);

	const FD: i32 = 3;
	const DATA: &str = "HelloWorld!";

	let params = generate_params(None, test_name, FD, DATA);

	let bin_path: PathBuf = build_hermit_bin("virtual_fd_tests");
	let res = thread::spawn(move || {
		let vm = UhyveVm::new(bin_path, params).unwrap();
		{
			let mut filemap = vm.peripherals.file_mapping.lock().unwrap();
			assert_eq!(
				filemap
					.fdmap
					.insert(FdData::Virtual {
						data: yoke::Yoke::attach_to_cart(Arc::new(DATA), |i| i.as_bytes())
							.erase_arc_cart(),
						offset: 0,
					})
					.unwrap()
					.0,
				FD
			);
		}
		vm.run(None)
	})
	.join()
	.expect("Uhyve thread panicked.");
	check_result(&res);
}
