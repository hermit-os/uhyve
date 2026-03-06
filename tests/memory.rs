mod common;

use common::{BuildMode, build_hermit_bin, run_vm_with_custom_memory};

/// Runs the `hello_world` kernel with the given memory size.
/// This is not simply done in one function and with a loop due to
/// threading in tests.
fn run_x_mib(memory_size: u64) {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("hello_world", BuildMode::Debug);
	let res = run_vm_with_custom_memory(bin_path, memory_size);
	println!("Kernel output: {res:?}");
	assert_eq!(res.code, 0);
}

#[test]
fn run_128mib() {
	run_x_mib(128);
}

#[test]
fn run_256mib() {
	run_x_mib(256);
}

#[test]
fn run_512mib() {
	run_x_mib(512);
}

#[test]
fn run_1024mib() {
	run_x_mib(1024);
}

#[test]
fn run_2048mib() {
	run_x_mib(2048);
}

/// TODO: This should panic for v1, but not for v2.
#[test]
#[should_panic]
fn run_4096mib() {
	run_x_mib(4096);
}
