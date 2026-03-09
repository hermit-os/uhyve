mod common;

use std::thread;

use common::{
	BuildMode, build_hermit_bin, check_result_and_print_output, env_logger_build,
	run_vm_with_custom_memory,
};
use uhyvelib::vm::VmResult;

/// Runs the `hello_world` kernel with the given memory size.
#[inline]
fn run_x_mib(memory_size: u64) -> VmResult {
	env_logger_build();
	let bin_path = build_hermit_bin("hello_world", BuildMode::Debug);
	run_vm_with_custom_memory(bin_path, memory_size)
}

/// Tries to start Uhyve VMs with different memory sizes to evaluate if the
/// run will succeed.
#[test]
fn memory_test() {
	// u64: memory (MiB), bool: success expected
	let params = vec![
		(128, true),
		(256, true),
		(512, true),
		(1024, true),
		(2048, true),
		#[cfg(target_os = "linux")]
		(3072, false), // v1 (KVM_32BIT_GAP_START)
		(4096, false), // v1
	];
	for (mem_size, success_expected) in params {
		let vm = thread::spawn(move || run_x_mib(mem_size));
		println!("MiB: {mem_size}, success: {success_expected}");
		if success_expected {
			let res = vm.join().expect("VM panicked for {mem_size}MiB");
			check_result_and_print_output(&res, 0);
		} else {
			vm.join().expect_err("VM did not panic for {mem_size}MiB.");
		}
	}
}
