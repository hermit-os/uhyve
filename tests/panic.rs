mod common;

use common::{
	BuildMode, build_hermit_bin, check_result_and_print_output, env_logger_build, run_simple_vm,
};

#[test]
fn panic_test() {
	env_logger_build();
	let bin_path = build_hermit_bin("panic", BuildMode::Debug);
	let res = run_simple_vm(bin_path);
	check_result_and_print_output(&res, -1);
}
