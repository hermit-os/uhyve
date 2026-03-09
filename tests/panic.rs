mod common;

use common::{BuildMode, build_hermit_bin, run_simple_vm};

use crate::common::check_result_and_print_output;

#[test]
fn panic_test() {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("panic", BuildMode::Debug);
	let res = run_simple_vm(bin_path);
	check_result_and_print_output(&res, -1);
}
