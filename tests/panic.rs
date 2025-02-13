mod common;

use common::{build_hermit_bin, run_simple_vm};

#[test]
fn panic_test() {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("panic");
	let res = run_simple_vm(bin_path);
	println!("Kernel output: {:?}", res);
	assert_eq!(res.code, -1);
}
