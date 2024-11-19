mod common;

use common::{build_hermit_bin, run_simple_vm};

#[test]
fn serial_buffer_test() {
	// TODO: Check the output once https://github.com/hermit-os/uhyve/issues/528 is resolved
	let bin_path = build_hermit_bin("serial");
	run_simple_vm(bin_path);
}
