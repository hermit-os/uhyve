mod common;

use std::{
	fs::{read, remove_file},
	path::PathBuf,
};

use common::{build_hermit_bin, run_simple_vm};

#[test]
fn network_test() {
	let bin_path = build_hermit_bin("network_test");
	run_simple_vm(bin_path);
	panic!();
}
