extern crate criterion;

use criterion::criterion_main;

mod vm;
use crate::vm::load_kernel_benchmark_group;

mod complete_binary;
use crate::complete_binary::run_complete_binaries_group;

mod network;
use network::network_benchmark_group;

#[path = "../tests/common.rs"]
pub(crate) mod common;
pub use common::build_hermit_bin;

// Add the benchmark groups that should be run
criterion_main!(
	load_kernel_benchmark_group,
	run_complete_binaries_group,
	network_benchmark_group
);
