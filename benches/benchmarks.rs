extern crate criterion;

use criterion::criterion_main;

pub mod benches;

use benches::{complete_binary::run_complete_binaries_group, vm::load_kernel_benchmark_group};

// Add the benchmark groups that should be run
criterion_main!(load_kernel_benchmark_group, run_complete_binaries_group);
