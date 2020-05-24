extern crate criterion;

use criterion::criterion_main;

mod vm;
use crate::vm::load_kernel_benchmark_group;

mod complete_binary;
use crate::complete_binary::run_hello_world_group;

// Add the benchmark groups that should be run
criterion_main!(load_kernel_benchmark_group, run_hello_world_group);
