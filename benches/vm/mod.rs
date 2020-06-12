extern crate criterion;

use criterion::{criterion_group, Criterion};

extern crate uhyvelib;
use crate::vm::uhyvelib::vm::Vm;

pub fn load_vm_hello_world(c: &mut Criterion) {
	let path = env!("CARGO_MANIFEST_DIR").to_string() + &"/benches_data/hello_world".to_string();
	let mut vm = uhyvelib::vm::create_vm(
		path,
		&uhyvelib::vm::Parameter::new(
			1024 * 100000,
			1,
			false,
			true,
			false,
			std::option::Option::None,
			std::option::Option::None,
			std::option::Option::None,
			std::option::Option::None,
			std::option::Option::None,
		),
	)
	.expect("Unable to create VM");

	c.bench_function("vm::load_kernel(hello world)", |b| {
		b.iter(|| unsafe {
			vm.load_kernel().unwrap();
		})
	});
}

criterion_group!(load_kernel_benchmark_group, load_vm_hello_world);
