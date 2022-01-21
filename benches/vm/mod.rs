use byte_unit::Byte;
use criterion::{criterion_group, Criterion};
use uhyvelib::{params::Params, vm::Vm, Uhyve};

pub fn load_vm_hello_world(c: &mut Criterion) {
	let path = [env!("CARGO_MANIFEST_DIR"), "benches_data/hello_world"]
		.iter()
		.collect();
	let params = Params {
		memory_size: Byte::from_bytes(1024 * 100000).try_into().unwrap(),
		..Default::default()
	};
	let mut vm = Uhyve::new(path, params).expect("Unable to create VM");

	c.bench_function("vm::load_kernel(hello world)", |b| {
		b.iter(|| unsafe {
			vm.load_kernel().unwrap();
		})
	});
}

criterion_group!(load_kernel_benchmark_group, load_vm_hello_world);
