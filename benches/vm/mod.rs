use byte_unit::Byte;
use criterion::{criterion_group, Criterion};
use uhyvelib::{
	params::Params,
	vm::{DefaultBackend, UhyveVm},
};

pub fn load_vm_hello_world(c: &mut Criterion) {
	let path = [env!("CARGO_MANIFEST_DIR"), "data/x86_64/hello_world"]
		.iter()
		.collect();
	let params = Params {
		memory_size: Byte::from_u64(1024 * 4096 * 500).try_into().unwrap(),
		..Default::default()
	};

	let mut vm = UhyveVm::<DefaultBackend>::new(path, params).expect("Unable to create VM");

	c.bench_function("vm::load_kernel(hello world)", |b| {
		b.iter(|| vm.load_kernel().unwrap())
	});
}

criterion_group!(load_kernel_benchmark_group, load_vm_hello_world);
