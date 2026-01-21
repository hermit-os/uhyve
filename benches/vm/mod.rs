use std::path::PathBuf;

use byte_unit::Byte;
use criterion::{Criterion, criterion_group};
use uhyvelib::{
	params::{FileSandboxMode, Output, Params},
	vm::{DefaultBackend, UhyveVm},
};

pub fn load_vm_hello_world(c: &mut Criterion) {
	let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "data/x86_64/hello_world"]
		.iter()
		.collect();
	let params = Params {
		memory_size: Byte::from_u64(1024 * 4096 * 500).try_into().unwrap(),
		output: Output::None,
		file_isolation: FileSandboxMode::None,
		aslr: false,
		..Default::default()
	};

	c.bench_function("vm::load_kernel(hello world)", |b| {
		b.iter(|| {
			let vm = UhyveVm::<DefaultBackend>::new(path.clone(), params.clone())
				.expect("Unable to create VM");
			vm.run(None);
		})
	});
}

criterion_group!(load_kernel_benchmark_group, load_vm_hello_world);
